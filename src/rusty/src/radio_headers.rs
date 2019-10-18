use std::convert::TryInto;
use std::collections::LinkedList;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::panic::{catch_unwind, UnwindSafe};
use std::time::{SystemTime, UNIX_EPOCH, Instant, Duration};
use std::{cmp, fs, ptr};

use std::ffi::CStr;
use std::os::raw::c_char;
use std::io::{Read, Write};

#[cfg(target_family = "unix")]
use std::os::unix::io::AsRawFd;
#[cfg(target_family = "unix")]
use libc::{fcntl, F_SETFL, O_NONBLOCK, poll, pollfd, POLLIN, POLLOUT};

use crate::bridge::*;
use crate::await_ibd_complete_or_stalled;

static THREAD_COUNT: AtomicUsize = AtomicUsize::new(0);

const POST_NET_HDR_MAGIC: u8 = 'H' as u8;
const POST_NET_REQ_MAGIC: u8 = 'R' as u8;
const POST_NET_TXN_MAGIC: u8 = 'T' as u8;

/// Maximum frame size we're willing to send. Important for being able to calculate
/// regulatory duty cycle limits, see comment in the lora protocol handler for more.
const MAX_FRAME_SIZE: usize = 89;

#[derive(PartialEq, Clone, Copy)]
pub enum RadioMode {
    ReadOnly,
    WriteOnly,
    ReadWrite
}

trait RadioDevice: UnwindSafe + Send {
    fn broadcast_msg(&mut self, msg: Vec<u8>);
    fn recv_msg(&mut self) -> Option<Vec<u8>>;
    fn mode(&self) -> RadioMode;
    /// Regulatory or practical maximum messages we can send per day, must be st lest 1200
    fn max_msgs_per_day(&self) -> u64;
    /// Indicates the dev_fd() fd should be poll()ed for free write space
    fn needs_write(&self) -> bool;
    /// Gets the file which should be poll()ed for
    fn file(&self) -> Option<&fs::File>;
    /// Called regularly, with arguments set if the device has available events
    fn poll(&mut self, readable: bool, writable: bool);
}

#[inline]
fn u32_to_arr_be(val: u32) -> [u8; 4] {
    [((val >> 3*8) & 0xff) as u8,
     ((val >> 2*8) & 0xff) as u8,
     ((val >> 1*8) & 0xff) as u8,
     ((val >> 0*8) & 0xff) as u8]
}

#[inline]
fn arr_to_u32_be(slice: &[u8; 4]) -> u32 {
    ((slice[0] as u32) << 3*8) |
    ((slice[1] as u32) << 2*8) |
    ((slice[2] as u32) << 1*8) |
    ((slice[3] as u32) << 0*8)
}

#[inline]
fn slice_first_bytes_to_u32_be(slice: &[u8]) -> u32 {
    if slice.len() >= 4 {
        arr_to_u32_be(slice[0..4].try_into().unwrap())
    } else {
        let mut arr = [0; 4];
        arr[..slice.len()].copy_from_slice(slice);
        arr_to_u32_be(&arr)
    }
}

fn build_header_data_packet(net_magic: &[u8; 4], index: BlockIndex, best_index: BlockIndex) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 1 + 4 + 4 + 80 - 4);
    data.extend_from_slice(net_magic);
    data.push(POST_NET_HDR_MAGIC);
    data.extend_from_slice(&u32_to_arr_be(index.height() as u32));
    data.extend_from_slice(&u32_to_arr_be(best_index.height() as u32));
    let header_bytes = index.header_bytes();
    // First 4 bytes of prevhash is always 0, even on testnet
    assert_eq!(header_bytes[32..36], [0; 4]);
    data.extend_from_slice(&header_bytes[0..32]);
    data.extend_from_slice(&header_bytes[36..]);
    assert!(data.len() <= MAX_FRAME_SIZE);
    data
}

fn build_request_data_packet(net_magic: &[u8; 4], height: i32) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 1 + 4);
    data.extend_from_slice(net_magic);
    data.push(POST_NET_REQ_MAGIC);
    data.extend_from_slice(&u32_to_arr_be(height as u32));
    assert!(data.len() <= MAX_FRAME_SIZE);
    data
}

fn process_msg(msg: &[u8], net_magic: &[u8; 4], tx_reconstruction_cache: &mut [Option<(Instant, Vec<u8>)>; 256]) -> Option<Vec<u8>> {
    log_line(&format!("Received radio message with contents: {:x?}", &msg[..]), true);

    if msg.len() < 4 + 1 { return None; }
    if &msg[..4] != net_magic { return None; }

    match msg[4] {
        POST_NET_HDR_MAGIC => {
            if msg.len() < 4 + 1 + 4 + 4 + 80 - 4 { return None; }

            let height: i32 = arr_to_u32_be(msg[5..9].try_into().unwrap()) as i32;
            if height < 0 { return None; }

            let tip_height: i32 = arr_to_u32_be(msg[9..13].try_into().unwrap()) as i32;
            if tip_height < height { return None; }

            let mut header_bytes = [0; 80];
            header_bytes[0..32].copy_from_slice(&msg[13..13+32]);
            header_bytes[36..].copy_from_slice(&msg[13+32..13+32+80-36]);

            let our_block_at_height = BlockIndex::best_header().get_ancestor(height);
            // If we already have the same header as our current block at this height, don't both
            // processing (note that we process even if we have the header, but not as a part of our
            // best chain, in case we want to request more blocks towards their best chain).
            // XXX: This should be more robust.
            if our_block_at_height.is_none() ||
                    our_block_at_height.as_ref().unwrap().header_bytes()[..] != header_bytes[..] {
                match connect_headers_flat_bytes(&header_bytes) {
                    Some(connected_hdr) => {
                        log_line(&format!("Connected header received over radio, height {} (of their claimed tip {})", connected_hdr.height(), tip_height), false);
                        // We connected it, check if the height matched their claimed height and it
                        // wasn't their tip and request the next one
                        if connected_hdr.height() == height && height != tip_height {
                            Some(build_request_data_packet(net_magic, height + 1))
                        } else { None }
                    },
                    None if height > 1 => {
                        // We couldn't connect the header, request the previous one (or our best header + 1)
                        Some(build_request_data_packet(net_magic, cmp::min(height - 1, BlockIndex::best_header().height() + 1)))
                    },
                    _ => None,
                }
            } else { None }
        },
        POST_NET_REQ_MAGIC => {
            if msg.len() < 4 + 1 + 4 { return None; }

            let height: i32 = arr_to_u32_be(msg[5..9].try_into().unwrap()) as i32;
            if height < 0 { return None; }

            if let Some(index) = BlockIndex::best_header().get_ancestor(height) {
                log_line(&format!("Responding to radio request for header at height {}", index.height()), false);
                Some(build_header_data_packet(net_magic, index, BlockIndex::best_header()))
            } else { None }
        },
        POST_NET_TXN_MAGIC => {
            if msg.len() < 4 + 1 + 1 + 2 { return None; }

            let txid = msg[5];
            let mut start_pos: u16 = 0;
            start_pos |= (msg[6] as u16) << 1*8;
            start_pos |= (msg[7] as u16) << 0*8;
            let data_bytes = msg.len() - 4 - 1 - 1 - 2;

            if tx_reconstruction_cache[txid as usize].is_none() {
                tx_reconstruction_cache[txid as usize] = Some((Instant::now(), Vec::with_capacity(data_bytes)));
            }
            {
                let (_, tx_data) = tx_reconstruction_cache[txid as usize].as_mut().unwrap();
                if tx_data.len() != start_pos as usize {
                    *tx_data = Vec::with_capacity(data_bytes);
                }
                tx_data.extend_from_slice(&msg[8..]);
            }
            for i in 0..256 {
                if {
                    if let &Some((ref start, ref tx_data)) = &tx_reconstruction_cache[i] {
                        if *start > Instant::now() - Duration::from_secs(60) {
                            accept_to_memory_pool(&tx_data);
                            true
                        } else { false }
                    } else { false }
                } {
                    tx_reconstruction_cache[i] = None;
                }
            }
            None
        },
        _ => None
    }
}

mod lora {
    /// Center frequency for EU that fits within a band that allows for 10% duty
    /// cycle (many other ISM bands in this range have a 1 or 0.1% duty cycle).
    pub const EU_CENTER_FREQ_HZ: u32 = 869_525_000; // 869.4 - 869.65
    /// Band that works pretty well in ITU region 1 and 3, ie the Americas and
    /// South-East Asia and AU (by avoiding the common 915-920 MHz LTE band).
    /// Does not work in at least India.
    pub const NA_CENTER_FREQ_HZ: u32 = 920_625_000; // 920.5 - 920.75

    #[derive(Copy, Clone)]
    pub enum LoraCodeRate {
        FourOnFive,
        FourOnSix,
        FourOnSeven,
        FourOnEight,
    }

    #[cfg(target_family = "unix")]
    pub mod rnode {
        use std::fs;
        use std::io::{Read, Write};
        use std::collections::LinkedList;
        use std::time::{Instant, Duration};

        use std::os::unix::io::AsRawFd;
        use libc::{cfsetspeed, cfmakeraw, tcgetattr, tcsetattr, termios, TCSANOW, B115200};

        use super::super::{u32_to_arr_be, slice_first_bytes_to_u32_be, RadioMode};
        use super::{LoraCodeRate, EU_CENTER_FREQ_HZ};

        use crate::bridge::*;

        /// The message types the RNode accepts.
        #[repr(u8)]
        #[derive(PartialEq, Clone, Copy, Debug)]
        enum Msgs {
            // A message:
            Data = 0x00,

            // 4-byte u32 messages:
            Freq = 0x01,
            /// Bandwidth used for transmission.
            /// Must be synchronized on the receive and sending ends.
            /// Range 7.8kHz - 500kHz. (250kHz used for public bitcoin header sync)
            BW = 0x02,
            TxPwr = 0x03,
            /// 2-Log of the number of "chips" used to represent a symbol on the air.
            /// Must be synchronized on the receive and sending ends.
            /// Range: 6 - 12 (12 used for public bitcoin header sync)
            Spread = 0x04,
            /// The amount of additional error correcting bits per 4 bits of data.
            /// Does *not* need to be synchronized on the receive and sending ends.
            /// Range: 4/5 - 4/8 (values 5-8) (5 aka 4/5 ie 1.25x overhead used by default)
            CodeRate = 0x05,

            RadioState = 0x06,

            /// Send this with contents 0x73 to get back this with contents 0x46
            Detect = 0x08,

            /// Disable the RNode-specific packet fragmentation
            Promisc = 0x0e,

            /// Flow control (read-only):
            Ready = 0x0f,

            // Rx/Tx Stats are defined as always 0 in current firmware:
            //RxStats = 0x21,
            //TxStats = 0x22,

            /// RSSI of the next msg received (received immediately before said packet)
            NextRSSI = 0x23,

            /// RSSI of the next msg received (received immediately before said packet)
            NextSNR = 0x24,

            /// Gets the Wideband RSSI out of the modem which the datasheet recommends
            /// for local randomness generation, so, ehh, why not? Can't be secure, but
            /// also no worse than xor'ing in some zeros.
            WidebandRSSI = 0x40,

            /// Gets the current firmware revision from the device
            FirmwareRev = 0x50,

            /// Sets us in "host-control" mode, which is what we want, we want to control!
            HostControl = 0x54,

            Error = 0x90,

            // Control:
            FEnd = 0xc0,
            Esc = 0xdb,
        }

        pub struct RNodeDev {
            broadcast_msg_queue: LinkedList<(Msgs, Vec<u8>)>,
            recv_msg_queue: LinkedList<Vec<u8>>,

            tty: String,
            tty_f: Option<fs::File>,

            mode: RadioMode,
            center_freq_hz: u32,
            code_rate: LoraCodeRate,
            txpower: u8,

            msg: Vec<u8>,
            in_msg: bool,
            in_esc: bool,
            msg_err: bool,
            last_recv: Instant,

            write_ready: bool,
            last_send: Instant,
            write_msg: Option<(Msgs, Vec<u8>)>,
            write_pos: usize,

            detected: bool,
        }

        fn escape_vec(v: Vec<u8>) -> Vec<u8> {
            let mut count = 0;
            for c in v.iter() {
                if *c == Msgs::FEnd as u8 || *c == Msgs::Esc as u8 {
                    count += 1;
                }
            }
            if count != 0 {
                let mut new_v = Vec::with_capacity(v.len() + count);
                for c in v {
                    if c == Msgs::FEnd as u8 { new_v.extend_from_slice(&[Msgs::Esc as u8, 0xdc]); }
                    else if c == Msgs::Esc as u8 { new_v.extend_from_slice(&[Msgs::Esc as u8, 0xdd]); }
                    else { new_v.push(c); }
                }
                new_v
            } else {
                v
            }
        }

        impl RNodeDev {
            /// Returns true if we've opened the tty and set the serial params
            fn reopen(&mut self) -> bool {
                self.tty_f.take();
                let tty_f = match fs::OpenOptions::new().read(true).write(true).open(&self.tty) {
                    Ok(f) => f,
                    Err(_) => return false,
                };

                // Set mode to raw, 115200 8N1 (in cpp_bridge)
                let mut term: termios = termios { // Dummy values:
                    c_iflag: 0, c_oflag: 0, c_cflag: 0, c_lflag: 0, c_line: 0, c_cc: [0; 32], c_ispeed: 0, c_ospeed: 0
                };
                assert_eq!(unsafe { tcgetattr(tty_f.as_raw_fd(), &mut term) }, 0);
                assert_eq!(unsafe { cfsetspeed(&mut term, B115200) }, 0);
                unsafe { cfmakeraw(&mut term) };
                assert_eq!(unsafe { tcsetattr(tty_f.as_raw_fd(), TCSANOW, &term) }, 0);

                self.tty_f = Some(tty_f);
                self.broadcast_msg_queue.clear();

                self.broadcast_msg_queue.push_back((Msgs::Detect, vec![0x73]));
                self.broadcast_msg_queue.push_back((Msgs::FirmwareRev, vec![0xff]));
                self.broadcast_msg_queue.push_back((Msgs::HostControl, vec![1]));
                self.broadcast_msg_queue.push_back((Msgs::RadioState, vec![0]));
                self.broadcast_msg_queue.push_back((Msgs::Freq, escape_vec(u32_to_arr_be(self.center_freq_hz).to_vec())));
                self.broadcast_msg_queue.push_back((Msgs::BW, escape_vec(u32_to_arr_be(250_000).to_vec())));
                self.broadcast_msg_queue.push_back((Msgs::TxPwr, vec![self.txpower]));
                self.broadcast_msg_queue.push_back((Msgs::Spread, vec![11]));
                match self.code_rate {
                    LoraCodeRate::FourOnFive => self.broadcast_msg_queue.push_back((Msgs::CodeRate, vec![5])),
                    LoraCodeRate::FourOnSix => self.broadcast_msg_queue.push_back((Msgs::CodeRate, vec![6])),
                    LoraCodeRate::FourOnSeven => self.broadcast_msg_queue.push_back((Msgs::CodeRate, vec![7])),
                    LoraCodeRate::FourOnEight => self.broadcast_msg_queue.push_back((Msgs::CodeRate, vec![8])),
                }
                self.broadcast_msg_queue.push_back((Msgs::Promisc, vec![1]));
                self.broadcast_msg_queue.push_back((Msgs::RadioState, vec![1]));

                self.msg = Vec::new();
                self.in_msg = false;
                self.in_esc = false;
                self.msg_err = false;
                self.last_recv = Instant::now();

                self.write_ready = true;
                self.last_send = Instant::now();
                self.write_msg = None;
                self.write_pos = 0;

                self.detected = false;

                true
            }

            pub fn new(tty: &str, center_freq_hz: u32, code_rate: LoraCodeRate, mode: RadioMode, txpower: u8) -> Option<Self> {
                let mut ret = Self {
                    broadcast_msg_queue: LinkedList::new(),
                    recv_msg_queue: LinkedList::new(),

                    tty: tty.to_string(),
                    tty_f: None,

                    mode,
                    center_freq_hz,
                    code_rate,
                    txpower,

                    msg: Vec::new(),
                    in_msg: false,
                    in_esc: false,
                    msg_err: false,
                    last_recv: Instant::now(),

                    write_ready: true,
                    last_send: Instant::now(),
                    write_msg: None,
                    write_pos: 0,

                    detected: false,
                };
                if ret.reopen() {
                    Some(ret)
                } else {
                    None
                }
            }
        }

        impl super::super::RadioDevice for RNodeDev {
            fn broadcast_msg(&mut self, msg: Vec<u8>) {
                if self.mode == RadioMode::ReadOnly { return; }

                if self.broadcast_msg_queue.len() < 20 {
                    log_line(&format!("Broadcasting LORA msg: {:x?}", &msg[..]), true);
                    self.broadcast_msg_queue.push_back((Msgs::Data, msg));
                } else {
                    log_line("Dropping LORA message due to full queue!", false);
                }
            }
            fn recv_msg(&mut self) -> Option<Vec<u8>> {
                self.recv_msg_queue.pop_front()
            }
            fn mode(&self) -> RadioMode {
                self.mode
            }

            fn max_msgs_per_day(&self) -> u64 {
                // A message from 86 - 90 bytes with an explicit header uses 98, 116, 134, or
                // 152 symbols at SF12 / 250 kHz, depending on the coding rate, taking 1806.3+,
                // 2101.2+, 2396.1+ or 2691+ ms to send.
                // For EU 869.4 - 869.65 MHz band the duty cycle limit is 10%.
                // Thus, we should never send more than 4783, 4111, 3605, or 3210 frames/day.
                // This meets the minimum 1200 frams, including:
                // * We budget 192 (8 blocks/hour) frames for current block broadcasting.
                // * We budget 1008 frames for sending the last two weeks' blocks (once per two
                //   days) which translates to one historical block every ~85.715 seconds.
                // In the US, no such restriction exists, so we disable the response limits.
                if self.center_freq_hz == EU_CENTER_FREQ_HZ {
                    match self.code_rate {
                        LoraCodeRate::FourOnFive => 4783,
                        LoraCodeRate::FourOnSix => 4111,
                        LoraCodeRate::FourOnSeven => 3605,
                        LoraCodeRate::FourOnEight => 3210,
                    }
                } else { std::u64::MAX }
            }

            fn file(&self) -> Option<&fs::File> {
                self.tty_f.as_ref()
            }

            fn needs_write(&self) -> bool {
                (!self.in_msg || self.write_pos != 0) && self.write_ready && self.write_msg.is_some()
            }

            fn poll(&mut self, readable: bool, writable: bool) {
                // If its been a full five minutes since the last time we received anything,
                // try to reset the world.
                if self.tty_f.is_none() || self.last_recv < Instant::now() - Duration::from_secs(5 * 60) {
                    self.reopen();
                }

                let tty_f = match &mut self.tty_f {
                    Some(f) => f,
                    None => return,
                };
                if self.write_msg.is_none() {
                    if let Some((msg_type, new_msg)) = self.broadcast_msg_queue.pop_front() {
                        self.write_msg = Some((msg_type, escape_vec(new_msg)));
                    } else if self.write_ready && self.last_send < Instant::now() - Duration::from_secs(1) {
                        // If we're bored, get a new random byte for use in our RNG
                        self.write_msg = Some((Msgs::WidebandRSSI, vec![0]));
                    }
                }
                if writable && (!readable || self.write_pos != 0) {
                    let msg_type = self.write_msg.as_ref().unwrap().0;

                    if self.write_pos == 0 || self.write_pos == 1 {
                        match tty_f.write(&[Msgs::FEnd as u8, msg_type as u8][self.write_pos..]) {
                            Ok(n) if n != 0 => self.write_pos += n,
                            _ => panic!("TTY Closed"),
                        };
                    } else if self.write_pos - 2 < self.write_msg.as_ref().unwrap().1.len() {
                        match tty_f.write(&self.write_msg.as_ref().unwrap().1[self.write_pos - 2..]) {
                            Ok(n) if n != 0 => self.write_pos += n,
                            _ => panic!("TTY Closed"),
                        };
                    } else {
                        tty_f.write_all(&[Msgs::FEnd as u8]).expect("TTY Closed");
                        // If its a message that doesn't get a response, don't wait on one
                        if msg_type == Msgs::HostControl {
                            self.write_msg = None;
                        } else {
                            self.write_ready = false;
                        }
                        self.write_pos = 0;
                        self.last_send = Instant::now();
                    }
                }
                // If we're not currently receiving a message, and we're waiting on a
                // response (write_msg.is_some() && !write_ready), and its been a full
                // three seconds since we sent the message, just give up waiting on the
                // response and send the next message.
                if !self.in_msg && self.write_msg.is_some() && !self.write_ready && self.last_send < Instant::now() - Duration::from_secs(3) {
                    log_line(&format!("No response to message of type {:?}, dropping it!", self.write_msg.as_ref().unwrap().0), true);
                    if self.detected {
                        self.write_msg = None;
                    } else {
                        self.write_msg = Some((Msgs::Detect, vec![0x73]));
                    }
                    self.write_ready = true;
                }

                if readable {
                    let mut buff = [0u8; 256];
                    for i in 0..match tty_f.read(&mut buff) {
                        Ok(x) if x > 0 => x,
                        _ => panic!("TTY Closed"),
                    } {
                        let b = buff[i];
                        if !self.in_msg && b != Msgs::FEnd as u8 { continue; }
                        if b == Msgs::FEnd as u8 {
                            if self.in_msg {
                                if !self.msg.is_empty() {
                                    // If we're waiting on a response, mark write ready again
                                    if self.write_msg.is_some() &&
                                        (self.msg[0] == self.write_msg.as_ref().unwrap().0 as u8 ||
                                         (self.write_msg.as_ref().unwrap().0 == Msgs::Data && self.msg[0] == Msgs::Ready as u8)) {
                                        log_line(&format!("Finished writing RNode message with ACK type {:x}", self.msg[0]), true);
                                        self.write_ready = true;
                                        self.write_msg = None;
                                    }
                                    self.last_recv = Instant::now();
                                    match self.msg[0] {
                                        x if x == Msgs::Detect as u8 => {
                                            if self.msg.len() >= 2 && self.msg[1] == 0x46 {
                                                log_line("Detected RNode", true);
                                                self.detected = true;
                                            }
                                        },
                                        x if x == Msgs::FirmwareRev as u8 => {
                                            if self.msg.len() >= 3 {
                                                if self.msg[1] == 1 && self.msg[2] <= 10 {
                                                    log_line(&format!("RNode reports firmware rev of {}.{}, too old as LowDataRateOptimize will be unset!", self.msg[1], self.msg[2]), false);
                                                    panic!();
                                                } else {
                                                    log_line(&format!("RNode reports firmware rev of {}.{}", self.msg[1], self.msg[2]), true);
                                                }
                                            }
                                        },
                                        x if x == Msgs::NextRSSI as u8 => {
                                            if self.msg.len() >= 2 {
                                                gather_event_entropy(slice_first_bytes_to_u32_be(&self.msg[..]));
                                                log_line(&format!("Received LORA packet with RSSI {} dBm", self.msg[1] as i16 - 157), true);
                                            }
                                        },
                                        x if x == Msgs::NextSNR as u8 => {
                                            if self.msg.len() >= 2 {
                                                gather_event_entropy(slice_first_bytes_to_u32_be(&self.msg[..]));
                                                log_line(&format!("Received LORA packet with SNR {} dBm", self.msg[1] as i16 - 128), true);
                                            }
                                        },
                                        x if x == Msgs::Data as u8 => {
                                            gather_event_entropy(slice_first_bytes_to_u32_be(&self.msg[..]));
                                            self.recv_msg_queue.push_back(self.msg.split_off(1));
                                        },
                                        x if x == Msgs::WidebandRSSI as u8 => {
                                            gather_event_entropy(slice_first_bytes_to_u32_be(&self.msg[..]));
                                        },
                                        x if x == Msgs::RadioState as u8 => {
                                            if self.msg.len() >= 2 && self.msg[1] == 1 {
                                                log_line("Successfully initialized LORA radio!", false);
                                            }
                                        },
                                        x if x == Msgs::Error as u8 => {
                                            if self.msg.len() >= 2 {
                                                match self.msg[1] {
                                                    0x01 => {
                                                        log_line("Failed to initialize LORA radio hardware", false);
                                                    },
                                                    0x02 => {
                                                        log_line("Hardware error transmitting LORA packet", false);
                                                    },
                                                    0x04 => {
                                                        log_line("LORA flow-control error, packet discarded", true);
                                                    },
                                                    _ => {
                                                        log_line("Unknown/undefined LORA error! Check your hardware.", false);
                                                    },
                                                }
                                            }
                                        },
                                        _ => {},
                                    }
                                    self.msg = Vec::new();
                                }
                                self.in_msg = false;
                                continue;
                            } else {
                                self.in_msg = true;
                                self.msg.clear();
                                continue;
                            }
                        }
                        if self.msg_err { continue; }
                        if self.in_esc {
                            if b == 0xdc { self.msg.push(Msgs::FEnd as u8); }
                            else if b == 0xdd { self.msg.push(Msgs::Esc as u8); }
                            else { self.msg_err = true; }
                            self.in_esc = false
                        } else if b == Msgs::Esc as u8 {
                            self.in_esc = true;
                        } else if self.msg.len() > 1000 {
                            self.msg_err = true;
                        } else {
                            self.msg.push(b);
                        }
                    }
                }
            }
        }
    }
}

struct RawFramedRadio {
    tty_f: fs::File,
    mode: RadioMode,

    broadcast_msg_queue: LinkedList<Vec<u8>>,
    recv_msg_queue: LinkedList<Vec<u8>>,

    read_magic: [u8; 4],

    read_magic_pos: usize,
    read_pos: usize,
    read_msg: Vec<u8>,

    write_msg: Vec<u8>,
    write_pos: usize,
}
impl RadioDevice for RawFramedRadio {
    fn broadcast_msg(&mut self, msg: Vec<u8>) {
        if self.mode == RadioMode::ReadOnly { return; }

        if self.broadcast_msg_queue.len() < 20 {
            self.broadcast_msg_queue.push_back(msg);
        } else {
            log_line("Dropping radio message due to full queue!", false);
        }
    }
    fn recv_msg(&mut self) -> Option<Vec<u8>> {
        self.recv_msg_queue.pop_front()
    }
    fn mode(&self) -> RadioMode {
        self.mode
    }
    fn max_msgs_per_day(&self) -> u64 {
        std::u64::MAX
    }
    fn needs_write(&self) -> bool {
        !self.write_msg.is_empty() || !self.broadcast_msg_queue.is_empty()
    }
    fn file(&self) -> Option<&fs::File> {
        Some(&self.tty_f)
    }
    fn poll(&mut self, readable: bool, writable: bool) {
        if readable {
            let mut buff = [0u8; 256];
            for i in 0..match self.tty_f.read(&mut buff) {
                Ok(x) if x > 0 => x,
                _ => panic!("TTY Closed"),
            } {
                if self.read_magic_pos < self.read_magic.len() {
                    if self.read_magic[self.read_magic_pos] == buff[i] {
                        self.read_magic_pos += 1;
                    } else {
                        self.read_magic_pos = 0;
                        continue;
                    }
                } else {
                    if self.read_pos == 0 {
                        self.read_msg.resize(buff[i] as usize + 4, 0u8);
                        self.read_msg[0..4].copy_from_slice(&self.read_magic);
                        self.read_pos = 4;
                    } else {
                        self.read_msg[self.read_pos] = buff[i];
                        self.read_pos += 1;
                    }
                    if self.read_pos == self.read_msg.len() {
                        let mut msg = Vec::new();
                        std::mem::swap(&mut msg, &mut self.read_msg);
                        self.recv_msg_queue.push_back(msg);
                        self.read_magic_pos = 0;
                        self.read_pos = 0;
                    }
                }
            }
        }
        if writable {
            if self.write_pos >= self.write_msg.len() {
                if let Some(msg) = self.broadcast_msg_queue.pop_front() {
                    assert_eq!(msg[0..4], self.read_magic[..]);
                    let len = msg.len() - 4;
                    assert!(len <= 255);
                    self.write_msg = msg;
                    self.write_msg.insert(4, len as u8);
                    self.write_pos = 0;
                }
            }
            if self.write_pos < self.write_msg.len() {
                match self.tty_f.write(&self.write_msg[self.write_pos..]) {
                    Ok(x) if x > 0 => self.write_pos += x,
                    _ => panic!("TTY Closed"),
                }
            }
        }
    }
}


struct HexLinesRadio {
    tty_f: fs::File,
    mode: RadioMode,

    broadcast_msg_queue: LinkedList<Vec<u8>>,
    recv_msg_queue: LinkedList<Vec<u8>>,

    read_msg: String,
    write_msg: String,
    write_pos: usize,
}
impl RadioDevice for HexLinesRadio {
    fn broadcast_msg(&mut self, msg: Vec<u8>) {
        if self.mode == RadioMode::ReadOnly { return; }

        if self.broadcast_msg_queue.len() < 20 {
            self.broadcast_msg_queue.push_back(msg);
        } else {
            log_line("Dropping radio message due to full queue!", false);
        }
    }
    fn recv_msg(&mut self) -> Option<Vec<u8>> {
        self.recv_msg_queue.pop_front()
    }
    fn mode(&self) -> RadioMode {
        self.mode
    }
    fn max_msgs_per_day(&self) -> u64 {
        std::u64::MAX
    }
    fn needs_write(&self) -> bool {
        !self.write_msg.is_empty() || !self.broadcast_msg_queue.is_empty()
    }
    fn file(&self) -> Option<&fs::File> {
        Some(&self.tty_f)
    }
    fn poll(&mut self, readable: bool, writable: bool) {
        if readable {
            let mut buff = [0u8; 256];
            for i in 0..match self.tty_f.read(&mut buff) {
                Ok(x) if x > 0 => x,
                _ => panic!("TTY Closed"),
            } {
                match buff[i] as char {
                    '0'...'9' | 'a'...'f' | 'A'...'F' => {
                        if self.read_msg.len() >= MAX_FRAME_SIZE * 2 {
                            self.read_msg.clear();
                        }
                        self.read_msg.push(buff[i] as char);
                    },
                    '\n' | '\r' => {
                        if !self.read_msg.is_empty() && self.read_msg.len() % 2 == 0 {
                            let mut msg = Vec::with_capacity(self.read_msg.len() / 2);
                            for b in self.read_msg.as_bytes().chunks(2) {
                                msg.push((
                                    ((b[0] as char).to_digit(16).unwrap() << 4) |
                                    (b[1] as char).to_digit(16).unwrap()) as u8);
                            }
                            self.recv_msg_queue.push_back(msg);
                        }
                        self.read_msg.clear();
                    },
                    _ => { self.read_msg.clear() },
                }

            }
        }
        if writable {
            if self.write_pos >= self.write_msg.len() {
                if let Some(msg) = self.broadcast_msg_queue.pop_front() {
                    use std::fmt::Write;
                    self.write_msg.clear();
                    for ch in msg {
                        write!(self.write_msg, "{:02x}", ch).expect("writing to string");
                    }
                    self.write_msg.push('\n');
                    self.write_pos = 0;
                }
            }
            if self.write_pos < self.write_msg.len() {
                match self.tty_f.write(&self.write_msg.as_bytes()[self.write_pos..]) {
                    Ok(x) if x > 0 => self.write_pos += x,
                    _ => panic!("TTY Closed"),
                }
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn init_radio_headers(proto_tty: *const c_char, msg_start_4_bytes: *const u8) -> bool {
    // Always catch panics so that even if we have some bug in our parser we don't take the
    // rest of Bitcoin Core down with us:
    if let Ok(res) = catch_unwind(move || {
        let mut net_magic: [u8; 4] = [0; 4];
        unsafe { ptr::copy(msg_start_4_bytes, (&mut net_magic).as_mut_ptr(), 4) };

        let proto_tty_str = match unsafe { CStr::from_ptr(proto_tty) }.to_str() {
            Ok(r) => r,
            Err(_) => return false,
        };

        let mut proto_tty_iter = proto_tty_str.splitn(3, ':');
        let proto = proto_tty_iter.next();
        let mode = match proto_tty_iter.next() {
            Some(x) if x.eq_ignore_ascii_case("ro") => RadioMode::ReadOnly,
            Some(x) if x.eq_ignore_ascii_case("wo") => RadioMode::WriteOnly,
            Some(x) if x.eq_ignore_ascii_case("rw") => RadioMode::ReadWrite,
            _ => return false,
        };

        let mut radio_dev: Box<RadioDevice> = match proto {
            Some(x) if x.eq_ignore_ascii_case("lora") => {
                let mut lora_iter = if let Some(rem) = proto_tty_iter.next() {
                    rem.splitn(4, ':')
                } else { return false; };

                let center_freq_hz = match lora_iter.next() {
                    Some(x) if x.eq_ignore_ascii_case("na") => lora::NA_CENTER_FREQ_HZ,
                    Some(x) if x.eq_ignore_ascii_case("eu") => lora::EU_CENTER_FREQ_HZ,
                    _ => return false,
                };
                let coding_rate = match lora_iter.next() {
                    Some("1") => lora::LoraCodeRate::FourOnFive,
                    Some("2") => lora::LoraCodeRate::FourOnSix,
                    Some("3") => lora::LoraCodeRate::FourOnSeven,
                    Some("4") => lora::LoraCodeRate::FourOnEight,
                    _ => return false,
                };
                let device = match lora_iter.next() {
                    Some(p) => p,
                    None => return false,
                };

                let mut tty = match lora_iter.next() {
                    Some(t) => t,
                    None => return false,
                };

                let txp = if device.eq_ignore_ascii_case("rnode") {
                    let mut tty_iter = tty.splitn(2, ':');
                    let p = match tty_iter.next().and_then(|p| str::parse::<u8>(p).ok()) {
                        Some(p) => p,
                        None => return false,
                    };
                    tty = match tty_iter.next() {
                        Some(t) => t,
                        None => return false,
                    };
                    p
                } else { 0 };

                Box::new(match device {
                    x if x.eq_ignore_ascii_case("rnode") =>
                        match lora::rnode::RNodeDev::new(tty, center_freq_hz, coding_rate, mode, txp) {
                            Some(dev) => dev,
                            None => return false,
                        },
                    _ => return false,
                })
            },
            Some(x) if x.eq_ignore_ascii_case("hexpipe") => {
                let tty = match proto_tty_iter.next() {
                    Some(t) => t,
                    None => return false,
                };
                Box::new(HexLinesRadio {
                    tty_f: match fs::OpenOptions::new().read(true).write(true).open(tty) {
                        Ok(f) => f,
                        Err(_) => return false,
                    },
                    mode,

                    broadcast_msg_queue: LinkedList::new(),
                    recv_msg_queue: LinkedList::new(),

                    read_msg: String::new(),
                    write_msg: String::new(),
                    write_pos: 0,
                })
            },
            Some(x) if x.eq_ignore_ascii_case("rawframed") => {
                let tty = match proto_tty_iter.next() {
                    Some(t) => t,
                    None => return false,
                };
                Box::new(RawFramedRadio {
                    tty_f: match fs::OpenOptions::new().read(true).write(true).open(tty) {
                        Ok(f) => f,
                        Err(_) => return false,
                    },
                    mode,

                    broadcast_msg_queue: LinkedList::new(),
                    recv_msg_queue: LinkedList::new(),

                    read_magic: net_magic,

                    read_magic_pos: 0,
                    read_pos: 0,
                    read_msg: Vec::new(),

                    write_msg: Vec::new(),
                    write_pos: 0,
                })
            },
            _ => return false,
        };
        #[cfg(target_family = "unix")]
        {
            std::thread::spawn(move || {
                THREAD_COUNT.fetch_add(1, Ordering::AcqRel);
                // Always catch panics so that even if we have some bug in our parser we don't take the
                // rest of Bitcoin Core down with us:
                let _ = catch_unwind(move || {
                    //XXX: await_ibd_complete_or_stalled();

                    let mut max_msgs = radio_dev.max_msgs_per_day();
                    assert!(max_msgs >= 1200);
                    max_msgs -= 192; // Broadcast new blocks as they come in
                    if radio_dev.mode() == RadioMode::ReadWrite {
                        // Try to reserve about half our broadcast space for responses
                        max_msgs /= 2;
                    }
                    let (historical_msgs_per_day, historical_block_range, per_msg_time) = if max_msgs > 1008 * 4 {
                        // Last 8 weeks of blocks, every 2 days
                        (4*1008, 6*24*7*4*2, Duration::from_millis(21_428))
                    } else if max_msgs > 1008 * 2 {
                        // Last 4 weeks of blocks, every 2 days
                        (2*1008, 6*24*7*4, Duration::from_millis(42_857))
                    } else {
                        // Last 2 weeks of blocks, every 2 days
                        (1008, 6*24*7*2, Duration::from_millis(85_715))
                    };
                    let max_resp_per_hour = radio_dev.max_msgs_per_day() - 192 - historical_msgs_per_day;

                    let mut prev_tip = BlockIndex::best_header();

                    let mut msg_time_rand = RandomContext::new();
                    // Keep track of the time we should target sending out, so we meet regulatory
                    // limits:
                    let mut historical_send_time = Instant::now() + per_msg_time;
                    // But actually send at random intervals around it:
                    let mut next_historical_send = historical_send_time - Duration::from_secs(10) + Duration::from_millis(msg_time_rand.randrange(20_000));
                    let mut last_historical_send_height = prev_tip.height();

                    let mut this_hour = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() % 60;
                    let mut responses_this_hour = 0;

                    let mut txn_reconstruction_cache: [Option<(Instant, Vec<u8>)>; 256] = [None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None];

                    while unsafe { !rusty_ShutdownRequested() } {
                        let mut pollfds = [pollfd { fd: 0, events: 0, revents: 0 }];
                        if let Some(dev) = radio_dev.file() {
                            assert_eq!(unsafe { fcntl(dev.as_raw_fd(), F_SETFL, O_NONBLOCK) }, 0);
                            let pollevents = POLLIN | if radio_dev.needs_write() { POLLOUT } else { 0 };
                            pollfds[0] = pollfd { fd: dev.as_raw_fd(), events: pollevents, revents: 0 };
                            assert!(unsafe { poll(pollfds.as_mut_ptr(), 1, 100) } >= 0);
                        } else {
                            std::thread::sleep(Duration::from_millis(100));
                        }

                        radio_dev.poll(pollfds[0].revents & POLLIN != 0, pollfds[0].revents & POLLOUT != 0);

                        let new_tip = BlockIndex::best_header();
                        if prev_tip != new_tip {
                            radio_dev.broadcast_msg(build_header_data_packet(&net_magic, new_tip, new_tip));
                            prev_tip = new_tip;
                        }

                        if let Some(msg) = radio_dev.recv_msg() {
                            if let Some(resp) = process_msg(&msg[..], &net_magic, &mut txn_reconstruction_cache) {
                                let cur_hour = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() % 60;
                                if this_hour != cur_hour {
                                    responses_this_hour = 0;
                                    this_hour = cur_hour
                                }
                                if responses_this_hour < max_resp_per_hour {
                                    responses_this_hour += 1;
                                    radio_dev.broadcast_msg(resp);
                                }
                            }
                        }
                        if next_historical_send < Instant::now() {
                            if last_historical_send_height >= new_tip.height() {
                                last_historical_send_height = cmp::max(0, new_tip.height() - historical_block_range);
                            } else {
                                last_historical_send_height += 1;
                            }
                            if let Some(index) = new_tip.get_ancestor(last_historical_send_height) {
                                radio_dev.broadcast_msg(build_header_data_packet(&net_magic, index, new_tip));
                            }
                            historical_send_time += per_msg_time;
                            next_historical_send = historical_send_time - Duration::from_secs(10) + Duration::from_millis(msg_time_rand.randrange(20_000));
                        }
                    }
                });
                THREAD_COUNT.fetch_sub(1, Ordering::AcqRel);
            });
            true
        }
        #[cfg(target_family = "windows")]
        {
            //TODO: Support Windows etc
            false
        }
    }) {
        res
    } else { false }
}

#[no_mangle]
pub extern "C" fn stop_radio_headers() {
    while THREAD_COUNT.load(Ordering::Acquire) != 0 {
        std::thread::sleep(Duration::from_millis(10));
    }
}
