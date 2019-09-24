use std::sync::atomic::{AtomicUsize, Ordering};
use std::panic::catch_unwind;
use std::time::{SystemTime, UNIX_EPOCH, Instant, Duration};
use std::{cmp, fs, ptr};

use std::ffi::CStr;
use std::os::raw::c_char;

use crate::bridge::*;
use crate::await_ibd_complete_or_stalled;

const POST_NET_HDR_MAGIC: u8 = 'H' as u8;
const POST_NET_REQ_MAGIC: u8 = 'R' as u8;
const POST_NET_TXN_MAGIC: u8 = 'T' as u8;

const EU_CENTER_FREQ_HZ: u32 = 869_525_000; // 869.4 - 869.65
const NA_CENTER_FREQ_HZ: u32 = 915_875_000; // 915.75 - 916

#[derive(Copy, Clone)]
pub enum LoraCodeRate {
    FourOnFive,
    FourOnSix,
    FourOnSeven,
    FourOnEight,
}

/// Maximum frame size (excluding LORA headers) we're willing to send. Important for fitting inside
/// regulatory duty cycle limits, see comment in the main protocol handler for more.
const MAX_FRAME_SIZE: usize = 93;

trait LoraDevice {
    fn broadcast_msg(&self, msg: Vec<u8>);
    fn recv_msg(&self) -> Option<Vec<u8>>;
}

fn u32_to_arr_be(val: u32) -> [u8; 4] {
    [((val >> 3*8) & 0xff) as u8,
     ((val >> 2*8) & 0xff) as u8,
     ((val >> 1*8) & 0xff) as u8,
     ((val >> 0*8) & 0xff) as u8]
}

static THREAD_COUNT: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_family = "unix")]
mod rnode {
    use std::os::unix::io::AsRawFd;
    use std::fs;
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::Ordering;
    use std::collections::LinkedList;
    use std::panic::catch_unwind;
    use std::time::{SystemTime, UNIX_EPOCH, Instant, Duration};

    use super::{u32_to_arr_be, THREAD_COUNT, LoraCodeRate};

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
        /// Note that we avoid using 125kHz/SF11 or SF12 as it requires the
        /// "low data rate optimization" mode on some Semtech modems, the
        /// enabling thereof appears to be commonly misimplemented (including,
        /// notable, on the RNode firmware).
        BW = 0x02,
        TxPwr = 0x03,
        /// 2-Log of the number of "chips" used to represent a symbol on the air.
        /// Must be synchronized on the receive and sending ends.
        /// Range: 6 - 12 (11 used for public bitcoin header sync)
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
        broadcast_msg_queue: Mutex<LinkedList<(Msgs, Vec<u8>)>>,
        recv_msg_queue: Mutex<LinkedList<Vec<u8>>>,
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
        pub fn new(mut tty_f: fs::File, center_freq_hz: u32, code_rate: LoraCodeRate) -> Option<Arc<Self>> {
            if !unsafe { rusty_select_possible(tty_f.as_raw_fd()) } { return None; }

            let mut initial_msgs = LinkedList::new();
            initial_msgs.push_back((Msgs::Detect, vec![0x73]));
            initial_msgs.push_back((Msgs::FirmwareRev, vec![0xff]));
            initial_msgs.push_back((Msgs::RadioState, vec![0]));
            initial_msgs.push_back((Msgs::HostControl, vec![1]));
            initial_msgs.push_back((Msgs::Freq, escape_vec(u32_to_arr_be(center_freq_hz).to_vec())));
            initial_msgs.push_back((Msgs::BW, escape_vec(u32_to_arr_be(250_000).to_vec())));
            initial_msgs.push_back((Msgs::TxPwr, vec![17]));
            initial_msgs.push_back((Msgs::Spread, vec![11]));
            match code_rate {
                LoraCodeRate::FourOnFive => initial_msgs.push_back((Msgs::CodeRate, vec![5])),
                LoraCodeRate::FourOnSix => initial_msgs.push_back((Msgs::CodeRate, vec![6])),
                LoraCodeRate::FourOnSeven => initial_msgs.push_back((Msgs::CodeRate, vec![7])),
                LoraCodeRate::FourOnEight => initial_msgs.push_back((Msgs::CodeRate, vec![8])),
            }
            initial_msgs.push_back((Msgs::Promisc, vec![1]));
            initial_msgs.push_back((Msgs::RadioState, vec![1]));

            let ret = Arc::new(Self {
                broadcast_msg_queue: Mutex::new(initial_msgs),
                recv_msg_queue: Mutex::new(LinkedList::new()),
            });
            let us = Arc::clone(&ret);
            std::thread::spawn(move || {
                THREAD_COUNT.fetch_add(1, Ordering::AcqRel);
                // Always catch panics so that even if we have some bug in our parser we don't take the
                // rest of Bitcoin Core down with us:
                let _ = catch_unwind(move || {
                    // Set mode to raw, 115200 8N1 (in cpp_bridge)
                    assert!(unsafe { rusty_set_char_dev_raw_115200(tty_f.as_raw_fd()) });

                    // read buffers/state:
                    let mut msg = Vec::new();
                    let mut in_msg = false;
                    let mut in_esc = false;
                    let mut msg_err = false;

                    let mut write_ready = true;
                    let mut last_send = Instant::now();
                    let mut write_msg: Option<(Msgs, Vec<u8>)> = None;
                    let mut write_pos = 0;

                    let mut detected = false;

                    // In firmware up to and including 1.10, the NextRSSI message received
                    // immediately before a Data message has the wrong RSSI, however if we query
                    // for the same message after receiving the data message, we'll get the right
                    // value.
                    let mut needs_rssi_workaround = false;
                    let mut awaiting_real_rssi = false;

                    while unsafe { !rusty_ShutdownRequested() } {
                        let select_res = unsafe { rusty_select(tty_f.as_raw_fd(), !in_msg && write_ready && write_msg.is_some(), 0, 100_000) };

                        if (select_res & 0b11 == 0b10) || (write_pos != 0 && select_res & 0b10 == 0b10) {
                            let (msg_type, msg_bytes) = write_msg.as_ref().unwrap();

                            if write_pos == 0 || write_pos == 1 {
                                match tty_f.write(&[Msgs::FEnd as u8, *msg_type as u8][write_pos..]) {
                                    Ok(n) if n != 0 => write_pos += n,
                                    _ => panic!("TTY Closed"),
                                };
                            } else if write_pos - 2 < msg_bytes.len() {
                                match tty_f.write(&msg_bytes[write_pos - 2..]) {
                                    Ok(n) if n != 0 => write_pos += n,
                                    _ => panic!("TTY Closed"),
                                };
                            } else {
                                tty_f.write_all(&[Msgs::FEnd as u8]).expect("TTY Closed");
                                // If its a message that doesn't get a response, don't wait on one
                                if *msg_type == Msgs::HostControl {
                                    write_msg = None;
                                } else {
                                    write_ready = false;
                                }
                                write_pos = 0;
                                last_send = Instant::now();
                            }
                        }
                        if write_msg.is_none() {
                            if let Some((msg_type, new_msg)) = us.broadcast_msg_queue.lock().unwrap().pop_front() {
                                write_msg = Some((msg_type, escape_vec(new_msg)));
                            } else if write_ready && last_send < Instant::now() - Duration::from_secs(1) {
                                // If we're bored, get a new random byte for use in our RNG
                                write_msg = Some((Msgs::WidebandRSSI, vec![0]));
                            }
                        }
                        // If we're not currently receiving a message, and we're waiting on a
                        // response (write_msg.is_some() && !write_ready), and its been a full
                        // ten seconds since we sent the message, just give up waiting on the
                        // response and send the next message.
                        if !in_msg && write_msg.is_some() && !write_ready && last_send < Instant::now() - Duration::from_secs(10) {
                            if detected {
                                write_msg = None;
                            } else {
                                write_msg = Some((Msgs::Detect, vec![0x73]));
                            }
                            write_ready = true;
                        }

                        if select_res & 0b1 != 0 {
                            let mut buff = [0u8; 256];
                            for i in 0..match tty_f.read(&mut buff) {
                                Ok(x) if x > 0 => x,
                                _ => panic!("TTY Closed"),
                            } {
                                let b = buff[i];
                                if !in_msg && b != Msgs::FEnd as u8 { continue; }
                                if b == Msgs::FEnd as u8 {
                                    if in_msg {
                                        if !msg.is_empty() {
                                            let time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards");
                                            provide_entropy(&u32_to_arr_be(time.subsec_nanos()));
                                            // If we're waiting on a response, mark write ready again
                                            if write_msg.is_some() &&
                                                (msg[0] == write_msg.as_ref().unwrap().0 as u8 ||
                                                 (write_msg.as_ref().unwrap().0 == Msgs::Data && msg[0] == Msgs::Ready as u8)) {
                                                write_ready = true;
                                                write_msg = None;
                                            }
                                            match msg[0] {
                                                x if x == Msgs::Detect as u8 => {
                                                    if msg.len() >= 2 && msg[1] == 0x46 {
                                                        detected = true;
                                                    }
                                                },
                                                x if x == Msgs::FirmwareRev as u8 => {
                                                    if msg.len() >= 3 {
                                                        if msg[1] == 1 && msg[2] <= 10 {
                                                            needs_rssi_workaround = true;
                                                            log_line(&format!("RNode reports firmware rev of {}.{}, enabling RSSI workaround", msg[1], msg[2]), true);
                                                        } else {
                                                            log_line(&format!("RNode reports firmware rev of {}.{}", msg[1], msg[2]), true);
                                                        }
                                                    }
                                                },
                                                x if x == Msgs::NextRSSI as u8 => {
                                                    if msg.len() >= 2 {
                                                        if !needs_rssi_workaround || awaiting_real_rssi {
                                                            log_line(&format!("Received LORA packet with RSSI {} dBm", msg[1] as i16 - 292), true);
                                                        }
                                                        awaiting_real_rssi = false;
                                                    }
                                                },
                                                x if x == Msgs::Data as u8 => {
                                                    let msg_data = msg.split_off(1);
                                                    if needs_rssi_workaround {
                                                        if write_msg.is_none() {
                                                            write_msg = Some((Msgs::NextRSSI, vec![0xff]));
                                                        } else {
                                                            us.broadcast_msg_queue.lock().unwrap().push_front((Msgs::NextRSSI, vec![0xff]));
                                                        }
                                                        awaiting_real_rssi = true;
                                                    }
                                                    us.recv_msg_queue.lock().unwrap().push_back(msg_data);
                                                },
                                                x if x == Msgs::WidebandRSSI as u8 => {
                                                    provide_entropy(&msg[1..]);
                                                },
                                                x if x == Msgs::RadioState as u8 => {
                                                    if msg.len() >= 2 && msg[1] == 1 {
                                                        log_line("Successfully initialized LORA radio!", false);
                                                    }
                                                },
                                                x if x == Msgs::Error as u8 => {
                                                    if msg.len() >= 2 {
                                                        match msg[1] {
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
                                            msg = Vec::new();
                                        }
                                        in_msg = false;
                                        continue;
                                    } else {
                                        in_msg = true;
                                        msg.clear();
                                        continue;
                                    }
                                }
                                if msg_err { continue; }
                                if in_esc {
                                    if b == 0xdc { msg.push(Msgs::FEnd as u8); }
                                    else if b == 0xdd { msg.push(Msgs::Esc as u8); }
                                    else { msg_err = true; }
                                    in_esc = false
                                } else if b == Msgs::Esc as u8 {
                                    in_esc = true;
                                } else if msg.len() > 1000 {
                                    msg_err = true;
                                } else {
                                    msg.push(b);
                                }
                            }
                        }
                    }
                });
                THREAD_COUNT.fetch_sub(1, Ordering::AcqRel);
            });
            Some(ret)
        }
    }

    impl super::LoraDevice for RNodeDev {
        fn broadcast_msg(&self, msg: Vec<u8>) {
            let mut msgs = self.broadcast_msg_queue.lock().unwrap();
            if msgs.len() < 20 {
                log_line(&format!("Broadcasting LORA msg: {:x?}", &msg[..]), true);
                msgs.push_back((Msgs::Data, msg));
            } else {
                log_line("Dropping LORA message due to full queue!", false);
            }
        }
        fn recv_msg(&self) -> Option<Vec<u8>> {
            self.recv_msg_queue.lock().unwrap().pop_front()
        }
    }
}

fn build_header_data_packet(net_magic: &[u8; 4], index: BlockIndex, best_index: BlockIndex) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 1 + 4 + 4 + 80);
    data.extend_from_slice(net_magic);
    data.push(POST_NET_HDR_MAGIC);
    data.extend_from_slice(&u32_to_arr_be(index.height() as u32));
    data.extend_from_slice(&u32_to_arr_be(best_index.height() as u32));
    data.extend_from_slice(&index.header_bytes()[..]);
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
    log_line(&format!("Received LORA message with contents: {:x?}", &msg[..]), true);

    if msg.len() < 4 + 1 { return None; }

    if &msg[0..4] != net_magic { return None; }

    match msg[4] {
        POST_NET_HDR_MAGIC => {
            if msg.len() < 4 + 1 + 4 + 4 + 80 { return None; }

            let mut height: i32 = 0;
            height |= (msg[5] as i32) << 3*8;
            height |= (msg[6] as i32) << 2*8;
            height |= (msg[7] as i32) << 1*8;
            height |= (msg[8] as i32) << 0*8;
            if height < 0 { return None; }

            let mut tip_height: i32 = 0;
            tip_height |= (msg[9 ] as i32) << 3*8;
            tip_height |= (msg[10] as i32) << 2*8;
            tip_height |= (msg[11] as i32) << 1*8;
            tip_height |= (msg[12] as i32) << 0*8;
            if tip_height < height { return None; }

            let our_block_at_height = BlockIndex::get_from_height(height);
            // If we already have the same header as our current block at this height, don't both
            // processing (note that we process even if we have the header, but not as a part of our
            // best chain, in case we want to request more blocks towards their best chain).
            // XXX: This should be more robust.
            if our_block_at_height.is_none() ||
                    our_block_at_height.as_ref().unwrap().header_bytes()[..] != msg[13..] {
                match connect_headers_flat_bytes(&msg[13..]) {
                    Some(connected_hdr) => {
                        log_line(&format!("Connected header received over LORA, height {} (of their claimed tip {})", connected_hdr.height(), tip_height), false);
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

            let mut height: i32 = 0;
            height |= (msg[5] as i32) << 3*8;
            height |= (msg[6] as i32) << 2*8;
            height |= (msg[7] as i32) << 1*8;
            height |= (msg[8] as i32) << 0*8;
            if height < 0 { return None; }

            if let Some(index) = BlockIndex::get_from_height(height) {
                log_line(&format!("Responding to LORA request for header at height {}", index.height()), false);
                Some(build_header_data_packet(net_magic, index, BlockIndex::tip()))
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
            let (_, tx_data) = tx_reconstruction_cache[txid as usize].as_mut().unwrap();
            if tx_data.len() != start_pos as usize {
                *tx_data = Vec::with_capacity(data_bytes);
            }
            tx_data.extend_from_slice(&msg[8..]);
            for i in 0..256 {
                if let &Some((ref start, ref tx_data)) = &tx_reconstruction_cache[i] {
                    if *start > Instant::now() - Duration::from_secs(60) {
                        accept_to_memory_pool(&tx_data);
                        tx_reconstruction_cache[i] = None;
                    }
                }
            }
            None
        },
        _ => None
    }
}

#[no_mangle]
pub extern "C" fn init_lora_headers(proto_tty: *const c_char, msg_start_4_bytes: *const u8) -> bool {
    let proto_tty_str = match unsafe { CStr::from_ptr(proto_tty) }.to_str() {
        Ok(r) => r,
        Err(_) => return false,
    };
    let mut proto_tty_iter = proto_tty_str.splitn(4, ':');
    let center_freq_hz = match proto_tty_iter.next() {
        Some(x) if x.eq_ignore_ascii_case("na") => NA_CENTER_FREQ_HZ,
        Some(x) if x.eq_ignore_ascii_case("eu") => EU_CENTER_FREQ_HZ,
        _ => return false,
    };
    let coding_rate = match proto_tty_iter.next() {
        Some("1") => LoraCodeRate::FourOnFive,
        Some("2") => LoraCodeRate::FourOnSix,
        Some("3") => LoraCodeRate::FourOnSeven,
        Some("4") => LoraCodeRate::FourOnEight,
        _ => return false,
    };
    let proto = match proto_tty_iter.next() {
        Some(p) => p,
        None => return false,
    };
    let tty = match proto_tty_iter.next() {
        Some(t) => t,
        None => return false,
    };
    let mut net_magic: [u8; 4] = [0; 4];
    unsafe { ptr::copy(msg_start_4_bytes, (&mut net_magic).as_mut_ptr(), 4) };
    #[cfg(target_family = "unix")]
    {
        let tty_f = match fs::OpenOptions::new().read(true).write(true).open(tty) {
            Ok(f) => f,
            Err(_) => return false,
        };

        let dev = match proto {
            x if x.eq_ignore_ascii_case("rnode") => match rnode::RNodeDev::new(tty_f, center_freq_hz, coding_rate) {
                Some(dev) => dev,
                None => return false,
            },
            _ => return false,
        };

        std::thread::spawn(move || {
            THREAD_COUNT.fetch_add(1, Ordering::AcqRel);
            // Always catch panics so that even if we have some bug in our parser we don't take the
            // rest of Bitcoin Core down with us:
            let _ = catch_unwind(move || {
                //XXX: await_ibd_complete_or_stalled();

                let mut prev_tip = BlockIndex::tip();
                dev.broadcast_msg(build_header_data_packet(&net_magic, prev_tip, prev_tip));

                let mut last_historical_send = Instant::now();
                let mut last_historical_send_height = prev_tip.height();
                let mut this_hour = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() % 60;
                let mut responses_this_hour = 0;

                let max_resp_per_hour = match coding_rate {
                    LoraCodeRate::FourOnFive => 241,
                    LoraCodeRate::FourOnSix => 183,
                    LoraCodeRate::FourOnSeven => 139,
                    LoraCodeRate::FourOnEight => 105,
                };

                let mut txn_reconstruction_cache: [Option<(Instant, Vec<u8>)>; 256] = [None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None];

                while unsafe { !rusty_ShutdownRequested() } {
                    let new_tip = BlockIndex::tip();
                    if prev_tip != new_tip {
                        dev.broadcast_msg(build_header_data_packet(&net_magic, new_tip, new_tip));
                        prev_tip = new_tip;
                    }
                    // A message from 89 - 93 bytes with an explicit header uses 93, 110, 127, or
                    // 144 symbols at SF11 / 250 kHz, depending on the coding rate, taking 862.2+,
                    // 1001.4+, 1140.7+ or 1280 ms to send.
                    // For EU 869.4 - 869.65 MHz band the duty cycle limit is 10%.
                    // Thus, we should never send more than 10020, 8627, 7574, or 6750 frames/day.
                    // * We budget 192 (8 blocks/hour) frames for current block broadcasting.
                    // * We budget 4032 frames for sending the last four weeks' blocks (once a day)
                    //   which translates to one historical block every ~21.429 seconds.
                    // * Leaving 5796, 4403, 3350, or 2526 frames per day for responding to requests
                    //   or sending transaction data which translates to responding to 241, 183,
                    //   139, or 105 requests per hour.
                    // In the US, no such restriction exists, so we disable the response limits.
                    if let Some(msg) = dev.recv_msg() {
                        if let Some(resp) = process_msg(&msg, &net_magic, &mut txn_reconstruction_cache) {
                            let cur_hour = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() % 60;
                            if this_hour != cur_hour {
                                responses_this_hour = 0;
                                this_hour = cur_hour
                            }
                            if center_freq_hz != EU_CENTER_FREQ_HZ || responses_this_hour < max_resp_per_hour {
                                responses_this_hour += 1;
                                dev.broadcast_msg(resp);
                            }
                        }
                    }
                    if last_historical_send < Instant::now() - Duration::from_millis(21_429) {
                        if last_historical_send_height >= new_tip.height() {
                            last_historical_send_height = cmp::max(0, new_tip.height() - 6*24*7*4);
                        } else {
                            last_historical_send_height += 1;
                        }
                        if let Some(index) = BlockIndex::get_from_height(last_historical_send_height) {
                            dev.broadcast_msg(build_header_data_packet(&net_magic, index, new_tip));
                        }
                        last_historical_send = Instant::now();
                    }
                    std::thread::sleep(Duration::from_millis(100));
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
}

#[no_mangle]
pub extern "C" fn stop_lora_headers() {
    while THREAD_COUNT.load(Ordering::Acquire) != 0 {
        std::thread::sleep(Duration::from_millis(10));
    }
}
