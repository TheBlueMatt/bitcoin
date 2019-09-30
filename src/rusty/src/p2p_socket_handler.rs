use std::collections::LinkedList;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use std::net::SocketAddr;
use std::io::{Cursor, Read, Write};

use crate::bridge::*;
use crate::p2p_addrs::*;

use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::consensus::encode::CheckedData;
use bitcoin::network::message::{CommandString, RawNetworkMessage, NetworkMessage};

use mio::{Events, Poll, Interests, Token, Waker};
use mio::net::TcpStream;

#[inline]
pub fn slice_to_u32_le(slice: &[u8]) -> u32 {
    assert_eq!(slice.len(), 4);
    (slice[0] as u32) << 0*8 |
    (slice[1] as u32) << 1*8 |
    (slice[2] as u32) << 2*8 |
    (slice[3] as u32) << 3*8
}

pub enum NetMsg {
    Msg(NetworkMessage),
    /// Since we just hand blocks over the wall to C++ for deserialization anyway, we don't bother
    /// to deserialize-reserialize-deserialize blocks and just put them, in full form, in a Vec.
    SerializedBlock(Vec<u8>),
    /// Indicates either the socket should be closed (if sent outbound) or that the socket has been
    /// closed (if received inbound)
    EOF,
}

/// state that gets wrapped in an Arc to pass incoming and outgoing messages into/out of the socket
/// handling thread.
pub struct MessageQueues {
    pub inbound: Mutex<LinkedList<NetMsg>>,
    pub outbound: Mutex<LinkedList<NetMsg>>,
}

const MSG_HDR_LEN: usize = 4 + 12 + 4 + 4;
/// Max number of messages to hold in the message queue, minus one
const MAX_QUEUE_LEN: usize = 2;

/// socket-handler-thread-specific data about a given peer (buffers and the socket itself).
struct SocketData {
    sock: TcpStream,
    read_len: usize,
    read_buff: Vec<u8>,
    write_pos: usize,
    write_buff: Vec<u8>,
    queues: Arc<MessageQueues>,
}

/// Reads from the given socket, deserializing messages into the inbound queue, and potentially
/// pausing read if the queue grows too large.
/// Returns true if the peer should be (or has been) disconnected!
fn sock_read(sock_state: &mut SocketData, msg_wake_condvar: &Condvar, msg_wake_mutex: &Mutex<()>) -> bool {
    loop { // Read until we have too many pending messages or we get Err(WouldBlock)
        if sock_state.read_len == 0 {
            // We've paused reading, and probably shouldn't have gotten here, but we may have hit
            // some kind of spurious wake, so just return false and move on.
            return false;
        }
        // We should never be asked to read if we already have a buffer of the next-read size:
        assert!(sock_state.read_buff.len() < sock_state.read_len);
        let read_pos = sock_state.read_buff.len();
        sock_state.read_buff.resize(sock_state.read_len, 0u8);
        match sock_state.sock.read(&mut sock_state.read_buff[read_pos..]) {
            Ok(0) => {
                // EOF - we've been disconnected
                return true;
            },
            Ok(read_len) => {
                assert!(read_pos + read_len <= sock_state.read_buff.len());
                if read_pos + read_len == sock_state.read_buff.len() {
                    macro_rules! process_msg { () => { {
                        macro_rules! push_msg { ($msg: expr) => { {
                            if {
                                // Push the new message onto the queue, passing whether to
                                // pause read into the if without holding the lock.
                                let mut inbounds = sock_state.queues.inbound.lock().unwrap();
                                inbounds.push_back($msg);
                                inbounds.len() >= MAX_QUEUE_LEN
                            } || sock_state.queues.outbound.lock().unwrap().len() >= MAX_QUEUE_LEN {
                                // Drop the buffer and pause reading...
                                sock_state.read_buff.clear();
                                sock_state.read_buff.shrink_to_fit();
                                sock_state.read_len = 0;
                                return false;
                            } else {
                                // Re-capacity the buffer to 8KB and resize to 0
                                sock_state.read_buff.resize(8 * 1024, 0u8);
                                sock_state.read_buff.shrink_to_fit();
                                sock_state.read_buff.clear();
                                sock_state.read_len = MSG_HDR_LEN;
                            }
                            {
                                // All we need to do is ensure that the message-handling thread
                                // will check for available messages after we've pushed a message
                                // or go to sleep before we call notify_one(), below. If we just
                                // lock the msg_wake_mutex here, we ensure that either it has
                                // slept, or it has yet to check for available messages when we
                                // exit this block. Thus, we should be good!
                                //
                                // Note that we very much deliberately do not take this lock at the
                                // same time as any of the queue locks, thus leaving any lock
                                // ordering guarantees up to the message-handling thread.
                                let _ = msg_wake_mutex.lock().unwrap();
                            }
                            msg_wake_condvar.notify_one();
                        } } }

                        match u32::consensus_decode(&sock_state.read_buff[..]) {
                            Ok(res) if res == bitcoin::Network::Bitcoin.magic() => {},
                            _ => return true,
                        }
                        // First deserialize the command. If it is a block, don't deserialize to a
                        // Rust-Bitcoin block (only to reserialize it and hand it to C++), but instead
                        // just check the checksum and hand it over the wall. Otherwise, call Rust-Bitcoin's
                        // deserialize routine for general network messages.
                        match CommandString::consensus_decode(&sock_state.read_buff[4..]) {
                            Ok(CommandString(ref cmd)) if cmd == "block" => {
                                match CheckedData::consensus_decode(&sock_state.read_buff[4 + 12..]) {
                                    Ok(res) => push_msg!(NetMsg::SerializedBlock(res.0)),
                                    Err(_) => return true,
                                }
                            },
                            Ok(_) => match RawNetworkMessage::consensus_decode(&sock_state.read_buff[..]) {
                                Ok(res) => push_msg!(NetMsg::Msg(res.payload)),
                                Err(bitcoin::consensus::encode::Error::UnrecognizedNetworkCommand(_)) => {
                                    // Re-capacity the buffer to 8KB and resize to 0
                                    sock_state.read_buff.resize(8 * 1024, 0u8);
                                    sock_state.read_buff.shrink_to_fit();
                                    sock_state.read_buff.clear();
                                    sock_state.read_len = MSG_HDR_LEN;
                                },
                                Err(_) => return true,
                            },
                            Err(_) => return true,
                        }
                    } } }

                    // If we're currently reading the header, deserialize the payload length then continue
                    // the read loop. If the payload happens to be zero-length, process the message too.
                    if sock_state.read_len == MSG_HDR_LEN {
                        let payload_len = slice_to_u32_le(&sock_state.read_buff[4 + 12..4 + 12 + 4]);
                        if payload_len as usize > bitcoin::consensus::encode::MAX_VEC_SIZE {
                            return true;
                        }
                        if payload_len == 0 {
                            process_msg!();
                        } else {
                            sock_state.read_len = MSG_HDR_LEN + payload_len as usize;
                        }
                    } else {
                        process_msg!();
                    }
                } else {
                    // Drop the size of the read_buff to how much we've
                    // read. Shouldn't ever result in a realloc (nor
                    // should reading later, since capacity doesn't
                    // change).
                    sock_state.read_buff.resize(read_pos + read_len, 0u8);
                }
            },
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                sock_state.read_buff.resize(read_pos, 0u8);
                return false
            },
            Err(_) => return true,
        }
    }
}

/// Writes to the given socket, taking messages from the outbound queue as necessary.
/// Does *not* automatically unpause read if we've sufficiently drained the outbound queue.
/// Returns true if the peer should be disconnected!
fn sock_write(sock_state: &mut SocketData) -> bool {
    loop { // Write until we get Err(WouldBlock)
        if sock_state.write_pos >= sock_state.write_buff.len() { // ie incl sock_state.write_buff.is_empty()
            let next_out_msg = sock_state.queues.outbound.lock().unwrap().pop_front();
            if let Some(write_msg) = next_out_msg {
                match write_msg {
                    NetMsg::Msg(msg) => {
                        let mut write_buff = Vec::new();
                        std::mem::swap(&mut write_buff, &mut sock_state.write_buff);
                        let mut cursor = Cursor::new(write_buff);
                        RawNetworkMessage {
                            magic: bitcoin::Network::Bitcoin.magic(),
                            payload: msg,
                        }.consensus_encode(&mut cursor).expect("Should only get I/O errors, which Cursor won't generate");
                        std::mem::swap(&mut cursor.into_inner(), &mut sock_state.write_buff);
                        sock_state.write_pos = 0;
                    },
                    NetMsg::SerializedBlock(block) => {
                        let mut write_buff = Vec::new();
                        std::mem::swap(&mut write_buff, &mut sock_state.write_buff);
                        let mut cursor = Cursor::new(write_buff);
                        bitcoin::Network::Bitcoin.magic().consensus_encode(&mut cursor).unwrap();
                        CommandString("block".to_string()).consensus_encode(&mut cursor).unwrap();
                        CheckedData(block).consensus_encode(&mut cursor).unwrap();
                        std::mem::swap(&mut cursor.into_inner(), &mut sock_state.write_buff);
                        sock_state.write_pos = 0;
                    },
                    NetMsg::EOF => { return true; },
                }
            } else { return false; }
        }
        match sock_state.sock.write(&mut sock_state.write_buff[sock_state.write_pos..]) {
            Ok(0) => { panic!(); }, //XXX: No, but need to figure out if this means EOF or WouldBlock!
            Ok(writelen) => {
                assert!(writelen <= sock_state.write_buff.len() - sock_state.write_pos);
                sock_state.write_pos += writelen;
                if sock_state.write_pos == sock_state.write_buff.len() {
                    // Re-capacity the buffer to 8KB and resize to 0
                    sock_state.write_buff.resize(8 * 1024, 0u8);
                    sock_state.write_buff.shrink_to_fit();
                    sock_state.write_buff.clear();
                }
            },
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => return false,
            Err(_) => return true,
        }
    }
}

pub fn spawn_socket_handler(thread_count_tracker: &'static AtomicUsize, msg_wake_arg: Arc<Condvar>, msg_wake_mutex: Arc<Mutex<()>>, pending_peers: Arc<Mutex<Vec<(Arc<MessageQueues>, NetAddress)>>>) -> Waker {
    let mut poll = Poll::new().unwrap();
    let waker = Waker::new(poll.registry(), Token(std::usize::MAX)).unwrap();

    std::thread::spawn(move || {
        // Always catch panics so that even if we have some bug in our parser we don't take the
        // rest of Bitcoin Core down with us:
        thread_count_tracker.fetch_add(1, Ordering::AcqRel);
        //XXX: WTF DOES THIS MEAN:
        let msg_wake_condvar = AssertUnwindSafe(msg_wake_arg);
        let _ = catch_unwind(move || {
            let mut socket_data: Vec<Option<SocketData>> = Vec::new();
            let mut events = Events::with_capacity(1024);

            while unsafe { !rusty_ShutdownRequested() } {
                if let Err(_) = poll.poll(&mut events, Some(Duration::from_millis(100))) {
                    std::thread::sleep(Duration::from_millis(100));
                } else {
                    for event in &events {
                        if event.token().0 > socket_data.len() ||
                            socket_data[event.token().0].is_none() { continue; }
                        let sock_state = socket_data[event.token().0].as_mut().unwrap();

                        if event.is_readable() {
                            if sock_read(sock_state, &msg_wake_condvar, &msg_wake_mutex) {
                                //TODO: do we need to call deregister before drop?
                                sock_state.queues.inbound.lock().unwrap().push_back(NetMsg::EOF);
                                socket_data[event.token().0] = None;
                                continue;
                            }
                        }

                        if event.is_writable() {
                            if sock_write(sock_state) {
                                //TODO: do we need to call deregister before drop?
                                sock_state.queues.inbound.lock().unwrap().push_back(NetMsg::EOF);
                                socket_data[event.token().0] = None;
                                continue;
                            }
                        }
                    }
                }

                for data in socket_data.iter_mut() {
                    if let Some(sock_state) = data {
                        if sock_write(sock_state) {
                            sock_state.queues.inbound.lock().unwrap().push_back(NetMsg::EOF);
                            *data = None;
                            continue;
                        }
                        // If we paused reading for this peer (read_len == 0) and the inbound+outbound
                        // message queues have room again, unpause reading. Because we use
                        // edge-triggered events we must then read from the peer's socket until we
                        // either fill the queue again or get a WouldBlock.
                        if sock_state.read_len == 0 && sock_state.queues.inbound.lock().unwrap().len() < MAX_QUEUE_LEN &&
                            sock_state.queues.outbound.lock().unwrap().len() < MAX_QUEUE_LEN {
                            sock_state.read_len = MSG_HDR_LEN;
                            if sock_read(sock_state, &msg_wake_condvar, &msg_wake_mutex) {
                                //TODO: do we need to call deregister before drop?
                                sock_state.queues.inbound.lock().unwrap().push_back(NetMsg::EOF);
                                *data = None;
                                continue;
                            }
                        }
                    }
                }

                // Check if we've been asked to open new connections...
                'connect_loop: for (queues, addr) in pending_peers.lock().unwrap().drain(..) {
                    match match addr {
                        NetAddress::IPv4(a) => TcpStream::connect(SocketAddr::V4(a)).ok(),
                        NetAddress::IPv6(a) => TcpStream::connect(SocketAddr::V6(a)).ok(),
                        _ => None,
                    } {
                        Some(sock) => {
                            macro_rules! insert {
                                ($idx: expr, $data: expr) => { {
                                    poll.registry().register(&sock, Token($idx), Interests::READABLE | Interests::WRITABLE).unwrap();
                                    $data = Some(SocketData {
                                        sock,
                                        queues,
                                        read_len: MSG_HDR_LEN,
                                        read_buff: Vec::new(),
                                        write_pos: 0,
                                        write_buff: Vec::new(),
                                    });
                                    continue 'connect_loop;
                                } }
                            }
                            for (idx, data) in socket_data.iter_mut().enumerate() {
                                if data.is_none() {
                                    insert!(idx, *data);
                                }
                            }
                            let idx = socket_data.len();
                            socket_data.push(None);
                            insert!(idx, socket_data[idx]);
                        }
                        None => {},
                    }
                }
            }
        });
        thread_count_tracker.fetch_sub(1, Ordering::AcqRel);
    });
    waker
}
