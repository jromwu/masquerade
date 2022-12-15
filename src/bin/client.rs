// Copyright (C) 2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/*
* Modified from cloudflare/quiche example client
*/

use log::*;

use mio::Token;
use mio::net::{UdpSocket, TcpStream, TcpListener};
use quiche;
use quiche::h3::{NameValue, Header};
use ring::rand::*;
use url::Url;

use std::io::{Read, Write};
use std::net::{ToSocketAddrs, SocketAddr};
use std::collections::{HashMap, VecDeque};

const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(PartialEq, Clone, Copy)]
enum ConnectStreamState {
    RequestNotSent,
    RequestSent,
    ConnectionEstablished,
}

#[derive(PartialEq)]
enum EventType {
    Headers {
        list: Vec<Header>,
    },
    Data,
    Datagram,
    Finished,
}

pub struct ToSend {
    stream_id: u64, // or flow_id for DATAGRAM
    send_type: EventType,
    data: Vec<u8>,
}

pub struct Received {
    receive_type: EventType,
    data: Vec<u8>,
}


struct ConnectStream<S> {
    stream_id: Option<u64>,
    state: S,
    socket: TcpStream,
    socket_read_queue: VecDeque<Received>,
    socket_write_queue: VecDeque<Vec<u8>>,
    h3_read_queue: VecDeque<Received>,
}

struct Client<F, S> where F: FnMut(&mut ConnectStream<S>, &mut VecDeque<ToSend>) -> bool {
    conn: quiche::Connection,
    h3_conn: Option<quiche::h3::Connection>,
    socket: UdpSocket,
    poll: mio::Poll,
    streams: HashMap<Token, ConnectStream<S>>, // TODO: change struct to allow tcp stream without stream_id
    handlers: HashMap<Token, F>,
    stream_to_token: HashMap<u64, Token>,
    // token_to_stream: BiMap<Token, u64>,
    write_queue: VecDeque<ToSend>,
    current_token: Token,
}

const QUIC_TOKEN: Token = Token(0);

impl<F, S> Client<F, S> where F: FnMut(&mut ConnectStream<S>, &mut VecDeque<ToSend>) -> bool {
    pub fn new(url: Url) -> Client<F, S> {
        let (conn, poll, socket) = Self::initiate_connection(url);
        return Client {
            conn,
            h3_conn: None,
            socket,
            poll,
            streams: HashMap::new(),
            handlers: HashMap::new(),
            stream_to_token: HashMap::new(),
            write_queue: VecDeque::new(),
            current_token: Token(QUIC_TOKEN.0 + 1),
        }
    }

    pub fn add_socket(&mut self, token: Token, mut socket: TcpStream, state: S, handler: F) {
        self.handlers.insert(token, handler);
        let token = self.next_token();
        self.poll.registry().register(&mut socket, token, mio::Interest::READABLE | mio::Interest::WRITABLE);
        self.streams.insert(token, ConnectStream {
            stream_id: None,
            state,
            socket,
            socket_read_queue: VecDeque::new(),
            socket_write_queue: VecDeque::new(),
            h3_read_queue: VecDeque::new(),
        });
    }
    
    pub fn add_stream(&mut self, token: Token, stream_id: u64) {
        self.stream_to_token.insert(stream_id, token);
        self.streams.get_mut(&token).unwrap().stream_id = Some(stream_id);
    }

    pub fn next_token(&mut self) -> Token {
        let next = self.current_token.0;
        self.current_token.0 += 1;
        Token(next)
    }

    fn initiate_connection(url: Url) -> (quiche::Connection, mio::Poll, UdpSocket) {
        let mut out = [0; MAX_DATAGRAM_SIZE];

        let mut poll = mio::Poll::new().unwrap();

        let peer_addr = url.to_socket_addrs().unwrap().next().unwrap(); // Resolve server address.
        let bind_addr = match peer_addr {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };

        let mut socket =
            mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
        poll.registry()
            .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
            .unwrap();
        
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        // TODO: *CAUTION*: this should not be set to `false` in production!!!
        config.verify_peer(false);
    
        config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL).unwrap();
        
        config.set_max_idle_timeout(10000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);

        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        let rng = SystemRandom::new();
        rng.fill(&mut scid[..]).unwrap();
        let scid = quiche::ConnectionId::from_ref(&scid);
        
        // Client connection.
        let local_addr = socket.local_addr().unwrap();
        let mut conn = quiche::connect(url.domain(), &scid, local_addr, peer_addr, &mut config).expect("quic connection failed");
        info!(
            "connecting to {:} from {:} with scid {}",
            peer_addr,
            socket.local_addr().unwrap(),
            hex_dump(&scid)
        );

        let (write, send_info) = conn.send(&mut out).expect("initial send failed"); 
        while let Err(e) = socket.send_to(&out[..write], send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                debug!("send() would block");
                continue;
            }
    
            panic!("send() failed: {:?}", e);
        }
        debug!("written {}", write);

        return (conn, poll, socket);
    }

    /*
     * final_events_handler to handle anything else that a stream can manage, e.g. handle server listening TCP socket, manage streams
     */
    pub fn run<G>(&mut self, mut final_events_handler: G) where G: FnMut(&mut Client<F, S>, &mio::Events) -> () {
        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];

        let mut events = mio::Events::with_capacity(1024);
        let timeout = self.conn.timeout();

        loop {
            self.poll.poll(&mut events, timeout).unwrap();

            self.process_quic_read(&events, &mut buf, &mut out);

            if self.conn.is_closed() {
                info!("connection closed, {:?}", self.conn.stats());
                break;
            }    
            
            // Create a new HTTP/3 connection once the QUIC connection is established.
            if self.conn.is_established() && self.h3_conn.is_none() {
                let h3_config = quiche::h3::Config::new().unwrap();
                self.h3_conn = Some(
                    quiche::h3::Connection::with_transport(&mut self.conn, &h3_config)
                    .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
                );
            }

            self.process_socket_read(&events, &mut buf, &mut out);
            self.handle_sockets();
            self.process_h3_read(&mut buf);
            self.process_h3_write();
            self.process_socket_write(&events, &mut buf, &mut out);
            self.process_quic_write(&mut buf, &mut out);

            final_events_handler(self, &events);
        }
    }

    fn handle_sockets(&mut self) {
        let mut to_remove = Vec::new();
        for (token, connect_stream) in self.streams.iter_mut() {
            let handler = self.handlers.get_mut(&token).unwrap();
            let finished = handler(connect_stream, &mut self.write_queue);
            if finished {
                to_remove.push(token.clone());
            }
        }
        for token in to_remove.iter() {
            self.remove_stream(token);
        };
    }

    fn remove_stream(&mut self, token: &Token) {
        let stream = self.streams.get(token).unwrap();
        stream.socket.shutdown(std::net::Shutdown::Both);
        if let Some(stream_id) = stream.stream_id {
            self.conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0);
            self.stream_to_token.remove(&stream_id);
        }
        self.streams.remove(token);
        self.handlers.remove(token);
    }


    fn process_socket_read(&mut self, events: &mio::Events, buf: &mut [u8], out: &mut [u8]) {
        for event in events.iter() {
            trace!("Poll event on token {}", event.token().0);
            match event.token() {
                QUIC_TOKEN => {} // ignore it
                token => {
                    if event.is_readable() {
                        trace!("read event on token {} for TCP", token.0);
                        let connect_stream = self.streams.get_mut(&token).unwrap();
                    
                        let mut received_data = vec![0; 4096];
                        let mut bytes_read = 0;

                        let mut connection_closed = false;
                        // We can (maybe) read from the connection.
                        loop {
                            match connect_stream.socket.read(&mut received_data[bytes_read..]) {
                                Ok(0) => {
                                    // Reading 0 bytes means the other side has closed the
                                    // connection or is done writing, then so are we.
                                    debug!("Received 0 bytes from TCP, token {}", token.0);
                                    connection_closed = true;
                                    break;
                                }
                                Ok(n) => {
                                    bytes_read += n;
                                    if bytes_read == received_data.len() {
                                        received_data.resize(received_data.len() + 1024, 0);
                                    }
                                    debug!("Received {} bytes from TCP, token {}", n, token.0);
                                }
                                // Would block "errors" are the OS's way of saying that the
                                // connection is not actually ready to perform this I/O operation.
                                Err(ref err) if would_block(err) => break,
                                Err(ref err) if interrupted(err) => continue,
                                Err(err) => {
                                    // Other errors we'll consider fatal.
                                    error!("Error in reading TCP connection {}", err);
                                    connection_closed = true;
                                    break;
                                },
                            }
                        }
                
                        if bytes_read != 0 {
                            let received_data = &received_data[..bytes_read];
                            connect_stream.socket_read_queue.push_back(Received {
                                receive_type: EventType::Data,
                                data: received_data.to_vec(),
                            });
                            debug!("Received {} bytes, token {}", bytes_read, token.0);
                            trace!("{}", unsafe {
                                std::str::from_utf8_unchecked(received_data)
                            });
                        }
                    
                        if connection_closed {
                            debug!("Connection closed on token {}", token.0);
                            connect_stream.socket_read_queue.push_back(Received {
                                receive_type: EventType::Finished,
                                data: vec!(),
                            });
                        }
                    }
                }
            }
        }
    }

    fn process_socket_write(&mut self, events: &mio::Events, buf: &mut [u8], out: &mut [u8]) {
        for event in events.iter() {
            trace!("Poll event on token {}", event.token().0);
            match event.token() {
                QUIC_TOKEN => {} // ignore it
                token => {
                    if event.is_writable() {
                        trace!("write event on token {} for TCP", token.0);
                        let connect_stream = self.streams.get_mut(&token).unwrap();

                        while let Some(data) = connect_stream.socket_write_queue.front() {
                            trace!("writing to TCP connection");
                            trace!("{}", unsafe {
                                std::str::from_utf8_unchecked(data)
                            });
                            match connect_stream.socket.write(data) {
                                // We want to write the entire `DATA` buffer in a single go. If we
                                // write less we'll return a short write error (same as
                                // `io::Write::write_all` does).
                                Ok(n) => {
                                    debug!("Sent {} bytes to {}", n, connect_stream.socket.peer_addr().unwrap());
                                    let data = connect_stream.socket_write_queue.pop_front().unwrap();
                                    if n < data.len() {
                                        // short write, try remaining again
                                        connect_stream.socket_write_queue.push_front(data[n..].to_vec());
                                    }
                                },
                                // Would block "errors" are the OS's way of saying that the
                                // connection is not actually ready to perform this I/O operation.
                                Err(ref err) if would_block(err) => {
                                    debug!("write() would block");
                                    break;
                                }
                                // Got interrupted (how rude!), we'll try again.
                                Err(ref err) if interrupted(err) => { 
                                    debug!("write() interupted");
                                    continue;
                                }
                                // Other errors we'll consider fatal.
                                Err(err) => {
                                    error!("Error in writing TCP connection {}", err);
                                    self.remove_stream(&token);
                                    break;
                                }
                            }

                            // re-register to get the next writable event again
                            self.poll.registry().reregister(&mut connect_stream.socket, token, mio::Interest::READABLE | mio::Interest::WRITABLE);
                        } 
                    }
                }
            }
        }
    }

    fn process_quic_read(&mut self, events: &mio::Events, buf: &mut [u8], out: &mut [u8]) {
        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                debug!("socket timed out");
                self.conn.on_timeout();
                break 'read;
            }


            let (len, from) = match self.socket.recv_from(buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            debug!("got {} bytes", len);

            let local_addr = self.socket.local_addr().unwrap();
            let recv_info = quiche::RecvInfo {
                to: local_addr,
                from,
            };

            // Process potentially coalesced packets.
            let read = match self.conn.recv(&mut buf[..len], recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("recv failed: {:?}", e);
                    continue 'read;
                },
            };

            debug!("processed {} bytes", read);
        }

        debug!("done reading");
    }

    fn process_h3_read(&mut self, buf: &mut [u8]) {
        if let Some(h3_conn) = &mut self.h3_conn {
            // Process HTTP/3 events.
            loop {
                match h3_conn.poll(&mut self.conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        info!("got response headers {:?} on stream id {}", hdrs_to_strings(&list), stream_id);
                        let token = self.stream_to_token.get(&stream_id).unwrap();
                        let connect_stream = self.streams.get_mut(&token).unwrap();
                        connect_stream.h3_read_queue.push_back(Received { 
                            receive_type: EventType::Headers { list }, 
                            data: vec![], 
                        });
                    },

                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        let token = self.stream_to_token.get(&stream_id).unwrap();
                        let connect_stream = self.streams.get_mut(&token).unwrap();
                        while let Ok(read) = h3_conn.recv_body(&mut self.conn, stream_id, buf) {
                            debug!("got {} bytes of response data on stream {}", read, stream_id);
                            trace!("{}", unsafe {std::str::from_utf8_unchecked(&buf[..read])});
                            connect_stream.h3_read_queue.push_back(Received {
                                receive_type: EventType::Data,
                                data: buf[..read].to_vec(),
                            });
                        }
                    },

                    Ok((stream_id, quiche::h3::Event::Finished)) => {
                        info!("finished received, stream id: {} closing", stream_id);
                        let token = self.stream_to_token.get(&stream_id).unwrap();
                        let connect_stream = self.streams.get_mut(&token).unwrap();
                        connect_stream.h3_read_queue.push_back(Received {
                            receive_type: EventType::Finished,
                            data: vec![],
                        });
                    },

                    Ok((stream_id, quiche::h3::Event::Reset(e))) => {
                        error!("request was reset by peer with {}, stream id: {} closed", e, stream_id);
                        let token = self.stream_to_token.get(&stream_id).unwrap();
                        let connect_stream = self.streams.get_mut(&token).unwrap();
                        connect_stream.h3_read_queue.push_back(Received {
                            receive_type: EventType::Finished,
                            data: vec![],
                        });
                    },

                    Ok((_flow_id, quiche::h3::Event::Datagram)) => todo!(),

                    Ok((_, quiche::h3::Event::PriorityUpdate)) => unreachable!(),

                    Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                        info!("GOAWAY id={}", goaway_id);
                    },

                    Err(quiche::h3::Error::Done) => {
                        break;
                    },

                    Err(e) => {
                        error!("HTTP/3 processing failed: {:?}", e);

                        break;
                    },
                }
            }
        }
    }

    fn process_h3_write(&mut self) {
        if let Some(h3_conn) = &mut self.h3_conn {
            let mut tokens_to_remove = Vec::new();
            while let Some(to_send) = self.write_queue.pop_front() {
                match to_send.send_type {
                    EventType::Headers { .. } => todo!(), // h3_conn.send_request(&mut self.conn, &list, false), // TODO: this might need to be handled by individual streams to get the stream_id
                    EventType::Data => {
                        debug!("stream {} sending {} byte of data", to_send.stream_id, to_send.data.len());
                        if let Ok(str_buf) = std::str::from_utf8(&to_send.data) {
                            trace!("{}", str_buf);
                        } else {
                            trace!("non-utf: {:?}", to_send.data);
                        }

                        let written = match h3_conn.send_body(&mut self.conn, to_send.stream_id, &to_send.data, false) {
                            Ok(v) => v,
            
                            Err(quiche::h3::Error::Done) => 0, 
                    
                            Err(e) => {
                                error!("stream {} send data failed {:?}", to_send.stream_id, e);
                                tokens_to_remove.push(self.stream_to_token.get(&to_send.stream_id).unwrap().clone());

                                continue;
                            },
                        };
                        if written < to_send.data.len() {
                            error!("stream {} partially written data {} bytes of {} bytes", to_send.stream_id, written, to_send.data.len());
                            if written == 0 {
                                self.write_queue.push_front(to_send); // TODO: we may want to push to the end of the queue instead, but maybe that will mess up with the packet order
                            } else {
                                self.write_queue.push_front(ToSend {
                                    send_type: to_send.send_type,
                                    stream_id: to_send.stream_id,
                                    data: to_send.data[written..].to_vec(),
                                });
                            }
                        }
                    },
                    EventType::Datagram => {
                        match h3_conn.send_dgram(&mut self.conn, to_send.stream_id, &to_send.data) {
                            Ok(_) => {},
                            Err(e) => {
                                error!("stream {} send datagram failed {:?}", to_send.stream_id, e);
                            }
                        }
                    },
                    EventType::Finished => {
                        unreachable!();
                        // debug!("stream {} finishing", to_send.stream_id);
                        // self.remove_stream(self.stream_to_token.get(&to_send.stream_id).unwrap());
                    },
                }
            }
            for token in tokens_to_remove {
                self.remove_stream(&token);
            }
        }
    }

    fn process_quic_write(&mut self, buf: &mut [u8], out: &mut [u8]) {
        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        loop {
            let (write, send_info) = match self.conn.send(out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("done writing");
                    break;
                },

                Err(e) => {
                    error!("send failed: {:?}", e);

                    self.conn.close(false, 0x1, b"fail").ok();
                    break;
                },
            };

            if let Err(e) = self.socket.send_to(&out[..write], send_info.to) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!("send() would block");
                    break;
                }

                panic!("send() failed: {:?}", e);
            }

            debug!("written {}", write);
        }
    }
}



fn main() {
    env_logger::init();

    // let server_name = "https://cloudflare-quic.com/";
    let server_name = "https://127.0.0.1:4433/";
    let bind_addr = "127.0.0.1:8899";

    let url = url::Url::parse(&server_name).unwrap();

    let mut client = Client::new(url);

    let mut listener = TcpListener::bind(bind_addr.parse().unwrap()).expect("TCP listener bind failed");
    let listener_token = client.next_token();
    
    client.poll.registry().register(&mut listener, listener_token, mio::Interest::READABLE);

    client.run(move |client, events| {
        for event in events {
            if event.token() == listener_token {
                loop {
                    match listener.accept() {
                        Ok((socket, _socket_addr)) => {
                            debug!("accepted TCP connection from {}", _socket_addr);
                            let mut state = ConnectStreamState::RequestNotSent;
                            let token = client.next_token();
                            client.add_socket(token, socket, ConnectStreamState::RequestNotSent, move |stream, to_sends| {
                                let mut new_state = state;
                                let mut finished = false;
                                match state {
                                    ConnectStreamState::RequestNotSent => {}, // wait for final_events_handler to check

                                    ConnectStreamState::RequestSent => {
                                        while let Some(received) = stream.h3_read_queue.pop_front() {
                                            match received.receive_type {
                                                EventType::Headers { list } => {
                                                    info!("Got response {:?} on token id {}", hdrs_to_strings(&list), token.0);
                                                    let mut status = None;
                                                    for hdr in list {
                                                        match hdr.name() {
                                                            b":status" => status = Some(hdr.value().to_owned()),
                                                            _ => (),
                                                        }
                                                    }
                                                    if let Some(status) = status {
                                                        if let Ok(status_str) = std::str::from_utf8(&status) {
                                                            if let Ok(status_code) = status_str.parse::<i32>() {
                                                                if status_code >= 200 && status_code < 300 {
                                                                    new_state = ConnectStreamState::ConnectionEstablished;
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                    }
                                                    error!("HTTP3 CONNECT failed on token {}", token.0);
                                                    finished = true;
                                                    break;
                                                },
                                                EventType::Data => unreachable!(),
                                                EventType::Datagram => todo!(),
                                                EventType::Finished => {
                                                    finished = true;
                                                    break;
                                                },
                                            }
                                        }
                                    },

                                    ConnectStreamState::ConnectionEstablished => {
                                        while let Some(received) = stream.h3_read_queue.pop_front() {
                                            match received.receive_type {
                                                EventType::Headers { list } => unreachable!(),
                                                EventType::Data => {
                                                    info!("Got data {} bytes of HTTP3 data on token id {}", received.data.len(), token.0);
                                                    trace!("{}", unsafe {std::str::from_utf8_unchecked(&received.data)});
                                                    stream.socket_write_queue.push_back(received.data);
                                                },
                                                EventType::Datagram => todo!(),
                                                EventType::Finished => {
                                                    finished = true;
                                                    break;
                                                },
                                            }
                                        }
                                        while let Some(received) = stream.socket_read_queue.pop_front() {
                                            match received.receive_type {
                                                EventType::Headers { list } => unreachable!(),
                                                EventType::Data => {
                                                    info!("Got data {} bytes of TCP data on token id {}", received.data.len(), token.0);
                                                    trace!("{}", unsafe {std::str::from_utf8_unchecked(&received.data)});
                                                    to_sends.push_back(ToSend { stream_id: stream.stream_id.unwrap(), send_type: EventType::Data, data: received.data });
                                                },
                                                EventType::Datagram => todo!(),
                                                EventType::Finished => {
                                                    finished = true;
                                                    break;
                                                },
                                            }
                                        }
                                    }
                                };
                                state = new_state;
                                finished
                            });
                        },

                        Err(ref err) if would_block(err) => {
                            debug!("accept() would block");
                            break;
                        }
                        Err(ref err) if interrupted(err) => { 
                            debug!("accept() interupted");
                            continue;
                        }
                        Err(err) => {
                            error!("Error in accepting TCP connection {}", err);
                            break; // TODO: exit?
                        }
                    }
                }
            }
        }
        
        if let Some(h3_conn) = &mut client.h3_conn{
            let mut streams_to_add = Vec::new();
            let mut tokens_to_remove = Vec::new();
            for (token, stream) in client.streams.iter_mut() {
                if stream.state == ConnectStreamState::RequestNotSent {
                    while let Some(received) = stream.socket_read_queue.pop_front() {
                        match received.receive_type {
                            EventType::Headers { list } => unreachable!(),
                            EventType::Data => {
                                // TODO: handle a chunk of data containing both request and bodies.. Is it possible though?
                                // TODO: handle other method correctly. CONNECT may not be the first request in the connection?
                                let mut headers = [httparse::EMPTY_HEADER; 16];
                                let mut req = httparse::Request::new(&mut headers);
                                let res = req.parse(&received.data).unwrap();
                                if let Some(method) = req.method {
                                    if let Some(path) = req.path {
                                        if method.eq_ignore_ascii_case("CONNECT") {
                                            // TODO: Check Host?
                                            let headers = vec![
                                                quiche::h3::Header::new(b":method", b"CONNECT"),
                                                quiche::h3::Header::new(b":authority", path.as_bytes()),
                                                quiche::h3::Header::new(b":authorization", b"something"),    
                                            ];
                                            info!("sending HTTP3 request {:?}", headers);
                                            match h3_conn.send_request(&mut client.conn, &headers, false) {
                                                Ok(stream_id) => {
                                                    streams_to_add.push((token.clone(), stream_id));
                                                    stream.state = ConnectStreamState::RequestSent;
                                                }
        
                                                Err(e) => {
                                                    error!("HTTP3 send request failed {:?}", e);
                                                    if e == quiche::h3::Error::StreamBlocked {
                                                        // retry later
                                                        stream.socket_read_queue.push_front(received);
                                                    } else {
                                                        // considered fatal
                                                        tokens_to_remove.push(token.clone());
                                                    }
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            EventType::Datagram => todo!(),
                            EventType::Finished => {
                                tokens_to_remove.push(token.clone());
                            },
                        }
                    }
                }
            }
            for (token, stream_id) in streams_to_add {
                client.add_stream(token, stream_id);
            }
            for token in tokens_to_remove {
                client.remove_stream(&token);
            }
        }
    });

}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

    vec.join("")
}

pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}


fn would_block(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::WouldBlock
}

fn interrupted(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::Interrupted
}

