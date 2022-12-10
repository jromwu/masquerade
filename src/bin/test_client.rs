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

use quiche;
use quiche::h3::{self, NameValue};
use ring::rand::*;
use bimap::BiMap;

use std::net::{ToSocketAddrs};
use std::collections::HashMap;

const MAX_DATAGRAM_SIZE: usize = 1350;

enum ConnectStreamState {
    RequestNotSent,
    RequestSent,
    ConnectionEstablished,
}

fn main() {
    env_logger::init();

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    // let server_name = "https://cloudflare-quic.com/";
    let server_name = "https://127.0.0.1:4433/";
    let url = url::Url::parse(&server_name).unwrap();
    // Resolve server address.
    let peer_addr = url.to_socket_addrs().unwrap().next().unwrap();
    
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };

    info!("Resolved {} to {}", server_name, peer_addr);

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let mut socket =
        mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();
    // TODO: add listening TCP socket to poll
    
    let local_addr = socket.local_addr().unwrap();

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    // *CAUTION*: this should not be set to `false` in production!!!
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
    

    while let Err(e) = socket.send_to(&out[..write], send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            debug!("send() would block");
            continue;
        }

        panic!("send() failed: {:?}", e);
    }

    debug!("written {}", write);
    
    
    let h3_config = quiche::h3::Config::new().unwrap();
    
    let mut http3_conn = None;
    
    let mut state = ConnectStreamState::RequestNotSent;
    let mut get_sent = false;
    let mut stream_id = 0;

    let timeout = conn.timeout();

    'main: loop {
        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                debug!("socket timed out"); //TODO: really?

                conn.on_timeout();

                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
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

            let recv_info = quiche::RecvInfo {
                to: local_addr,
                from,
            };

            // Process potentially coalesced packets.
            let read = match conn.recv(&mut buf[..len], recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("recv failed: {:?}", e);
                    continue 'read;
                },
            };

            debug!("processed {} bytes", read);
        }

        debug!("done reading");

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }

        // Create a new HTTP/3 connection once the QUIC connection is established.
        if conn.is_established() && http3_conn.is_none() {
            http3_conn = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
            );
        }


        if let Some(h3_conn) = &mut http3_conn {
            // Send HTTP requests once the QUIC connection is established
            state = match state {
                ConnectStreamState::RequestNotSent => {
                    let headers = vec![
                        quiche::h3::Header::new(b":method", b"CONNECT"),
                        quiche::h3::Header::new(b":authority", b"http://example.com"),
                        // quiche::h3::Header::new(b":authority", b"http://127.0.0.1:8888"),
                        quiche::h3::Header::new(b":authorization", b"something"),
                    ];
                        
                    info!("sending HTTP request {:?}", headers);
        
                    stream_id = h3_conn.send_request(&mut conn, &headers, false).unwrap();
        
                    info!("sent HTTP request on stream id: {}", stream_id);
        
                    ConnectStreamState::RequestSent
                }
                ConnectStreamState::ConnectionEstablished => {
                    if !get_sent {
                        let body = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
                        info!("sending HTTP body {:?}", body);
                        h3_conn.send_body(&mut conn, stream_id, body, false).expect("HTTP body send failed");
                        info!("sent HTTP body on stream id: {}", stream_id);
                        get_sent = true;
                    }
                    ConnectStreamState::ConnectionEstablished
                }
                other => other
            };
        
        
            // Process HTTP/3 events.
            loop {
                match h3_conn.poll(&mut conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        info!(
                            "got response headers {:?} on stream id {}",
                            hdrs_to_strings(&list),
                            stream_id
                        );
                        state = ConnectStreamState::ConnectionEstablished;
                    },
    
                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        while let Ok(read) =
                            h3_conn.recv_body(&mut conn, stream_id, &mut buf)
                        {
                            debug!(
                                "got {} bytes of response data on stream {}",
                                read, stream_id
                            );
    
                            trace!("{}", unsafe {
                                std::str::from_utf8_unchecked(&buf[..read])
                            });
                        }
                    },
    
                    Ok((stream_id, quiche::h3::Event::Finished)) => {
                        info!(
                            "finished received, stream id: {} closed",
                            stream_id
                        );
                        break;
                    },
    
                    Ok((stream_id, quiche::h3::Event::Reset(e))) => {
                        error!(
                            "request was reset by peer with {}, stream id: {} closed",
                            e,
                            stream_id
                        );
                        break;
                    },
    
                    Ok((_flow_id, quiche::h3::Event::Datagram)) => (),
    
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

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        loop {
            let (write, send_info) = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("done writing");
                    break;
                },

                Err(e) => {
                    error!("send failed: {:?}", e);

                    conn.close(false, 0x1, b"fail").ok();
                    break;
                },
            };

            if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!("send() would block");
                    break;
                }

                panic!("send() failed: {:?}", e);
            }

            debug!("written {}", write);
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }
    }
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

