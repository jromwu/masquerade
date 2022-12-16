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
* Modified from cloudflare/quiche example server
*/

#[macro_use]
extern crate log;

use std::net;
use std::net::ToSocketAddrs;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::str::from_utf8;
use std::collections::VecDeque;

use bimap::BiMap;
use mio::{Token, Poll};
use mio::net::TcpStream;
use ring::rand::*;

use quiche::h3::NameValue;

const MAX_DATAGRAM_SIZE: usize = 1350;

const HOST: &str = "127.0.0.1";
const PORT: usize = 4433;

const SERVER: Token = Token(0);

#[derive(PartialEq)]
enum ConnectStreamState {
    RequestReceived,
    ConnectionEstablished,
}

struct ConnectStream {
    state: ConnectStreamState,
    socket: TcpStream,
    write_queue: VecDeque<Vec<u8>> 
}

struct PartialResponse {
    headers: Option<Vec<quiche::h3::Header>>,
    body: Vec<u8>,
    written: usize,
}


struct Client {
    conn: quiche::Connection,

    http3_conn: Option<quiche::h3::Connection>,

    partial_responses: HashMap<u64, PartialResponse>,

    connect_streams: HashMap<u64, ConnectStream>, // Stream ID to ConnectStream
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;
type TokenMap = BiMap<Token, (quiche::ConnectionId<'static>, u64)>;

fn main() {
    env_logger::init();

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    debug!("creating socket");

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP listening socket, and register it with the event loop.
    let mut socket =
        mio::net::UdpSocket::bind(format!("{}:{}", HOST, PORT).parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, SERVER, mio::Interest::READABLE)
        .unwrap();

    debug!("listening on {}:{}", HOST, PORT);

    // Create the configuration for the QUIC connections.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config
        .load_cert_chain_from_pem_file("example_cert/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("example_cert/cert.key")
        .unwrap();

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();

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
    config.enable_early_data();

    let h3_config = quiche::h3::Config::new().unwrap();

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients = ClientMap::new();
    let mut tcp_connections = TokenMap::new();

    let local_addr = socket.local_addr().unwrap();
    
    let mut unique_token = Token(SERVER.0 + 1);

    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let timeout = clients.values().filter_map(|c| c.conn.timeout()).min();

        poll.poll(&mut events, timeout).unwrap();

        for event in events.iter() {
            debug!("Poll event on token {}", event.token().0);
            match event.token() {
                SERVER => {} // ignore it for now, handles all read and write to QUIC later
                token => {
                    debug!("Poll event on token {} for TCP", event.token().0);
                    let remove_token = if let Some((connection_id, stream_id)) = tcp_connections.get_by_left(&token) {
                        debug!("Poll event on token {} for TCP connection {:?} stream {}", event.token().0, connection_id, stream_id);
                        let client = clients.get_mut(connection_id).unwrap();
                        let connect_session = client.connect_streams.get_mut(stream_id).unwrap();
                        let connection = &mut connect_session.socket;
                        let mut connection_closed = false;
                        let mut http_conn_closed = false;

                        if connect_session.state == ConnectStreamState::RequestReceived {
                            if let Ok(addr) = connection.peer_addr() {
                                debug!("TCP connection established to {} for connection {:?} stream {}", addr, connection_id, stream_id);
                                connect_session.state = ConnectStreamState::ConnectionEstablished;

                                // Send 2xx HEADERS to inform client connection established
                                let headers = vec![
                                    quiche::h3::Header::new(b":status", b"200"),
                                    quiche::h3::Header::new(b"content-length", b"0"), // NOTE: is this needed?
                                ];
                                match client.http3_conn.as_mut().unwrap().send_response(&mut client.conn, *stream_id, &headers, false) {
                                    Ok(v) => v,
                            
                                    Err(quiche::h3::Error::StreamBlocked) => {
                                        // TODO: handle partial response using queue
                                        let response = PartialResponse {
                                            headers: Some(headers),
                                            body: b"".to_vec(),
                                            written: 0,
                                        };
                            
                                        client.partial_responses.insert(*stream_id, response);
                                    },
                            
                                    Err(e) => {
                                        error!("{} stream send failed {:?}", client.conn.trace_id(), e);
                                    },
                                }
                            }
                        } 

                        if event.is_readable() {
                            let mut received_data = vec![0; 4096];
                            let mut bytes_read = 0;
                            // We can (maybe) read from the connection.
                            loop {
                                match connection.read(&mut received_data[bytes_read..]) {
                                    Ok(0) => {
                                        // Reading 0 bytes means the other side has closed the
                                        // connection or is done writing, then so are we.
                                        debug!("Received 0 bytes from TCP, connection {:?} session {}", connection_id, stream_id);
                                        connection_closed = true;
                                        break;
                                    }
                                    Ok(n) => {
                                        bytes_read += n;
                                        if bytes_read == received_data.len() {
                                            received_data.resize(received_data.len() + 1024, 0);
                                        }
                                        debug!("Received {} bytes from TCP, connection {:?} session {}", n, connection_id, stream_id);
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
                                // Relay data to client
                                debug!("Received {} bytes, connection {:?} session {}", bytes_read, connection_id, stream_id);
                                trace!("{}", unsafe {
                                    std::str::from_utf8_unchecked(received_data)
                                });
                                
                                let written = match client.http3_conn.as_mut().unwrap().send_body(&mut client.conn, *stream_id, received_data, connection_closed) {
                                    Ok(v) => { http_conn_closed = connection_closed; v},
                            
                                    Err(quiche::h3::Error::Done) => 0, // TODO: handle this
                            
                                    Err(e) => {
                                        error!("connection {:?} stream {} send failed {:?}", connection_id, stream_id, e);
                                        connection_closed = true;
                                        0
                                        // TODO: handle error
                                        // return;
                                    },
                                };
                            
                                if written < received_data.len() {
                                    // TODO: handle partial write correctly: retry next time, add a queue
                                    error!("connection {:?} stream {} partially written {} bytes of {} bytes", connection_id, stream_id, written, received_data.len());
                                }

                                if let Ok(str_buf) = from_utf8(received_data) {
                                    debug!("Received data: {}", str_buf.trim_end());
                                } else {
                                    debug!("Received (none UTF-8) data: {:?}", received_data);
                                }
                            }
                        } 
                        
                        if !connection_closed && event.is_writable() {
                            // TODO: if event is writable
                            debug!("event for token {} is writable", token.0);
                            if connect_session.state == ConnectStreamState::ConnectionEstablished {
                                debug!("TCP connection is checked established");

                                while let Some(data) = connect_session.write_queue.front() {
                                    debug!("writing to TCP connection");
                                    trace!("{}", unsafe {
                                        std::str::from_utf8_unchecked(data)
                                    });
                                    match connection.write(data) {
                                        // We want to write the entire `DATA` buffer in a single go. If we
                                        // write less we'll return a short write error (same as
                                        // `io::Write::write_all` does).
                                        Ok(n) => {
                                            // TODO: handle short write
                                            debug!("Sent {} bytes to {}", n, connection.peer_addr().unwrap());
                                            connect_session.write_queue.pop_front();
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
                                            connection_closed = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        
                    
                        if connection_closed {
                            debug!("Connection closed on connection {:?} stream {}", connection_id, stream_id);
                            poll.registry().deregister(connection).expect("poll registry deregister failed");
                            if !http_conn_closed {
                                client.http3_conn.as_mut().unwrap().send_body(&mut client.conn, *stream_id, b"", true); // TODO: is this correct for server to close the stream? Also, error check missing
                                client.conn.stream_shutdown(*stream_id, quiche::Shutdown::Read, 0);
                            }
                            connection.shutdown(std::net::Shutdown::Both);
                            client.connect_streams.remove(stream_id);
                            true
                        } else {
                            false
                        }
                    } else {false};
                    if remove_token {
                        tcp_connections.remove_by_left(&token);
                    }
                }
            }
        }

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                debug!("timed out"); // TODO: really?

                clients.values_mut().for_each(|c| c.conn.on_timeout());

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

            let pkt_buf = &mut buf[..len];

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(
                pkt_buf,
                quiche::MAX_CONN_ID_LEN,
            ) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue 'read;
                },
            };

            debug!("got packet {:?}", hdr);

            let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
            let conn_id = conn_id.to_vec().into();

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let client = if !clients.contains_key(&hdr.dcid) &&
                !clients.contains_key(&conn_id)
            {
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue 'read;
                }

                if !quiche::version_is_supported(hdr.version) {
                    warn!("Doing version negotiation");

                    let len =
                        quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                            .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);

                let scid = quiche::ConnectionId::from_ref(&scid);

                // Token is always present in Initial packets.
                let token = hdr.token.as_ref().unwrap();

                // Do stateless retry if the client didn't send a token.
                if token.is_empty() {
                    warn!("Doing stateless retry");

                    let new_token = mint_token(&hdr, &from);

                    let len = quiche::retry(
                        &hdr.scid,
                        &hdr.dcid,
                        &scid,
                        &new_token,
                        hdr.version,
                        &mut out,
                    )
                    .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let odcid = validate_token(&from, token);

                // The token was not valid, meaning the retry failed, so
                // drop the packet.
                if odcid.is_none() {
                    error!("Invalid address validation token");
                    continue 'read;
                }

                if scid.len() != hdr.dcid.len() {
                    error!("Invalid destination connection ID");
                    continue 'read;
                }

                // Reuse the source connection ID we sent in the Retry packet,
                // instead of changing it again.
                let scid = hdr.dcid.clone();

                debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                let conn = quiche::accept(
                    &scid,
                    odcid.as_ref(),
                    local_addr,
                    from,
                    &mut config,
                )
                .unwrap();

                let client = Client {
                    conn,
                    http3_conn: None,
                    partial_responses: HashMap::new(),
                    connect_streams: HashMap::new(),
                };

                clients.insert(scid.clone(), client);

                clients.get_mut(&scid).unwrap()
            } else {
                match clients.get_mut(&hdr.dcid) {
                    Some(v) => v,

                    None => clients.get_mut(&conn_id).unwrap(),
                }
            };

            let recv_info = quiche::RecvInfo {
                to: socket.local_addr().unwrap(),
                from,
            };

            // Process potentially coalesced packets.
            let read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    continue 'read;
                },
            };

            debug!("{} processed {} bytes", client.conn.trace_id(), read);

            // Create a new HTTP/3 connection as soon as the QUIC connection
            // is established.
            if (client.conn.is_in_early_data() || client.conn.is_established()) &&
                client.http3_conn.is_none()
            {
                debug!(
                    "{} QUIC handshake completed, now trying HTTP/3",
                    client.conn.trace_id()
                );

                let h3_conn = match quiche::h3::Connection::with_transport(
                    &mut client.conn,
                    &h3_config,
                ) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("failed to create HTTP/3 connection: {}", e);
                        continue 'read;
                    },
                };

                // TODO: sanity check h3 connection before adding to map
                client.http3_conn = Some(h3_conn);
            }

            if client.http3_conn.is_some() {
                // Handle writable streams.
                for stream_id in client.conn.writable() {
                    handle_writable(client, stream_id);
                }

                // Process HTTP/3 events.
                loop {
                    let http3_conn = client.http3_conn.as_mut().unwrap();

                    match http3_conn.poll(&mut client.conn) {
                        Ok((
                            stream_id,
                            quiche::h3::Event::Headers { list, .. },
                        )) => {
                            handle_request(
                                client,
                                stream_id,
                                &list,
                                "examples/root",
                                &mut poll,
                                &mut unique_token,
                                &mut tcp_connections,
                            );
                        },

                        Ok((stream_id, quiche::h3::Event::Data)) => {
                            info!(
                                "{} got data on stream id {}",
                                client.conn.trace_id(),
                                stream_id
                            );
                            
                            if client.connect_streams.contains_key(&stream_id) {
                                while let Ok(read) = http3_conn.recv_body(&mut client.conn, stream_id, &mut buf) {
                                    debug!(
                                        "got {} bytes of data on stream {}",
                                        read, stream_id
                                    );
                                    trace!("{}", unsafe {
                                        std::str::from_utf8_unchecked(&buf[..read])
                                    });
            
                                    client.connect_streams.get_mut(&stream_id).unwrap().write_queue.push_back(buf[..read].to_vec());
                                }
                                poll.registry()
                                    .reregister(
                                        &mut client.connect_streams.get_mut(&stream_id).unwrap().socket, 
                                        tcp_connections.get_by_right(&(client.conn.source_id(), stream_id)).unwrap().to_owned(), 
                                        mio::Interest::READABLE | mio::Interest::WRITABLE
                                    ).expect("poll registry reregister failed");  // re-register to receive a new writable event when socket is writable
                            }
                        },

                        Ok((_stream_id, quiche::h3::Event::Finished)) => (),

                        Ok((_stream_id, quiche::h3::Event::Reset { .. })) => (),

                        Ok((_flow_id, quiche::h3::Event::Datagram)) => (),

                        Ok((
                            _prioritized_element_id,
                            quiche::h3::Event::PriorityUpdate,
                        )) => (),

                        Ok((_goaway_id, quiche::h3::Event::GoAway)) => (),

                        Err(quiche::h3::Error::Done) => {
                            break;
                        },

                        Err(e) => {
                            error!(
                                "{} HTTP/3 error {:?}",
                                client.conn.trace_id(),
                                e
                            );

                            break;
                        },
                    }
                }
            }
        }

        // Generate outgoing QUIC packets for all active connections and send
        // them on the UDP socket, until quiche reports that there are no more
        // packets to be sent.
        for client in clients.values_mut() {
            loop {
                let (write, send_info) = match client.conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        debug!("{} done writing", client.conn.trace_id());
                        break;
                    },

                    Err(e) => {
                        error!("{} send failed: {:?}", client.conn.trace_id(), e);

                        client.conn.close(false, 0x1, b"fail").ok();
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

                debug!("{} written {} bytes", client.conn.trace_id(), write);
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, ref mut c| {
            debug!("Collecting garbage");

            if c.conn.is_closed() {
                info!(
                    "{} connection collected {:?}",
                    c.conn.trace_id(),
                    c.conn.stats()
                );
            }

            !c.conn.is_closed()
        });
    }
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    // TODO: add cryptographic token
    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(
    src: &net::SocketAddr, token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}

/// Handles incoming HTTP/3 requests.
fn handle_request(
    client: &mut Client, stream_id: u64, headers: &[quiche::h3::Header],
    root: &str, poll: &mut Poll, current_token: &mut Token, tcp_connections: &mut TokenMap
) {
    let conn = &mut client.conn;
    let http3_conn = &mut client.http3_conn.as_mut().unwrap();

    info!(
        "{} got request {:?} on stream id {}",
        conn.trace_id(),
        hdrs_to_strings(headers),
        stream_id
    );

    // We decide the response based on headers alone, so stop reading the
    // request stream so that any body is ignored and pointless Data events
    // are not generated.
    // conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
    //     .unwrap();

    // TODO: Handle CONNECT: 
    /*
     * 0. Connect TcpStream
     * 1. Add to connect_streams
     * 2. Register to poll
     */

    let mut method = None;
    let mut authority = None;

    // Look for the request's path and method.
    for hdr in headers {
        match hdr.name() {
            b":method" => method = Some(hdr.value()),
            b":authority" => authority = Some(std::str::from_utf8(hdr.value()).unwrap()),
            _ => (),
        }
    }

    match method {
        Some(b"CONNECT") => {
            if let Some(authority) = authority {
                if let Ok(target_url) = if authority.contains("://") { url::Url::parse(authority) } else {url::Url::parse(format!("scheme://{}", authority).as_str())} {
                    debug!("connecting to url {} from authority {}", target_url, authority);
                    if let Ok(mut socket_addrs) = target_url.to_socket_addrs() {
                        let peer_addr = socket_addrs.next().unwrap();
                        match TcpStream::connect(peer_addr) {
                            Ok(stream) => {
                                debug!("connecting to url {} {}", target_url, target_url.to_socket_addrs().unwrap().next().unwrap());
                                // TODO: check authorization
                                client.connect_streams.insert(stream_id, ConnectStream { 
                                    state: ConnectStreamState::RequestReceived, 
                                    socket: stream, 
                                    write_queue: VecDeque::new() 
                                });
                                let token = next(current_token);
                                poll.registry()
                                    .register(
                                        &mut client.connect_streams.get_mut(&stream_id).unwrap().socket, 
                                        token, 
                                        mio::Interest::READABLE | mio::Interest::WRITABLE
                                    ).expect("poll registry register failed");
                                tcp_connections.insert(token, (conn.source_id().into_owned(), stream_id));
                            },
                            Err(_) => {}, // TODO: send error
                        }
                    } else {
                        // TODO: send error
                    }
                } else {
                    // TODO: send error
                }
            } else {
                // TODO: send error
            }
        },

        _ => {
            let (headers, body) = build_response(root, headers);

            match http3_conn.send_response(conn, stream_id, &headers, false) {
                Ok(v) => v,

                Err(quiche::h3::Error::StreamBlocked) => {
                    let response = PartialResponse {
                        headers: Some(headers),
                        body,
                        written: 0,
                    };

                    client.partial_responses.insert(stream_id, response);
                    return;
                },

                Err(e) => {
                    error!("{} stream send failed {:?}", conn.trace_id(), e);
                    return;
                },
            }

            let written = match http3_conn.send_body(conn, stream_id, &body, true) {
                Ok(v) => v,

                Err(quiche::h3::Error::Done) => 0,

                Err(e) => {
                    error!("{} stream send failed {:?}", conn.trace_id(), e);
                    return;
                },
            };

            if written < body.len() {
                let response = PartialResponse {
                    headers: None,
                    body,
                    written,
                };

                client.partial_responses.insert(stream_id, response);
            }
        },
    };
}

/// Builds an HTTP/3 response given a request.
fn build_response(
    root: &str, request: &[quiche::h3::Header],
) -> (Vec<quiche::h3::Header>, Vec<u8>) {
    let mut file_path = std::path::PathBuf::from(root);
    let mut path = std::path::Path::new("");
    let mut method = None;

    // Look for the request's path and method.
    for hdr in request {
        match hdr.name() {
            b":path" =>
                path = std::path::Path::new(
                    std::str::from_utf8(hdr.value()).unwrap(),
                ),

            b":method" => method = Some(hdr.value()),

            _ => (),
        }
    }

    let (status, body) = match method {
        Some(b"GET") => {
            (200, b"hello world".to_vec())
        },

        _ => (405, Vec::new()),
    };

    let headers = vec![
        quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
        quiche::h3::Header::new(b"server", b"quiche"),
        quiche::h3::Header::new(
            b"content-length",
            body.len().to_string().as_bytes(),
        ),
    ];

    (headers, body)
}

/// Handles newly writable streams.
fn handle_writable(client: &mut Client, stream_id: u64) {
    let conn = &mut client.conn;
    let http3_conn = &mut client.http3_conn.as_mut().unwrap();

    debug!("{} stream {} is writable", conn.trace_id(), stream_id);

    if !client.partial_responses.contains_key(&stream_id) {
        return;
    }

    let resp = client.partial_responses.get_mut(&stream_id).unwrap();

    if let Some(ref headers) = resp.headers {
        match http3_conn.send_response(conn, stream_id, headers, false) {
            Ok(_) => (),

            Err(quiche::h3::Error::StreamBlocked) => {
                return;
            },

            Err(e) => {
                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            },
        }
    }

    resp.headers = None;

    let body = &resp.body[resp.written..];

    let written = match http3_conn.send_body(conn, stream_id, body, true) {
        Ok(v) => v,

        Err(quiche::h3::Error::Done) => 0,

        Err(e) => {
            client.partial_responses.remove(&stream_id);

            error!("{} stream send failed {:?}", conn.trace_id(), e);
            return;
        },
    };

    resp.written += written;

    if resp.written == resp.body.len() {
        client.partial_responses.remove(&stream_id);
    }
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

fn next(current: &mut Token) -> Token {
    let next = current.0;
    current.0 += 1;
    Token(next)
}

fn would_block(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::WouldBlock
}

fn interrupted(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Interrupted
}
