#[macro_use]
extern crate log;

use std::net;
use std::net::ToSocketAddrs;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::env;
use std::error::Error;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::net::{UdpSocket, TcpStream};
use tokio::sync::mpsc::{self, UnboundedSender};

use ring::rand::*;

use quiche::h3::NameValue;

const MAX_DATAGRAM_SIZE: usize = 1350;

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

#[derive(PartialEq, Debug)]
enum Content {
    Headers {
        headers: Vec<quiche::h3::Header>,
    },
    Data {
        data: Vec<u8>,
    },
    Datagram,
    Finished,
}

#[derive(Debug)]
pub struct ToSend {
    stream_id: u64, // or flow_id for DATAGRAM
    content: Content,
    finished: bool,
}

struct QuicReceived {
    recv_info: quiche::RecvInfo,
    data: Vec<u8>,
}


struct Client {
    conn: quiche::Connection,
    quic_receiver: mpsc::UnboundedReceiver<QuicReceived>,
    socket: Arc<UdpSocket>,
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, mpsc::UnboundedSender<QuicReceived>>;
// type TokenMap = BiMap<Token, (quiche::ConnectionId<'static>, u64)>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    debug!("creating socket");

    let listen_addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4433".to_string());

    // Create the UDP listening socket, and register it with the event loop.
    let socket = UdpSocket::bind(listen_addr.clone()).await?;
    let socket = Arc::new(socket);

    debug!("listening on {}", listen_addr);

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

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients = ClientMap::new();
    // let mut tcp_connections = TokenMap::new();

    let local_addr = socket.local_addr().unwrap();

    'read: loop {
        let (len, from) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,

            Err(e) => {
                panic!("recv_from() failed: {:?}", e);
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
        let tx = if !clients.contains_key(&hdr.dcid) &&
            !clients.contains_key(&conn_id)
        {
            // TODO: move initialization to client task
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

                if let Err(e) = socket.send_to(out, from).await {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("send_to() would block");
                        break;
                    }

                    panic!("send_to() failed: {:?}", e);
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

                if let Err(e) = socket.send_to(out, from).await {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("send_to() would block");
                        break;
                    }

                    panic!("send_to() failed: {:?}", e);
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

            let (tx, rx) = mpsc::unbounded_channel();

            let client = Client {
                conn,
                quic_receiver: rx,
                socket: socket.clone(),
            };

            clients.insert(scid.clone(), tx);

            tokio::spawn(async move {
                handle_client(client).await
            });

            clients.get(&scid).unwrap()
        } else {
            match clients.get(&hdr.dcid) {
                Some(v) => v,

                None => clients.get(&conn_id).unwrap(),
            }
        };

        let recv_info = quiche::RecvInfo {
            to: socket.local_addr().unwrap(),
            from,
        };
        
        match tx.send(QuicReceived { recv_info, data: pkt_buf.to_vec() }) {
            Ok(_) => {},
            _ => {
                debug!("Error sending to {:?}", &hdr.dcid);
                clients.remove(&hdr.dcid);
            }
        }

    }

    Ok(())
}

async fn handle_client(mut client: Client) {
    let mut http3_conn: Option<quiche::h3::Connection> = None;
    let mut connect_streams: HashMap<u64, UnboundedSender<Vec<u8>>> = HashMap::new();
    let (http3_sender, mut http3_receiver) = mpsc::unbounded_channel::<ToSend>();

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let timeout = 5000;
    let sleep = tokio::time::sleep(tokio::time::Duration::from_millis(timeout));
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            http3_to_send = http3_receiver.recv() => {
                if http3_to_send.is_none() {
                    unreachable!()
                }
                let mut to_send = http3_to_send.unwrap();
                let http3_conn = http3_conn.as_mut().unwrap();
                loop {
                    let result = match &to_send.content {
                        Content::Headers { headers } => {
                            debug!("sending http3 response {:?}", hdrs_to_strings(&headers));
                            http3_conn.send_response(&mut client.conn, to_send.stream_id, headers, to_send.finished)
                        },
                        Content::Data { data } => {
                            debug!("sending http3 data of {} bytes", data.len());
                            let mut written = 0;
                            loop {
                                if written >= data.len() {
                                    break Ok(())
                                }
                                match http3_conn.send_body(&mut client.conn, to_send.stream_id, &data[written..], to_send.finished) {
                                    Ok(v) => written += v,
                                    Err(e) => {
                                        to_send = ToSend { stream_id: to_send.stream_id, content: Content::Data { data: data[written..].to_vec() }, finished: to_send.finished };
                                        break Err(e)
                                    },
                                }
                                debug!("written http3 data {} of {} bytes", written, data.len());
                            }
                        },
                        Content::Datagram => todo!(),
                        Content::Finished => todo!(),
                    };
                    match result {
                        Ok(_) => {},
                        Err(quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done) => {
                            debug!("Connection {} stream {} stream blocked, retry later", client.conn.trace_id(), to_send.stream_id);
                            http3_sender.send(to_send).expect("http3 channel send failed"); // retry later 
                            break; 
                        },
                        Err(e) => {
                            error!("Connection {} stream {} send failed {:?}", client.conn.trace_id(), to_send.stream_id, e);
                            client.conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Write, 0);
                            connect_streams.remove(&to_send.stream_id);
                        }
                    };
                    to_send = match http3_receiver.try_recv() {
                        Ok(v) => v,
                        Err(e) => break,
                    };
                }
            },
            recvd = client.quic_receiver.recv() => {
                match recvd {
                    Some(mut quic_received) => {
                        let read = match client.conn.recv(&mut quic_received.data, quic_received.recv_info) {
                            Ok(v) => v,
                            Err(e) => {
                                error!("Error when quic recv(): {}", e);
                                break
                            }
                        };
                        debug!("{} processed {} bytes", client.conn.trace_id(), read);
                        
                    },
                    None => {
                        break // channel closed on the other side. Should not happen?
                    },
                }
                // Create a new HTTP/3 connection as soon as the QUIC connection
                // is established.
                if (client.conn.is_in_early_data() || client.conn.is_established()) &&
                    http3_conn.is_none()
                {
                    debug!(
                        "{} QUIC handshake completed, now trying HTTP/3",
                        client.conn.trace_id()
                    );

                    let h3_config = quiche::h3::Config::new().unwrap();
                    let h3_conn = match quiche::h3::Connection::with_transport(
                        &mut client.conn,
                        &h3_config,
                    ) {
                        Ok(v) => v,

                        Err(e) => {
                            error!("failed to create HTTP/3 connection: {}", e);
                            continue;
                        },
                    };

                    // TODO: sanity check h3 connection before adding to map
                    http3_conn = Some(h3_conn);
                }

                if http3_conn.is_some() {
                    // Process HTTP/3 events.
                    let http3_conn = http3_conn.as_mut().unwrap();
                    loop {
                        match http3_conn.poll(&mut client.conn) {
                            Ok((
                                stream_id,
                                quiche::h3::Event::Headers { list: headers, .. },
                            )) => {
                                info!(
                                    "{} got request {:?} on stream id {}",
                                    client.conn.trace_id(),
                                    hdrs_to_strings(&headers),
                                    stream_id
                                );
                            
                                // Handle CONNECT: 
                                /*
                                 * 0. Connect TcpStream
                                 * 1. Add to connect_streams
                                 * 2. Register to poll
                                 */
                            
                                let mut method = None;
                                let mut authority = None;
                            
                                // Look for the request's path and method.
                                for hdr in headers.iter() {
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
                                                    let http3_sender_clone_1 = http3_sender.clone();
                                                    let http3_sender_clone_2 = http3_sender.clone();
                                                    let (tcp_sender, mut tcp_receiver) = mpsc::unbounded_channel::<Vec<u8>>();
                                                    connect_streams.insert(stream_id, tcp_sender);
                                                    tokio::spawn(async move {
                                                        let stream = match TcpStream::connect(peer_addr).await {
                                                            Ok(v) => v,
                                                            Err(e) => {
                                                                error!("Error connecting TCP to {}: {}", peer_addr, e);
                                                                return
                                                            }
                                                        };
                                                        debug!("connecting to url {} {}", target_url, target_url.to_socket_addrs().unwrap().next().unwrap());
                                                        let (mut read_half, mut write_half) = stream.into_split();
                                                        let read_task = tokio::spawn(async move {
                                                            let mut buf = [0; 65535];
                                                            loop {
                                                                let read = match read_half.read(&mut buf).await {
                                                                    Ok(v) => v,
                                                                    Err(e) => {
                                                                        error!("Error reading from TCP {}: {}", peer_addr, e);
                                                                        break
                                                                    },
                                                                };
                                                                if read == 0 {
                                                                    debug!("TCP connection closed from {}", peer_addr);
                                                                    break
                                                                }
                                                                debug!("read {} bytes from TCP from {} for stream {}", read, peer_addr, stream_id);
                                                                http3_sender_clone_1.send(ToSend { stream_id: stream_id, content: Content::Data { data: buf[..read].to_vec() }, finished: false });
                                                            }
                                                        });
                                                        let write_task = tokio::spawn(async move {
                                                            loop {
                                                                let data = match tcp_receiver.recv().await {
                                                                    Some(v) => v,
                                                                    None => {
                                                                        debug!("TCP receiver channel closed for stream {}", stream_id);
                                                                        break
                                                                    },
                                                                };
                                                                trace!("start sending on TCP");
                                                                let mut pos = 0;
                                                                while pos < data.len() {
                                                                    let bytes_written = match write_half.write(&data[pos..]).await {
                                                                        Ok(v) => v,
                                                                        Err(e) => {
                                                                            error!("Error writing to TCP {} on stream id {}: {}", peer_addr, stream_id, e);
                                                                            return
                                                                        },
                                                                    };
                                                                    pos += bytes_written;
                                                                }
                                                                debug!("written {} bytes from TCP to {} for stream {}", data.len(), peer_addr, stream_id);
                                                            }
                                                        });
                                                        let headers = vec![
                                                            quiche::h3::Header::new(b":status", b"200"),
                                                            quiche::h3::Header::new(b"content-length", b"0"), // NOTE: is this needed?
                                                        ];
                                                        http3_sender_clone_2.send(ToSend { stream_id, content: Content::Headers { headers }, finished: false }).expect("channel send failed");
                                                        tokio::join!(read_task, write_task);
                                                    });
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
                            
                                    _ => {},
                                };
                            },

                            Ok((stream_id, quiche::h3::Event::Data)) => {
                                info!(
                                    "{} got data on stream id {}",
                                    client.conn.trace_id(),
                                    stream_id
                                );
                                if connect_streams.contains_key(&stream_id) {
                                    while let Ok(read) = http3_conn.recv_body(&mut client.conn, stream_id, &mut buf) {
                                        debug!(
                                            "got {} bytes of data on stream {}",
                                            read, stream_id
                                        );
                                        trace!("{}", unsafe {
                                            std::str::from_utf8_unchecked(&buf[..read])
                                        });
                                        let data = &buf[..read];
                                        connect_streams.get(&stream_id).unwrap().send(data.to_vec()).expect("channel send failed");
                                    }
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
            },
            () = &mut sleep => {
                trace!("timeout elapsed");
                sleep.as_mut().reset(tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout));

                if client.conn.is_closed() {
                    info!(
                        "{} connection collected {:?}",
                        client.conn.trace_id(),
                        client.conn.stats()
                    );
                }
            },
            else => break,
        }
        loop {
            let (write, send_info) = match client.conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("QUIC connection {} done writing", client.conn.trace_id());
                    break;
                },

                Err(e) => {
                    error!("QUIC connection {} send failed: {:?}", client.conn.trace_id(), e);

                    client.conn.close(false, 0x1, b"fail").ok();
                    break;
                },
            };

            match client.socket.send_to(&out[..write], send_info.to).await {
                Ok(written) => debug!("{} written {} bytes out of {}", client.conn.trace_id(), written, write),
                Err(e) => panic!("UDP socket send_to() failed: {:?}", e),
            }
        }
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


pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}
