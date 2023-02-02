use log::*;
use quiche::h3::NameValue;

use std::net::{self, SocketAddr};
use std::net::ToSocketAddrs;
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::net::{UdpSocket, TcpStream};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::time::{self, Duration};

use ring::rand::*;

use crate::common::*;

#[derive(PartialEq, Debug)]
enum Content {
    Headers {
        headers: Vec<quiche::h3::Header>,
    },
    Data {
        data: Vec<u8>,
    },
    Datagram {
        payload: Vec<u8>,
    },
    Finished,
}

#[derive(Debug)]
struct ToSend {
    stream_id: u64, // or flow_id for DATAGRAM
    content: Content,
    finished: bool,
}

struct QuicReceived {
    recv_info: quiche::RecvInfo,
    data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct RunBeforeBindError;

impl std::fmt::Display for RunBeforeBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "bind(listen_addr) has to be called before run()")
    }
}
impl Error for RunBeforeBindError {}

struct Client {
    conn: quiche::Connection,
    quic_receiver: mpsc::UnboundedReceiver<QuicReceived>,
    socket: Arc<UdpSocket>,
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, mpsc::UnboundedSender<QuicReceived>>;

pub struct Server {
    socket: Option<Arc<UdpSocket>>,
}

impl Server {
    pub fn new() -> Server {
        Server { socket: None }
    }

    /**
     * returns None if server is not bound to a socket yet
     */
    pub fn listen_addr(&self) -> Option<SocketAddr> {
        return self.socket.clone().map(|socket| socket.local_addr().unwrap())
    }

    pub async fn bind<T: tokio::net::ToSocketAddrs>(&mut self, listen_addr: T) -> Result<(), Box<dyn Error>> {
        debug!("creating UDP socket");
    
        // Create the UDP listening socket, and register it with the event loop.
        let socket = UdpSocket::bind(listen_addr).await?;
        debug!("listening on {}", socket.local_addr().unwrap());
        
        self.socket = Some(Arc::new(socket));
        Ok(())
    }

    pub async fn run(&self) -> Result<(), Box<dyn Error>> {
        if self.socket.is_none() {
            return Err(Box::new(RunBeforeBindError))
        }
        let socket = self.socket.clone().unwrap();

        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];
    
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
}



async fn handle_client(mut client: Client) {
    let mut http3_conn: Option<quiche::h3::Connection> = None;
    let mut connect_streams: HashMap<u64, UnboundedSender<Vec<u8>>> = HashMap::new(); // for TCP CONNECT
    let mut connect_sockets: HashMap<u64, UnboundedSender<Vec<u8>>> = HashMap::new(); // for CONNECT UDP
    let (http3_sender, mut http3_receiver) = mpsc::unbounded_channel::<ToSend>();

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let timeout = 5000; // milliseconds
    let sleep = tokio::time::sleep(Duration::from_millis(timeout));
    tokio::pin!(sleep);

    let mut http3_retry_send: Option<ToSend> = None;
    let mut interval = time::interval(Duration::from_millis(20));
    loop {
        tokio::select! {
            http3_to_send = http3_receiver.recv(), if http3_conn.is_some() && http3_retry_send.is_none() => {
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
                        Content::Datagram { payload } => {
                            debug!("sending http3 datagram of {} bytes", payload.len());
                            http3_conn.send_dgram(&mut client.conn, to_send.stream_id, &payload)
                        },
                        Content::Finished => todo!(),
                    };
                    match result {
                        Ok(_) => {},
                        Err(quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done) => {
                            debug!("Connection {} stream {} stream blocked, retry later", client.conn.trace_id(), to_send.stream_id);
                            http3_retry_send = Some(to_send);
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
                            
                                let mut method = None;
                                let mut authority = None;
                                let mut protocol = None;
                                let mut scheme = None;
                                let mut path = None;
                            
                                // Look for the request's path and method.
                                for hdr in headers.iter() {
                                    match hdr.name() {
                                        b":method" => method = Some(hdr.value()),
                                        b":authority" => authority = Some(std::str::from_utf8(hdr.value()).unwrap()),
                                        b":protocol" => protocol = Some(hdr.value()),
                                        b":scheme" => scheme = Some(hdr.value()),
                                        b":path" => path = Some(hdr.value()),
                                        _ => (),
                                    }
                                }
                            
                                match method {
                                    Some(b"CONNECT") => {
                                        if let Some(authority) = authority {
                                            if protocol == Some(b"connect-udp") && scheme.is_some() && path.is_some() {
                                                let path = path.unwrap();
                                                if let Some(peer_addr) = path_to_socketaddr(path) {
                                                    debug!("connecting udp to {} at {} from authority {}", std::str::from_utf8(&path).unwrap(), peer_addr, authority);
                                                    let http3_sender_clone_1 = http3_sender.clone();
                                                    let http3_sender_clone_2 = http3_sender.clone();
                                                    let (udp_sender, mut udp_receiver) = mpsc::unbounded_channel::<Vec<u8>>();
                                                    let flow_id = stream_id / 4;
                                                    connect_sockets.insert(flow_id, udp_sender);
                                                    tokio::spawn(async move {
                                                        let socket = match UdpSocket::bind("0.0.0.0:0").await {
                                                            Ok(v) => v,
                                                            Err(e) => {
                                                                error!("Error binding UDP socket");
                                                                return
                                                            }
                                                        };
                                                        if socket.connect(peer_addr).await.is_err() {
                                                            error!("Error connecting to UDP {}", peer_addr);
                                                            return
                                                        };
                                                        let socket = Arc::new(socket);
                                                        let socket_clone = socket.clone();
                                                        let read_task = tokio::spawn(async move {
                                                            let mut buf = [0; 65527]; // max length of UDP Proxying Payload, ref: https://www.rfc-editor.org/rfc/rfc9298.html#name-http-datagram-payload-forma
                                                            loop {
                                                                let read = match socket_clone.recv(&mut buf).await {
                                                                    Ok(v) => v,
                                                                    Err(e) => {
                                                                        error!("Error reading from UDP {} on stream id {}: {}", peer_addr, stream_id, e);
                                                                        break
                                                                    },
                                                                };
                                                                if read == 0 {
                                                                    debug!("UDP connection closed from {}", peer_addr); // do we need this check?
                                                                    break
                                                                }
                                                                debug!("read {} bytes from UDP from {} for flow {}", read, peer_addr, flow_id);
                                                                let data = wrap_udp_connect_payload(0, &buf[..read]);
                                                                http3_sender_clone_1.send(ToSend { stream_id: flow_id, content: Content::Datagram { payload: data }, finished: false });
                                                            }
                                                        });
                                                        let write_task = tokio::spawn(async move {
                                                            loop {
                                                                let data = match udp_receiver.recv().await {
                                                                    Some(v) => v,
                                                                    None => {
                                                                        debug!("UDP receiver channel closed for flow {}", flow_id);
                                                                        break
                                                                    },
                                                                };
                                                                let (context_id, payload) = decode_var_int(&data);
                                                                assert_eq!(context_id, 0, "received UDP Proxying Datagram with non-zero Context ID");

                                                                trace!("start sending on UDP");
                                                                let bytes_written = match socket.send(payload).await {
                                                                    Ok(v) => v,
                                                                    Err(e) => {
                                                                        error!("Error writing to UDP {} on flow id {}: {}", peer_addr, flow_id, e);
                                                                        return
                                                                    },
                                                                };
                                                                if bytes_written < payload.len() {
                                                                    debug!("Partially sent {} bytes of UDP packet of length {}", bytes_written, payload.len());
                                                                }
                                                                debug!("written {} bytes from UDP to {} for flow {}", payload.len(), peer_addr, flow_id);
                                                            }
                                                        });
                                                        let headers = vec![
                                                            quiche::h3::Header::new(b":status", b"200"),
                                                        ];
                                                        http3_sender_clone_2.send(ToSend { stream_id, content: Content::Headers { headers }, finished: false }).expect("channel send failed");
                                                        tokio::join!(read_task, write_task);
                                                    });
                                                }
                                            } else if let Ok(target_url) = if authority.contains("://") { url::Url::parse(authority) } else {url::Url::parse(format!("scheme://{}", authority).as_str())} {
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

                            Ok((_stream_id, quiche::h3::Event::Finished)) => (), // TODO: Add to the queue

                            Ok((_stream_id, quiche::h3::Event::Reset { .. })) => (), // TODO: Add to the queue

                            Ok((flow_id, quiche::h3::Event::Datagram)) => {
                                info!(
                                    "{} got datagram on flow id {}",
                                    client.conn.trace_id(),
                                    flow_id
                                );
                                if connect_sockets.contains_key(&flow_id) {
                                    match http3_conn.recv_dgram(&mut client.conn, &mut buf) {
                                        Ok((read, recvd_flow_id, _flow_id_len)) => {
                                            debug!("got {} bytes of datagram on flow {}", read, flow_id);
                                            assert_eq!(flow_id, recvd_flow_id, "flow id by recv_dgram does not match");
                                            trace!("{}", unsafe {
                                                std::str::from_utf8_unchecked(&buf[..read])
                                            });
                                            let data = &buf[..read];
                                            connect_sockets.get(&flow_id).unwrap().send(data.to_vec()).expect("channel send failed");
                                        },
                                        Err(e) => {
                                            error!("error recv_dgram(): {}", e);
                                            break;
                                        }
                                    }
                                }
                                ()
                            },

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

            _ = interval.tick(), if http3_conn.is_some() && http3_retry_send.is_some() => {
                let mut to_send = http3_retry_send.unwrap();
                let http3_conn = http3_conn.as_mut().unwrap();
                let result = match &to_send.content {
                    Content::Headers { headers } => {
                        debug!("retry sending http3 response {:?}", hdrs_to_strings(&headers));
                        http3_conn.send_response(&mut client.conn, to_send.stream_id, headers, to_send.finished)
                    },
                    Content::Data { data } => {
                        debug!("retry sending http3 data of {} bytes", data.len());
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
                    Content::Datagram { payload } => {
                        debug!("retry sending http3 datagram of {} bytes", payload.len());
                        http3_conn.send_dgram(&mut client.conn, to_send.stream_id, &payload)
                    },
                    Content::Finished => todo!(),
                };
                match result {
                    Ok(_) => {
                        http3_retry_send = None;
                    },
                    Err(quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done) => {
                        debug!("Connection {} stream {} stream blocked, retry later", client.conn.trace_id(), to_send.stream_id);
                        http3_retry_send = Some(to_send);
                    },
                    Err(e) => {
                        error!("Connection {} stream {} send failed {:?}", client.conn.trace_id(), to_send.stream_id, e);
                        client.conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Write, 0);
                        connect_streams.remove(&to_send.stream_id);
                        http3_retry_send = None;
                    }
                };
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

/**
 * Parse pseudo-header path for CONNECT UDP to SocketAddr
 */
fn path_to_socketaddr(path: &[u8]) -> Option<net::SocketAddr> {
    // for now, let's assume path pattern is "/something.../target-host/target-port/"
    let mut split_iter = std::io::BufRead::split(path, b'/');
    let mut second_last = None;
    let mut last = None;
    while let Some(curr) = split_iter.next() {
        if let Ok(curr) = curr {
            second_last = last;
            last = Some(curr);
        } else {
            return None
        }
    }
    if second_last.is_some() && last.is_some() {
        let second_last = second_last.unwrap();
        let last = last.unwrap();
        let second_last = std::str::from_utf8(&second_last);
        let last = std::str::from_utf8(&last);
        if second_last.is_ok() && last.is_ok() {
            let url_str = format!("scheme://{}:{}/", second_last.unwrap(), last.unwrap());
            let url = url::Url::parse(&url_str);
            if let Ok(url) = url {
                let socket_addrs = url.to_socket_addrs();
                if let Ok(mut socket_addrs) = socket_addrs {
                    return socket_addrs.next()
                }
            }
        }
    }

    None
}
