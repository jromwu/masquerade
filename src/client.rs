use log::*;

use quiche;
use quiche::h3::{NameValue, Header};
use ring::rand::*;

use std::net::{ToSocketAddrs, SocketAddr};
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::net::{UdpSocket, TcpStream, TcpListener};
use tokio::sync::mpsc::{self, UnboundedSender, UnboundedReceiver};
use tokio::time;

use crate::common::*;

#[derive(Debug)]
enum Content {
    Request {
        headers: Vec<quiche::h3::Header>,
        stream_id_sender: mpsc::Sender<u64>,
    },
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
struct ToSend {
    stream_id: u64, // or flow_id for DATAGRAM
    content: Content,
    finished: bool,
}

pub struct Client {
    bind_addr: String,
    listener: Option<TcpListener>,
}

impl Client {
    pub fn new(bind_addr: &String) -> Client {
        Client { bind_addr: bind_addr.clone(), listener: None }
    }

    pub async fn bind(&mut self) -> Result<(), Box<dyn Error>> {
        debug!("creating TCP listener");

        let mut listener = TcpListener::bind(self.bind_addr.clone().parse::<SocketAddr>().unwrap()).await?;
        self.listener = Some(listener);

        debug!("listening on {}", self.bind_addr);
        Ok(())
    }
    
    pub async fn run(&mut self, server_addr: &String) -> Result<(), Box<dyn Error>> {
        if self.listener.is_none() {
            self.bind().await?;
        }
        let listener = self.listener.as_mut().unwrap();

        let server_name = format!("https://{}", server_addr);
    
        // Resolve server address.
        let url = url::Url::parse(&server_name).unwrap();
        let peer_addr = url.to_socket_addrs().unwrap().next().unwrap();
        
        debug!("creating socket");
        let socket = UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).await?;
        socket.connect(peer_addr.clone()).await?;
        let socket = Arc::new(socket);
        debug!("connecting to {} at {}", server_name, peer_addr);
        
    
        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];
    
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
        while let Err(e) = socket.send_to(&out[..write], send_info.to).await {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                debug!("send_to() would block");
                continue;
            }
            panic!("UDP socket send_to() failed: {:?}", e);
        }
        debug!("written {}", write);
    
        let mut http3_conn: Option<quiche::h3::Connection> = None;
        let (http3_sender, mut http3_receiver) = mpsc::unbounded_channel::<ToSend>();
        let connect_streams: Arc<Mutex<HashMap<u64, UnboundedSender<Content>>>> = Arc::new(Mutex::new(HashMap::new()));
        let mut http3_retry_send: Option<ToSend> = None;
        let mut interval = time::interval(Duration::from_millis(20));
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        loop {
            if conn.is_closed() {
                info!("connection closed, {:?}", conn.stats());
                break;
            }
    
            tokio::select! {
                recvd = socket.recv_from(&mut buf) => {
                    let (read, from) = match recvd {
                        Ok(v) => v,
                        Err(e) => {
                            error!("error when reading from UDP socket");
                            continue
                        },
                    };
                    debug!("received {} bytes", read);
                    let recv_info = quiche::RecvInfo {
                        to: local_addr,
                        from,
                    };
    
                    // Process potentially coalesced packets.
                    let read = match conn.recv(&mut buf[..read], recv_info) {
                        Ok(v) => v,
    
                        Err(e) => {
                            error!("QUIC recv failed: {:?}", e);
                            continue
                        },
                    };
                    debug!("processed {} bytes", read);
    
                    if let Some(http3_conn) = &mut http3_conn {
                        // Process HTTP/3 events.
                        loop {
                            match http3_conn.poll(&mut conn) {
                                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                                    info!("got response headers {:?} on stream id {}", hdrs_to_strings(&list), stream_id);
                                    let connect_streams = connect_streams.lock().unwrap();
                                    if let Some(sender) = connect_streams.get(&stream_id) {
                                        sender.send(Content::Headers { headers: list });
                                    }
                                },
            
                                Ok((stream_id, quiche::h3::Event::Data)) => {
                                    let connect_streams = connect_streams.lock().unwrap();
                                    if let Some(sender) = connect_streams.get(&stream_id) {
                                        while let Ok(read) = http3_conn.recv_body(&mut conn, stream_id, &mut buf) {
                                            debug!("got {} bytes of response data on stream {}", read, stream_id);
                                            trace!("{}", unsafe {std::str::from_utf8_unchecked(&buf[..read])});
                                            sender.send(Content::Data { data: buf[..read].to_vec() });
                                        }
                                    }
                                },
            
                                Ok((stream_id, quiche::h3::Event::Finished)) => {
                                    info!("finished received, stream id: {} closing", stream_id);
                                    let connect_streams = connect_streams.lock().unwrap();
                                    if let Some(sender) = connect_streams.get(&stream_id) {
                                        sender.send(Content::Finished {});
                                    }
                                },
            
                                Ok((stream_id, quiche::h3::Event::Reset(e))) => {
                                    error!("request was reset by peer with {}, stream id: {} closed", e, stream_id);
                                    let connect_streams = connect_streams.lock().unwrap();
                                    if let Some(sender) = connect_streams.get(&stream_id) {
                                        sender.send(Content::Finished {});
                                    }
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
                },
                http3_to_send = http3_receiver.recv(), if http3_conn.is_some() && http3_retry_send.is_none() => {
                    if http3_to_send.is_none() {
                        unreachable!()
                    }
                    let mut to_send = http3_to_send.unwrap();
                    let http3_conn = http3_conn.as_mut().unwrap();
                    loop {
                        let result = match &to_send.content {
                            Content::Headers { .. } => unreachable!(),
                            Content::Request { headers, stream_id_sender } => {
                                debug!("sending http3 request {:?}", hdrs_to_strings(&headers));
                                match http3_conn.send_request(&mut conn, headers, to_send.finished) {
                                    Ok(stream_id) => {
                                        stream_id_sender.send(stream_id).await;
                                        Ok(())
                                    },
                                    Err(e) => {
                                        error!("http3 request send failed");
                                        Err(e)
                                    },
                                }
                            },
                            Content::Data { data } => {
                                debug!("sending http3 data of {} bytes", data.len());
                                let mut written = 0;
                                loop {
                                    if written >= data.len() {
                                        break Ok(())
                                    }
                                    match http3_conn.send_body(&mut conn, to_send.stream_id, &data[written..], to_send.finished) {
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
                                debug!("Connection {} stream {} stream blocked, retry later", conn.trace_id(), to_send.stream_id);
                                http3_retry_send = Some(to_send);
                                break; 
                            },
                            Err(e) => {
                                error!("Connection {} stream {} send failed {:?}", conn.trace_id(), to_send.stream_id, e);
                                conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Write, 0);
                                {
                                    let mut connect_streams = connect_streams.lock().unwrap();
                                    connect_streams.remove(&to_send.stream_id);
                                }
                            }
                        };
                        to_send = match http3_receiver.try_recv() {
                            Ok(v) => v,
                            Err(e) => break,
                        };
                    }
                },
                tcp_accepted = listener.accept() => {
                    match tcp_accepted {
                        Ok((tcp_socket, addr)) => {
                            debug!("accepted connection from {}", addr);
                            tokio::spawn(handle_stream(tcp_socket, http3_sender.clone(), connect_streams.clone()));
                        },
                        Err(_) => todo!(),
                    };
                },

                _ = interval.tick(), if http3_conn.is_some() && http3_retry_send.is_some() => {
                    let mut to_send = http3_retry_send.unwrap();
                    let http3_conn = http3_conn.as_mut().unwrap();
                    let result = match &to_send.content {
                        Content::Headers { .. } => unreachable!(),
                        Content::Request { headers, stream_id_sender } => {
                            debug!("retry sending http3 request {:?}", hdrs_to_strings(&headers));
                            match http3_conn.send_request(&mut conn, headers, to_send.finished) {
                                Ok(stream_id) => {
                                    stream_id_sender.send(stream_id).await;
                                    Ok(())
                                },
                                Err(e) => {
                                    error!("http3 request send failed");
                                    Err(e)
                                },
                            }
                        },
                        Content::Data { data } => {
                            debug!("retry sending http3 data of {} bytes", data.len());
                            let mut written = 0;
                            loop {
                                if written >= data.len() {
                                    break Ok(())
                                }
                                match http3_conn.send_body(&mut conn, to_send.stream_id, &data[written..], to_send.finished) {
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
                        Ok(_) => {
                            http3_retry_send = None;
                        },
                        Err(quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done) => {
                            debug!("Connection {} stream {} stream blocked, retry later", conn.trace_id(), to_send.stream_id);
                            http3_retry_send = Some(to_send);
                        },
                        Err(e) => {
                            error!("Connection {} stream {} send failed {:?}", conn.trace_id(), to_send.stream_id, e);
                            conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Write, 0);
                            {
                                let mut connect_streams = connect_streams.lock().unwrap();
                                connect_streams.remove(&to_send.stream_id);
                            }
                            http3_retry_send = None;
                        }
                    };
                },
    
                else => break,
            }
            
            // Create a new HTTP/3 connection once the QUIC connection is established.
            if conn.is_established() && http3_conn.is_none() {
                let h3_config = quiche::h3::Config::new().unwrap();
                http3_conn = Some(
                    quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
                );
            }
            loop {
                let (write, send_info) = match conn.send(&mut out) {
                    Ok(v) => v,
    
                    Err(quiche::Error::Done) => {
                        debug!("QUIC connection {} done writing", conn.trace_id());
                        break;
                    },
    
                    Err(e) => {
                        error!("QUIC connection {} send failed: {:?}", conn.trace_id(), e);
    
                        conn.close(false, 0x1, b"fail").ok();
                        break;
                    },
                };
    
                match socket.send_to(&out[..write], send_info.to).await {
                    Ok(written) => debug!("{} written {} bytes out of {}", conn.trace_id(), written, write),
                    Err(e) => panic!("UDP socket send_to() failed: {:?}", e),
                }
            }
    
        }
    
        Ok(())
    }
}

async fn handle_stream(mut stream: TcpStream, http3_sender: UnboundedSender<ToSend>, connect_streams: Arc<Mutex<HashMap<u64, UnboundedSender<Content>>>>) {
    let mut buf = [0; 65535];
    let mut pos = match stream.read(&mut buf).await {
        Ok(v) => v,
        Err(e) => {
            error!("Error reading from TCP stream: {}", e);
            return
        },
    }; // TODO: change this to a read loop
    loop {
        match stream.try_read(&mut buf[pos..]) {
            Ok(read) => pos += read,
            Err(ref e) if would_block(e) => break,
            Err(ref e) if interrupted(e) => continue,
            Err(e) => {
                error!("Error reading from TCP stream: {}", e);
                return
            }
        };
    }
    let peer_addr = stream.peer_addr().unwrap();

    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut req = httparse::Request::new(&mut headers);
    let res = req.parse(&buf[..pos]).unwrap();
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
                let (stream_id_sender, mut stream_id_receiver) = mpsc::channel(1);
                let (response_sender, mut response_receiver) = mpsc::unbounded_channel::<Content>();
                http3_sender.send(ToSend { content: Content::Request { headers, stream_id_sender }, finished: false, stream_id: 0});
                let stream_id = stream_id_receiver.recv().await.expect("stream_id receiver error");
                {
                    let mut connect_streams = connect_streams.lock().unwrap();
                    connect_streams.insert(stream_id, response_sender); 
                    // TODO: potential race condition: the response could be received before connect_streams is even inserted and get dropped
                }

                let response = response_receiver.recv().await.expect("http3 response receiver error");
                if let Content::Headers { headers } = response {
                    info!("Got response {:?}", hdrs_to_strings(&headers));
                    let mut status = None;
                    for hdr in headers {
                        match hdr.name() {
                            b":status" => status = Some(hdr.value().to_owned()),
                            _ => (),
                        }
                    }
                    if let Some(status) = status {
                        if let Ok(status_str) = std::str::from_utf8(&status) {
                            if let Ok(status_code) = status_str.parse::<i32>() {
                                if status_code >= 200 && status_code < 300 {
                                    info!("connection established, sending 200 OK");
                                    stream.write(&b"HTTP/1.1 200 OK\r\n\r\n".to_vec()).await;
                                }
                            }
                        }
                    }
                } else {
                    error!("received others when expecting headers for connect");
                }

                let (mut read_half, mut write_half) = stream.into_split();
                let http3_sender_clone = http3_sender.clone();
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
                        http3_sender_clone.send(ToSend { stream_id: stream_id, content: Content::Data { data: buf[..read].to_vec() }, finished: false });
                    }
                });
                let write_task = tokio::spawn(async move {
                    loop {
                        let data = match response_receiver.recv().await {
                            Some(v) => v,
                            None => {
                                debug!("TCP receiver channel closed for stream {}", stream_id);
                                break
                            },
                        };
                        match data {
                            Content::Request { headers, stream_id_sender } => unreachable!(),
                            Content::Headers { .. } => unreachable!(),
                            Content::Data { data } => {
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
                            },
                            Content::Datagram => todo!(),
                            Content::Finished => todo!(),
                        };
                        
                    }
                });
                tokio::join!(read_task, write_task);
                
                {
                    let mut connect_streams = connect_streams.lock().unwrap();
                    connect_streams.remove(&stream_id);
                }
                return
            }
        }
    }
    stream.write(&b"HTTP/1.1 400 Bad Request\r\n\r\n".to_vec()).await;
}
