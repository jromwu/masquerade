use std::error::Error;
use std::net::Ipv4Addr;
use std::time::Duration;

use masquerade::client::{Http1Client, Socks5Client};
use masquerade::server::Server;

use tokio::net::unix::SocketAddr;
use tokio::net::{TcpStream, TcpSocket, TcpListener, UdpSocket};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::time::timeout;
use rand::RngCore;

pub const TIMEOUT_DURATION: Duration = Duration::from_secs(5);

pub async fn setup_http1_client() -> Result<(TcpStream, TcpStream), Box<dyn Error>> {
    // set up a tunnel: first TCP socket <-> listen_addr <--masquerade--> server_addr <-> second TCP socket

    let mut server = Server::new();
    server.bind("127.0.0.1:0").await?;
    let server_addr = server.listen_addr().unwrap();

    let mut client = Http1Client::new();
    client.bind("127.0.0.1:0").await?;
    let listen_addr = client.listen_addr().unwrap();

    let server_task = tokio::spawn(async move {
        server.run().await;
    });
    let client_task = tokio::spawn(async move {
        client.run(&server_addr.to_string()).await;
    });

    let socket = TcpSocket::new_v4()?;
    let mut client_stream = socket.connect(listen_addr).await?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let peer_addr = listener.local_addr().unwrap();

    let request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", peer_addr, peer_addr);
    println!("sending request:");
    println!("{}", request);

    client_stream.write(request.as_bytes()).await?;

    let (server_stream, client_addr) = listener.accept().await?;

    let mut buf = [0; 65535];
    let mut read = 0;
    
    loop {
        read += timeout(TIMEOUT_DURATION, client_stream.read(&mut buf[read..])).await??;
        
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut res = httparse::Response::new(&mut headers);
        let status = res.parse(&buf[..read]).unwrap();
        if status.is_complete() {
            assert!(res.code.is_some());
            assert!(res.code.unwrap() < 300 && res.code.unwrap() >= 200);
            break
        }
    };

    println!("received response:");
    println!("{}", std::str::from_utf8(&buf[..read]).unwrap());
    
    Ok((client_stream, server_stream))
}


/**
 * SOCKS5 version identifier/method selection message:
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     | 1 to 255 |
        +----+----------+----------+
 * SOCKS5 request format:
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
 * Example CONNECT request to 127.0.0.1:8899 (in hex):
        +----+-----+-----+------+-------------+----------+
        |VER | CMD | RSV | ATYP |  DST.ADDR   | DST.PORT |
        +----+-----+-----+------+-------------+----------+
        | 05 | 01  | 00  |  01  | 7f 00 00 01 |  22 c3   |
        +----+-----+-----+------+-------------+----------+
 */
pub async fn setup_socks5_tcp_client() -> Result<(TcpStream, TcpStream), Box<dyn Error>> {
    // set up a tunnel: first TCP socket <-> listen_addr <--masquerade--> server_addr <-> second TCP socket
    let mut server = Server::new();
    server.bind("127.0.0.1:0").await?;
    let server_addr = server.listen_addr().unwrap();

    let mut client = Socks5Client::new();
    client.bind("127.0.0.1:0").await?;
    let listen_addr = client.listen_addr().unwrap();

    let server_task = tokio::spawn(async move {
        server.run().await;
    });
    let client_task = tokio::spawn(async move {
        client.run(&server_addr.to_string()).await;
    });

    let socket = TcpSocket::new_v4()?;
    let mut client_stream = socket.connect(listen_addr).await?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let peer_addr = listener.local_addr().unwrap();

    socks5_handshake_no_auth(&mut client_stream).await?;

    let mut request: Vec<u8> = vec![5, 1, 0, 1];
    let mut peer_ip = match peer_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        std::net::IpAddr::V6(_) => unreachable!(),
    }.to_vec();
    let mut peer_port = peer_addr.port().to_be_bytes().to_vec();
    request.append(&mut peer_ip);
    request.append(&mut peer_port);

    println!("sending request:");
    println!("{:02x?}", request);
    client_stream.write(&request).await?;

    let (server_stream, client_addr) = listener.accept().await?;
    let mut buf = [0; 65535];
    let mut read = 0;
    while read < 6 { // we are expecting a reply of at least 6 bytes
        read += timeout(TIMEOUT_DURATION, client_stream.read(&mut buf[read..])).await??;
    } 

    println!("received response:");
    println!("{:02X?}", &buf[..read]);
    
    assert_eq!(buf[1], 0u8, "socks5 reply code not succeeded (0)");
    
    Ok((client_stream, server_stream))
}

pub async fn setup_socks5_udp_client() -> Result<UdpSocket, Box<dyn Error>> {
    // set up a tunnel: local UDP socket <-> bind_addr <--masquerade--> server_addr <-> remote UDP socket
    // note: SOCKS5 does not proxy UDP packets as it is. It requires a header attached to packets in/out the local socket
    let mut server = Server::new();
    server.bind("127.0.0.1:0").await?;
    let server_addr = server.listen_addr().unwrap();

    let mut client = Socks5Client::new();
    client.bind("127.0.0.1:0").await?;
    let listen_addr = client.listen_addr().unwrap();

    let server_task = tokio::spawn(async move {
        server.run().await;
    });
    let client_task = tokio::spawn(async move {
        client.run(&server_addr.to_string()).await;
    });

    let socket = TcpSocket::new_v4()?;
    let mut client_stream = socket.connect(listen_addr).await?;

    socks5_handshake_no_auth(&mut client_stream).await?;

    let mut request: Vec<u8> = vec![5, 3, 0, 1, 0, 0, 0, 0, 0, 0];

    println!("sending request:");
    println!("{:02x?}", request);
    client_stream.write(&request).await?;

    let mut buf = [0; 65535];
    let mut read = 0;
    while read < 10 { // we are expecting a reply of at least 10 bytes
        read += timeout(TIMEOUT_DURATION, client_stream.read(&mut buf[read..])).await??;
    }

    println!("received response:");
    println!("{:02X?}", &buf[..read]);
    
    assert_eq!(buf[1], 0u8, "socks5 reply code not succeeded (0)");

    // assume socks5 reply only gives an ipv4 address to bind to 
    assert_eq!(buf[3], 1u8, "socks5 reply address type not ipv4");

    let bind_ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
    let bind_port = ((buf[8] as u16) << 8) | (buf[9] as u16);
    let local_socket = UdpSocket::bind("127.0.0.1:0").await?;
    local_socket.connect((bind_ip, bind_port)).await?;
    
    Ok(local_socket)
}

async fn socks5_handshake_no_auth(stream: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    let mut buf = [0; 65535];
    let mut handshake: Vec<u8> = vec![5, 1, 0]; // Ask only for no authentication method
    println!("sending socks5 handshake:");
    println!("{:02x?}", handshake);
    stream.write(&handshake).await?;

    let mut read = 0;
    while read < 2 { // we are expecting a reply of two bytes
        read += timeout(TIMEOUT_DURATION, stream.read(&mut buf[read..])).await??;
    } 
    println!("received socks5 handshake response:");
    println!("{:02X?}", &buf[..read]);

    assert_eq!(read, 2);
    assert_eq!(&buf[..read], [5, 0], "socks5 no auth not accepted by server");

    Ok(())
}

pub async fn assert_stream_connected(mut write_stream: TcpStream, mut read_stream: TcpStream, size: usize) -> (TcpStream, TcpStream) {
    let mut data = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut data);
    let data_clone = data.clone();
    let mut received = vec![0u8; size + 1];
    
    let write_task = tokio::spawn(async move {
        let mut written = 0;
        while written < data.len() {
            written += write_stream.write(&data[written..]).await.unwrap();
        }
        assert_eq!(written, data.len());
        write_stream
    });

    let mut read = 0;
    while read < size {
        read += timeout(TIMEOUT_DURATION, read_stream.read(&mut received[read..])).await.unwrap().unwrap();
    }
    assert_eq!(read, size);

    assert_eq!(received[..read], data_clone);

    let (join_result,) = tokio::join!(write_task);
    let write_stream = join_result.unwrap();
    (write_stream, read_stream)
}

/**
 * This is assuming that UDP sockets does not drop packets (for loopback)
 * 
 * SOCKS5 UDP request header:
 *    +----+------+------+----------+----------+----------+
      |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
      +----+------+------+----------+----------+----------+
      | 2  |  1   |  1   | Variable |    2     | Variable |
      +----+------+------+----------+----------+----------+
 */
pub async fn assert_socks5_socket_connected(local_socket: &UdpSocket, size: usize) {
    let mut data = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut data);

    let remote_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote_socket.local_addr().unwrap();

    let mut request: Vec<u8> = vec![0, 0, 0, 1];
    let mut remote_ip = match remote_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        std::net::IpAddr::V6(_) => unreachable!(),
    }.to_vec();
    let mut remote_port = remote_addr.port().to_be_bytes().to_vec();
    request.append(&mut remote_ip);
    request.append(&mut remote_port);
    request.append(&mut data.clone());

    println!("local: sending packet:");
    println!("{:02x?}", request);
    local_socket.send(&request).await.unwrap();

    let mut buf = [0; 65535];
    let (read, peer_addr) = timeout(TIMEOUT_DURATION, remote_socket.recv_from(&mut buf)).await.unwrap().unwrap();
    println!("remote: received packet:");
    println!("{:02x?}", &buf[..read]);

    assert_eq!(data.len(), read, "data length not match");
    assert_eq!(&data, &buf[..read], "data content not match");
    
    rand::thread_rng().fill_bytes(&mut data);
    println!("remote: sending packet:");
    println!("{:02x?}", data);
    remote_socket.send_to(&data, peer_addr).await.unwrap();

    let read = timeout(TIMEOUT_DURATION, local_socket.recv(&mut buf)).await.unwrap().unwrap();
    println!("local: received packet:");
    println!("{:02x?}", &buf[..read]);

    assert!(read > 10, "read length too small to a socks5 header");
    // assume the address in the header is ipv4, so header is 10 bytes
    let udp_request_header = &buf[..10];
    let payload = &buf[udp_request_header.len()..read];

    assert_eq!(data.len(), payload.len(), "data length not match");
    assert_eq!(&data, payload, "data content not match");
    
}
