use std::error::Error;
use std::time::Duration;

use masquerade::client::{Http1Client, Socks5Client};
use masquerade::server::Server;

use tokio::net::{TcpStream, TcpSocket, TcpListener};
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
pub async fn setup_socks5_client() -> Result<(TcpStream, TcpStream), Box<dyn Error>> {
    // set up a tunnel: first TCP socket <-> listen_addr <--masquerade--> server_addr <-> second TCP socket
    let mut buf = [0; 65535];

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

    let mut handshake: Vec<u8> = vec![5, 1, 0]; // Ask only for no authentication method
    println!("sending handshake:");
    println!("{:02x?}", handshake);
    client_stream.write(&handshake).await?;

    let read = timeout(TIMEOUT_DURATION, client_stream.read(&mut buf)).await??;
    println!("received handshake response:");
    println!("{:02X?}", &buf[..read]);

    assert_eq!(read, 2);
    assert_eq!(&buf[..read], [5, 0], "SOCKS5 no auth not accepted by server");    

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
    let read = timeout(TIMEOUT_DURATION, client_stream.read(&mut buf)).await??;

    println!("received response:");
    println!("{:02X?}", &buf[..read]);
    
    assert!(read > 4, "read SOCKS5 reply too short");
    assert_eq!(buf[1], 0u8, "SOCKS5 reply code not succeeded (0)");
    
    Ok((client_stream, server_stream))
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
        read += read_stream.read(&mut received[read..]).await.unwrap();
    }
    assert_eq!(read, size);

    assert_eq!(received[..read], data_clone);

    let (join_result,) = tokio::join!(write_task);
    let write_stream = join_result.unwrap();
    (write_stream, read_stream)
}
