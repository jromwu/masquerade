use std::error::Error;
use std::time::Duration;

use masquerade::client::Client;
use masquerade::server::Server;

use log::*;
use tokio::net::{TcpStream, TcpSocket, TcpListener};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::time::timeout;
use rand::RngCore;

pub const TIMEOUT_DURATION: Duration = Duration::from_secs(5);

pub async fn setup() -> Result<(TcpStream, TcpStream), Box<dyn Error>> {
    // set up a tunnel: first TCP socket <-> listen_addr <--masquerade--> server_addr <-> second TCP socket

    let listen_addr = "127.0.0.1:8899".to_string();
    let server_addr = "127.0.0.1:4433".to_string();

    let mut server = Server::new(&server_addr);
    server.bind().await?;

    let mut client = Client::new(&listen_addr);
    client.bind().await?;

    let server_task = tokio::spawn(async move {
        server.run().await;
    });
    let client_task = tokio::spawn(async move {
        client.run(&server_addr).await;
    });

    let socket = TcpSocket::new_v4()?;
    let mut client_stream = socket.connect(listen_addr.parse().unwrap()).await?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let peer_addr = listener.local_addr().unwrap();

    let request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", peer_addr, peer_addr);
    debug!("sending request:");
    debug!("{}", request);

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

    debug!("received response:");
    debug!("{}", std::str::from_utf8(&buf[..read]).unwrap());
    
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
