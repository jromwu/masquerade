use masquerade::client;
use masquerade::server;

use log::*;
use tokio::net::{TcpStream, TcpSocket, TcpListener};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::time::timeout;
use std::time::Duration;

mod common;

#[tokio::test]
async fn end_to_end_http1_test() {
    env_logger::builder().is_test(true).try_init();

    let timeout_duration = Duration::from_secs(5);    

    let (mut client_stream, mut server_stream) = timeout(timeout_duration, common::setup_http1_client()).await.unwrap().unwrap();
    
    let (mut client_stream, mut server_stream) =  common::assert_stream_connected(client_stream, server_stream, 74783).await;
    let (mut client_stream, mut server_stream) = common::assert_stream_connected(server_stream, client_stream, 84783).await;
    let (mut client_stream, mut server_stream) = common::assert_stream_connected(server_stream, client_stream, 84783).await;
    let (mut client_stream, mut server_stream) =  common::assert_stream_connected(client_stream, server_stream, 84783).await;

    // TODO: graceful exit
}



