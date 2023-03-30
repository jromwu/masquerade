use masquerade_proxy::client;
use masquerade_proxy::server;

use log::*;
use tokio::net::{TcpStream, TcpSocket, TcpListener};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::time::timeout;
use std::time::Duration;

mod common;

// TODO: gracefully exit the tests (implement Drop for server and clients)

/**
 * Simple test with single stream in a single QUIC connection. No multiplexing.
 */
#[test_log::test(tokio::test)]
async fn end_to_end_http1_tcp_test() {
    let timeout_duration = Duration::from_secs(5);    

    let (mut client_stream, mut server_stream) = timeout(timeout_duration, common::setup_http1_client()).await.unwrap().unwrap();
    
    let (mut client_stream, mut server_stream) =  common::assert_stream_connected(client_stream, server_stream, 74783).await;
    let (mut client_stream, mut server_stream) = common::assert_stream_connected(server_stream, client_stream, 84783).await;
    let (mut client_stream, mut server_stream) = common::assert_stream_connected(server_stream, client_stream, 84783).await;
    let (mut client_stream, mut server_stream) =  common::assert_stream_connected(client_stream, server_stream, 84783).await;
}

/**
 * Simple test with single stream in a single QUIC connection. No multiplexing.
 */
#[test_log::test(tokio::test)]
async fn end_to_end_socks5_tcp_test() {
    let timeout_duration = Duration::from_secs(5);    

    let (mut client_stream, mut server_stream) = timeout(timeout_duration, common::setup_socks5_tcp_client()).await.unwrap().unwrap();
    
    let (mut client_stream, mut server_stream) =  common::assert_stream_connected(client_stream, server_stream, 74783).await;
    let (mut client_stream, mut server_stream) = common::assert_stream_connected(server_stream, client_stream, 84783).await;
    let (mut client_stream, mut server_stream) = common::assert_stream_connected(server_stream, client_stream, 84783).await;
    let (mut client_stream, mut server_stream) =  common::assert_stream_connected(client_stream, server_stream, 84783).await;
}


/**
 * Simple test with single stream and single flow in a single QUIC connection. No multiplexing.
 */
#[test_log::test(tokio::test)]
async fn end_to_end_socks5_udp_test() {
    let timeout_duration = Duration::from_secs(5);    

    let (client_socket, _client_stream) = timeout(timeout_duration, common::setup_socks5_udp_client()).await.unwrap().unwrap();
    
    common::assert_socks5_socket_connected(&client_socket, 1000).await;
}


