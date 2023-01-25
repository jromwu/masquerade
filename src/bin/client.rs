use masquerade::client::{Http1Client, Socks5Client};

use std::env;
use std::error::Error;
use log::error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::builder().format_timestamp_millis().init();

    let server_name = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4433".to_string());
    
    let bind_addr = env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:8899".to_string());

    let protocol = env::args()
        .nth(3)
        .unwrap_or_else(|| "http".to_string());
    
    match protocol.as_str() {
        "http" => Http1Client::new(&bind_addr).run(&server_name).await,
        "socks5" => Socks5Client::new(&bind_addr).run(&server_name).await,
        _ => {
            error!("not supported protocol");
            Ok(())
        },
    }
}
