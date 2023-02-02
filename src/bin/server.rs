use masquerade::server::Server;

use std::env;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::builder().format_timestamp_millis().init();
    
    let bind_addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4433".to_string());
    
    let mut server = Server::new();
    server.bind(bind_addr).await?;

    server.run().await
}
