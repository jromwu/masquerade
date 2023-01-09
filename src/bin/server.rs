use masquerade::server::Server;

use std::env;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    
    let bind_addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4433".to_string());
    
    let server = Server::new(&bind_addr);

    server.run().await
}
