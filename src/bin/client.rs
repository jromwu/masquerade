use masquerade::client::Client;

use std::env;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let server_name = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4433".to_string());
    
    let bind_addr = env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:8899".to_string());

    let mut client = Client::new(&bind_addr);

    client.run(&server_name).await
}
