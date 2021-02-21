use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

use socks5::config;
use socks5::crypto;
use socks5::socks::TCPRelay;

async fn handle(stream: TcpStream, server: String, secret_key: &Vec<u8>) {
    let socks5s = TCPRelay::new(server);
    socks5s.serve(stream, secret_key).await;
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Arc::new(config::parse_conf()?);

    let local = format!("{}:{}", cfg.local[0].address, cfg.local[0].port);
    let listen = TcpListener::bind(&local).await?;
    let server = format!("{}:{}", cfg.server[0].address, cfg.server[0].port);
    println!("Server listens at {}.", local);

    let key = crypto::evp_bytes_to_key(cfg.server[0].password.clone(), 16);
    let secret_key = Arc::new(key);
    loop {
        let (stream, _) = match listen.accept().await {
            Ok(a) => a,
            Err(err) => {
                println!("{}", err);
                return Ok(());
            }
        };
        let _server = server.clone();
        let _cfg = cfg.clone();
        let sk = secret_key.clone();
        tokio::spawn(async move {
            handle(stream, _server, &sk).await;
        });
    }
}
