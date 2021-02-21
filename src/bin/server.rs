use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

use socks5::config;
use socks5::crypto;
use socks5::mika::TCPRelay;

async fn handle(stream: TcpStream, secret_key: &Vec<u8>) {
    let mika = TCPRelay::new();
    mika.serve(stream, secret_key).await;
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config::parse_conf().unwrap();
    let local = format!("0.0.0.0:{}", cfg.server[0].port);
    let listen = TcpListener::bind(&local).await?;

    let key = crypto::evp_bytes_to_key(cfg.server[0].password.clone(), 16);
    let secret_key = Arc::new(key);
    println!("Server listens at {}.", local);
    loop {
        let (stream, _) = listen.accept().await?;
        let sk = secret_key.clone();
        tokio::spawn(async move {
            handle(stream, &sk).await;
        });
    }
}
