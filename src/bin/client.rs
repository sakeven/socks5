use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

use socks5::config;
use socks5::socks::TCPRelay;

async fn handle(stream: TcpStream, server: String, secret_key: &[u8; 32]) {
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
    let secret_key = Arc::new([
        0x29, 0xfa, 0x35, 0x60, 0x88, 0x45, 0xc6, 0xf9, 0xd8, 0xfe, 0x65, 0xe3, 0x22, 0x0e, 0x5b,
        0x05, 0x03, 0x4a, 0xa0, 0x9f, 0x9e, 0x27, 0xad, 0x0f, 0x6c, 0x90, 0xa5, 0x73, 0xa8, 0x10,
        0xe4, 0x94,
    ]);
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
            // println!("{}", _cfg.server[0].port);
            handle(stream, _server, &sk).await;
        });
    }
}
