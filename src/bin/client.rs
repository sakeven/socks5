use tokio::net::{TcpListener, TcpStream};

use socks5::socks::TCPRelay;

async fn handle(stream: TcpStream) {
    let socks5 = TCPRelay::new("127.0.0.1:7090".to_string());
    socks5.serve(stream).await;
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = 1080u16;
    let listen = TcpListener::bind(("127.0.0.1", port)).await?;

    println!("Server listens at {}.", port);
    loop {
        let (stream, _) = listen.accept().await?;
        tokio::spawn(async move {
            handle(stream).await;
        });
    }
}
