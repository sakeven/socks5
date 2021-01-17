use tokio::net::{TcpListener, TcpStream};

use socks5::mika::TCPRelay;

async fn handle(stream: TcpStream) {
    let mika = TCPRelay::new();
    mika.serve(stream).await;
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = 7090u16;
    let listen = TcpListener::bind(("0.0.0.0", port)).await?;

    println!("Server listens at {}.", port);
    loop {
        let (stream, _) = listen.accept().await?;
        tokio::spawn(async move {
            handle(stream).await;
        });
    }
}
