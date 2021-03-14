use std::sync::Arc;

use clap::{App, Arg};
use log::{error, info};
use pretty_env_logger;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};

use socks5::config;
use socks5::config::Server;
use socks5::crypto;
use socks5::socks::TCPRelay;

async fn handle(stream: TcpStream, server: String, secret_key: &Server) -> io::Result<()> {
    let socks5s = TCPRelay::new(server);
    socks5s.serve(stream, secret_key).await
}

#[tokio::main(worker_threads = 10)]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init_timed();

    let matches = App::new("Mika client")
        .version("1.0")
        .author("Sake")
        .about("Network Proxy")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Sets a custom config file")
                .takes_value(true),
        )
        .get_matches();
    let config_path = matches.value_of("config").unwrap_or("mika.cfg");
    let cfg = config::parse_conf(config_path.to_string())?;

    let server = format!("{}:{}", cfg.server[0].address, cfg.server[0].port);
    let key = crypto::evp_bytes_to_key(cfg.server[0].password.clone(), 16);
    let mut server_cfg = cfg.server[0].clone();
    server_cfg.key = key;
    let server_cfg = Arc::new(server_cfg);

    let local = format!("{}:{}", cfg.local[0].address, cfg.local[0].port);
    let listen = TcpListener::bind(&local).await?;
    info!("Server listens at {}.", local);
    loop {
        let (stream, _) = match listen.accept().await {
            Ok(a) => a,
            Err(err) => {
                error!("{}", err);
                return Ok(());
            }
        };
        let _server = server.clone();
        let sk = server_cfg.clone();
        tokio::spawn(async move { handle(stream, _server, &sk).await });
    }
}
