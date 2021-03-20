use std::sync::Arc;

use clap::{App, Arg};
use log::{error, info};
use pretty_env_logger;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};

use socks5::config;
use socks5::crypto;
use socks5::socks::acl;
use socks5::socks::server;
use socks5::socks::TCPRelay;

async fn handle(
    stream: TcpStream,
    server_manager: Arc<server::ServerManager>,
    acl_manager: Arc<acl::ACLManager>,
) -> io::Result<()> {
    let socks5s = TCPRelay::new(acl_manager, server_manager);
    socks5s.serve(stream).await
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
    let mut cfg = config::parse_conf(config_path.to_string())?;

    for srv in cfg.server.iter_mut() {
        let key = crypto::evp_bytes_to_key(srv.password.clone(), 16);
        srv.key = key
    }

    let acl_manager = Arc::new(acl::ACLManager::new(cfg.acl_cfg));
    let server_manager = Arc::new(server::ServerManager::new(cfg.server));

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
        let sk = server_manager.clone();
        let acl_manager = acl_manager.clone();
        tokio::spawn(async move { handle(stream, sk, acl_manager).await });
    }
}
