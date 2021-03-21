use rand::{thread_rng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite, Result};
use tokio::net::TcpStream;

use crate::config::Server;
use crate::crypto::{CryptoReader, CryptoWriter};
use crate::obfs::{ObfsReader, ObfsWriter};

pub struct ServerManager {
    servers: Vec<Server>,
}

impl ServerManager {
    pub fn new(servers: Vec<Server>) -> Self {
        ServerManager { servers }
    }

    fn pick(&self) -> &Server {
        let id = thread_rng().next_u32() as usize % self.servers.len();
        &self.servers[id]
    }

    pub async fn pick_one(
        &self,
    ) -> Result<(
        Box<dyn AsyncWrite + Unpin + Send>,
        Box<dyn AsyncRead + Unpin + Send>,
        String,
    )> {
        let server_cfg = self.pick();

        let server =
            TcpStream::connect(format!("{}:{}", server_cfg.address, server_cfg.port)).await?;
        let server_addr = format!("{}", server.peer_addr()?);

        let (rr, rw) = server.into_split();
        let mut writer: Box<dyn AsyncWrite + Unpin + Send> = Box::new(rw);
        let mut reader: Box<dyn AsyncRead + Unpin + Send> = Box::new(rr);
        if !server_cfg.obfs_url.is_empty() {
            writer = Box::new(ObfsWriter::new(writer, server_cfg.obfs_url.clone()));
            reader = Box::new(ObfsReader::new(reader));
        }

        let sk = server_cfg.key.clone();
        Ok((
            Box::new(CryptoWriter::new(writer, &server_cfg.key)),
            Box::new(CryptoReader::new(reader, &sk)),
            server_addr,
        ))
    }
}
