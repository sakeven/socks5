// Package socks5 implements socks5 proxy protocol.
use log::{debug, error, info};
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::address;
use crate::config::Policy;
use std::sync::Arc;

pub mod acl;
pub mod server;

const SOCKS_V5: u8 = 0x05;

const CONNECT: u8 = 0x01;
const BIND: u8 = 0x02;
const UDP_ASSOCIATE: u8 = 0x03;

// TCPRelay as a socks5 server and mika client.
pub struct TCPRelay {
    acl_manager: Arc<acl::ACLManager>,
    server_manager: Arc<server::ServerManager>,
}

impl TCPRelay {
    // TCPRelay::new creates a new Socks5 TCPRelay.
    pub fn new(
        acl_manager: Arc<acl::ACLManager>,
        server_manager: Arc<server::ServerManager>,
    ) -> TCPRelay {
        TCPRelay {
            acl_manager,
            server_manager,
        }
    }

    // serve handles connection between socks5 client and remote addr.
    pub async fn serve(mut self, mut conn: TcpStream) -> io::Result<()> {
        self.hand_shake(&mut conn).await?;

        // get cmd and address
        let (cmd, addr) = self.parse_request(&mut conn).await?;
        self.reply(&mut conn).await?;

        match cmd {
            CONNECT => {
                self.connect(conn, addr).await?;
            }
            UDP_ASSOCIATE => self.udp_associate(&mut conn).await,
            BIND => {}
            _ => {}
        }
        Ok(())
    }

    // version identifier/method selection message
    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |    1     | 1 to 255 |
    // +----+----------+----------+
    // reply:
    // +----+--------+
    // |VER | METHOD |
    // +----+--------+
    // |  1 |   1    |
    // +----+--------+
    // hand_shake dail hand_shake between socks5 client and socks5 server.
    async fn hand_shake(&mut self, conn: &mut TcpStream) -> io::Result<()> {
        // get socks version
        let ver = conn.read_u8().await?;
        debug!("Socks version {}", ver);

        if ver != SOCKS_V5 {
            error!("Error version {}", ver);
        }

        // read all method identifier octets
        let nmethods: usize = conn.read_u8().await? as usize;
        debug!("Socks method {}", nmethods);

        let mut raw = [0u8; 257];
        conn.read_exact(&mut raw[2..2 + nmethods]).await?;

        // reply to socks5 client
        conn.write(&[SOCKS_V5, 0x00]).await?;
        Ok(())
    }

    // The SOCKS request is formed as follows:
    //         +----+-----+-------+------+----------+----------+
    //         |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    //         +----+-----+-------+------+----------+----------+
    //         | 1  |  1  | X’00’ |  1   | Variable |    2     |
    //         +----+-----+-------+------+----------+----------+
    // Where:
    //           o  VER    protocol version: X’05’
    //           o  CMD
    //              o  CONNECT X’01’
    //              o  BIND X’02’
    //              o  UDP ASSOCIATE X’03’
    //           o  RSV    RESERVED
    //           o  ATYP   address type of following address
    //              o  IP V4 address: X’01’
    //              o  DOMAINNAME: X’03’
    //              o  IP V6 address: X’04’
    //           o  DST.ADDR       desired destination address
    //           o  DST.PORT desired destination port in network octet order

    // get_cmd gets the cmd requested by socks5 client.
    async fn get_cmd(&mut self, conn: &mut TcpStream) -> io::Result<u8> {
        let ver = conn.read_u8().await?;
        if ver != SOCKS_V5 {
            error!("Error version {}", ver);
        }
        conn.read_u8().await
    }

    // parse_request parses socks5 client request.
    async fn parse_request(&mut self, conn: &mut TcpStream) -> io::Result<(u8, Vec<u8>)> {
        let cmd = self.get_cmd(conn).await?;
        debug!("Cmd {}", cmd);

        // check cmd type
        match cmd {
            CONNECT | BIND | UDP_ASSOCIATE => {}
            _ => {
                error!("unknown cmd type");
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "unsupported address type",
                ));
            }
        }

        // RSV
        conn.read_u8().await?;

        let addr = address::get_raw_address(conn).await?;
        Ok((cmd, addr))
    }

    // returns a reply formed as follows:
    //         +----+-----+-------+------+----------+----------+
    //         |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    //         +----+-----+-------+------+----------+----------+
    //         | 1  |  1  | X’00’ |  1   | Variable |    2     |
    //         +----+-----+-------+------+----------+----------+
    // Where:
    //           o  VER    protocol version: X’05’
    //           o  REP    Reply field:
    //              o  X’00’ succeeded
    //              o  X’01’ general SOCKS server failure
    //              o  X’02’ connection not allowed by ruleset
    //              o  X’03’ Network unreachable
    //              o  X’04’ Host unreachable
    //              o  X’05’ Connection refused
    //              o  X’06’ TTL expired
    //              o  X’07’ Command not supported
    //              o  X’08’ Address type not supported
    //              o  X’09’ to X’FF’ unassigned
    //           o  RSV    RESERVED
    //           o  ATYP   address type of following address
    //              o  IP V4 address: X’01’
    //              o  DOMAINNAME: X’03’
    //              o  IP V6 address: X’04’
    //           o  BND.ADDR       server bound address
    //           o  BND.PORT       server bound port in network octet order
    async fn reply(&mut self, conn: &mut TcpStream) -> io::Result<()> {
        conn.write(&[
            SOCKS_V5,
            0x00,
            0x00,
            address::IPV4_ADDR,
            0x00,
            0x00,
            0x00,
            0x00,
            0x10,
            0x10,
        ])
        .await?;
        Ok(())
    }

    async fn connect(self, mut conn: TcpStream, addr: Vec<u8>) -> io::Result<()> {
        let parsed_addr = address::parse_address_from_vec(&addr)?;

        match self.acl_manager.acl(&parsed_addr) {
            Policy::Direct => {
                info!("directly connect to {}", &parsed_addr);
                let server = parsed_addr.new_conn().await?;
                let (mut cr, mut cw) = conn.into_split();
                let (mut server_reader, mut server_writer) = server.into_split();

                tokio::spawn(async move {
                    let _ = io::copy(&mut server_reader, &mut cw).await;
                });
                let _ = io::copy(&mut cr, &mut server_writer).await;
                Ok(())
            }
            Policy::Reject => conn.shutdown().await,
            Policy::Proxy => self.connect_by_proxy(conn, addr, None).await,
            Policy::ProxyGroup(pg) => self.connect_by_proxy(conn, addr, Some(pg)).await,
        }
    }

    // connect handles CONNECT cmd
    // Here is a bit magic. It acts as a mika client that redirects connection to mika server.
    async fn connect_by_proxy(
        self,
        conn: TcpStream,
        addr: Vec<u8>,
        pg: Option<String>,
    ) -> io::Result<()> {
        let (mut cr, mut cw) = conn.into_split();
        let (mut server_writer, mut server_reader, remote_addr) =
            self.server_manager.pick_one(pg).await?;

        server_writer.write(addr.as_slice()).await?;

        let parsed_addr = address::parse_address_from_vec(&addr)?;
        info!("connect to {} via {}", &parsed_addr, remote_addr);
        tokio::spawn(async move {
            if let Err(e) = io::copy(&mut server_reader, &mut cw).await {
                error!("io remote copy failed {}", e);
            }
        });

        if let Err(e) = io::copy(&mut cr, &mut server_writer).await {
            error!("io client copy failed {}", e);
        }
        Ok(())
    }

    // udp_associate handles UDP_ASSOCIATE cmd
    async fn udp_associate(&mut self, conn: &mut TcpStream) {
        let _ = conn
            .write(&[
                SOCKS_V5,
                0x00,
                0x00,
                address::IPV4_ADDR,
                0x00,
                0x00,
                0x00,
                0x00,
                0x04,
                0x38,
            ])
            .await;
    }
}
