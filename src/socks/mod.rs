#![allow(dead_code)]

// Package socks5 implements socks5 proxy protocol.
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::address;
use crate::crypto::{CryptoReader, CryptoWriter};

const SOCKSV5: u8 = 0x05;
const DEBUG: bool = false;

const CONNECT: u8 = 0x01;
const BIND: u8 = 0x02;
const UDP_ASSOCIATE: u8 = 0x03;

// TCPRelay as a socks5 server and mika client.
pub struct TCPRelay {
    ss_server: String,
}

impl TCPRelay {
    // TCPRelay::new creates a new Socks5 TCPRelay.
    pub fn new(mika_server: String) -> TCPRelay {
        TCPRelay {
            ss_server: mika_server,
        }
    }

    // serve handles connection between socks5 client and remote addr.
    pub async fn serve(mut self, mut conn: TcpStream, secret_key: &Vec<u8>) {
        self.hand_shake(&mut conn).await;

        // get cmd and address
        let (cmd, addr) = self.parse_request(&mut conn).await.unwrap();
        self.reply(&mut conn).await;

        match cmd {
            CONNECT => {
                self.connect(conn, addr, secret_key).await;
            }
            UDP_ASSOCIATE => self.udp_associate(&mut conn).await,
            BIND => {}
            _ => {}
        }
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
    async fn hand_shake(&mut self, conn: &mut TcpStream) {
        // get socks version
        let ver = conn.read_u8().await.unwrap();
        if DEBUG {
            println!("Socks version {}", ver);
        }

        if ver != SOCKSV5 {
            println!("Error version {}", ver);
        }

        // read all method identifier octets
        let nmethods: usize = conn.read_u8().await.unwrap() as usize;
        if DEBUG {
            println!("Socks method {}", nmethods);
        }

        let mut raw = [0u8; 257];
        let _ = conn.read_exact(&mut raw[2..2 + nmethods]).await;

        // reply to socks5 client
        let _ = conn.write(&[SOCKSV5, 0x00]).await;
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
    async fn get_cmd(&mut self, conn: &mut TcpStream) -> u8 {
        let ver = conn.read_u8().await.unwrap();
        if ver != SOCKSV5 {
            println!("Error version {}", ver);
        }
        return conn.read_u8().await.unwrap();
    }

    // parse_request parses socks5 client request.
    async fn parse_request(&mut self, conn: &mut TcpStream) -> io::Result<(u8, Vec<u8>)> {
        let cmd = self.get_cmd(conn).await;

        if DEBUG {
            println!("Cmd {}", cmd);
        }

        // check cmd type
        match cmd {
            CONNECT | BIND | UDP_ASSOCIATE => {}
            _ => {
                println!("unknow cmd type");
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "unsupported address type",
                ));
            }
        }

        // RSV
        let _ = conn.read_u8().await.unwrap();

        // let addr = address::get_raw_address(Pin::new(conn)).await.unwrap();
        let addr = address::get_raw_address(conn).await.unwrap();
        if DEBUG {
            println!("{:?}", addr);
        }

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
    async fn reply(&mut self, conn: &mut TcpStream) {
        let _ = conn
            .write(&[
                SOCKSV5,
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
            .await;
    }

    // connect handles CONNECT cmd
    // Here is a bit magic. It acts as a mika client that redirects connection to mika server.
    async fn connect(self, conn: TcpStream, addr: Vec<u8>, secret_key: &Vec<u8>) {
        let server = TcpStream::connect(self.ss_server).await.unwrap();
        let (mut cr, mut cw) = conn.into_split();
        let (mut rr, mut rw) = server.into_split();
        let mut server_writer = CryptoWriter::new(&mut rw, secret_key);
        let sk = secret_key.clone();
        server_writer.write(addr.as_slice()).await.unwrap();
        tokio::spawn(async move {
            let mut server_reader = CryptoReader::new(&mut rr, &sk);
            io::copy(&mut server_reader, &mut cw).await
        });
        if let Err(e) = io::copy(&mut cr, &mut server_writer).await {
            println!("io copy failed {}", e);
        }
    }

    // udp_associate handles UDP_ASSOCIATE cmd
    async fn udp_associate(&mut self, conn: &mut TcpStream) {
        let _ = conn
            .write(&[
                SOCKSV5,
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
