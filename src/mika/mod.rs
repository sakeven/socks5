#![allow(dead_code)]

// Package socks5 implements socks5 proxy protocol.
use std::pin::Pin;

use tokio::io;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::address;
use crate::crypto::{CryptoReader, CryptoWriter};

const SOCKSV5: u8 = 0x05;
const DEBUG: bool = false;

const CONNECT: u8 = 0x01;
const BIND: u8 = 0x02;
const UDP_ASSOCIATE: u8 = 0x03;

// TCPRelay as a socks5 server and mika client.
pub struct TCPRelay {}

impl TCPRelay {
    // TCPRelay::new creates a new mika instance.
    pub fn new() -> TCPRelay {
        TCPRelay {}
    }

    // serve handles connection between socks5 client and remote addr.
    pub async fn serve(self, conn: TcpStream) {
        self.connect(conn).await;
        println!("serve stopped");
    }

    // The SOCKS request is formed as follows:
    //         +------+----------+----------+
    //         | ATYP | DST.ADDR | DST.PORT |
    //         +------+----------+----------+
    //         |  1   | Variable |    2     |
    //         +------+----------+----------+
    // Where:
    //           o  ATYP   address type of following address
    //              o  IP V4 address: X’01’
    //              o  DOMAINNAME: X’03’
    //              o  IP V6 address: X’04’
    //           o  DST.ADDR       desired destination address
    //           o  DST.PORT desired destination port in network octet order

    // parse_request parses socks5 client request.
    async fn parse_request(&mut self, conn: &mut TcpStream) -> io::Result<address::Address> {
        return address::get_address(Pin::new(conn)).await;
    }

    // connect handles CONNECT cmd
    // Here is a bit magic. It acts as a mika client that redirects conntion to mika server.
    async fn connect(self, conn: TcpStream) {
        let (mut cr, mut cw) = conn.into_split();
        let mut nonce = [0u8; 8];
        cr.read_exact(&mut nonce).await.unwrap();
        let mut client_reader = CryptoReader::new(&mut cr, nonce);

        // get cmd and address
        let addr = address::get_address(Pin::new(&mut client_reader))
            .await
            .unwrap();
        let remote = TCPRelay::new_conn(addr).await;
        let (mut rr, mut rw) = remote.into_split();
        tokio::spawn(async move {
            let mut client_writer = CryptoWriter::new(&mut cw);
            io::copy(&mut rr, &mut client_writer).await
        });
        if let Err(e) = io::copy(&mut client_reader, &mut rw).await {
            println!("io copy failed {}", e);
        }
    }

    async fn new_conn(addr: address::Address) -> TcpStream {
        match addr {
            address::Address::SocketAddr(_addr) => {
                return TcpStream::connect(_addr).await.unwrap();
            }
            address::Address::DomainAddr(ref _host, _port) => {
                return TcpStream::connect((&_host[..], _port)).await.unwrap();
            }
        };
    }
}