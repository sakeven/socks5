#![allow(dead_code)]

// Package mika implements ss proxy protocol.
use tokio::io;
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
    pub async fn serve(self, conn: TcpStream, secret_key: &Vec<u8>) {
        let (mut cr, mut cw) = conn.into_split();
        let mut client_reader = CryptoReader::new(&mut cr, &secret_key);

        // get cmd and address
        let addr = address::get_address(&mut client_reader).await.unwrap();
        let remote = addr.new_conn().await.unwrap();
        let (mut rr, mut rw) = remote.into_split();
        let sk = secret_key.clone();
        tokio::spawn(async move {
            let mut client_writer = CryptoWriter::new(&mut cw, &sk);
            io::copy(&mut rr, &mut client_writer).await
        });
        if let Err(e) = io::copy(&mut client_reader, &mut rw).await {
            println!("io copy failed {}", e);
            return;
        }
    }
}
