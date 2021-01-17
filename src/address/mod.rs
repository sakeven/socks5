use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::str;
use std::vec;

use tokio::io;
use tokio::io::AsyncReadExt;

const DEBUG: bool = true;

pub const IPV4_ADDR: u8 = 0x1;
pub const DOMAIN_ADDR: u8 = 0x3;
pub const IPV6_ADDR: u8 = 0x4;

pub const IPV4_LEN: usize = 4;
pub const IPV6_LEN: usize = 16;
// pub const PORT_LEN: usize = 2;

#[derive(Debug)]
pub enum Address {
    SocketAddr(SocketAddr),
    DomainAddr(String, u16),
}

impl ToSocketAddrs for Address {
    type Iter = vec::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> io::Result<vec::IntoIter<SocketAddr>> {
        match self.clone() {
            &Address::SocketAddr(addr) => Ok(vec![addr].into_iter()),
            &Address::DomainAddr(ref host, port) => (&host[..], port).to_socket_addrs(),
        }
    }
}

// +------+----------+----------+
// | ATYP | DST.ADDR | DST.PORT |
// +------+----------+----------+
// |  1   | Variable |    2     |
// +------+----------+----------+
// o  ATYP    address type of following addresses:
// 		o  IP V4 address: X’01’
// 		o  DOMAINNAME: X’03’
// 		o  IP V6 address: X’04’
// o  DST.ADDR		desired destination address
// o  DST.PORT		desired destination port in network octet
// In an address field (DST.ADDR, BND.ADDR), the ATYP field specifies
//    the type of address contained within the field:
//			o  X’01’
//    the address is a version-4 IP address, with a length of 4 octets
// 			o X’03’
//    the address field contains a fully-qualified domain name.  The first
//    octet of the address field contains the number of octets of name that
//    follow, there is no terminating NUL octet.
//			o  X’04’
//    the address is a version-6 IP address, with a length of 16 octets.
pub async fn get_address<T: Unpin + AsyncReadExt>(r: &mut T) -> io::Result<Address> {
    let atyp = r.read_u8().await.unwrap();
    if DEBUG {
        println!("ATYP {}", atyp);
    }

    let raw_addr_len = match atyp {
        IPV4_ADDR => IPV4_LEN,
        DOMAIN_ADDR => r.read_u8().await.unwrap() as usize,
        IPV6_ADDR => IPV6_LEN,
        _ => {
            println!("unsupported address type");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "unsupported address type",
            ));
        }
    };

    if DEBUG {
        println!("len {}", raw_addr_len);
    }

    let mut raw_addr = [0u8; 260];
    let _ = r.read_exact(&mut raw_addr[0..raw_addr_len]).await;

    let port = r.read_u16().await.unwrap();
    if DEBUG {
        println!("Port {}", port);
    }

    match atyp {
        IPV4_ADDR => {
            let ip = Ipv4Addr::new(raw_addr[0], raw_addr[1], raw_addr[2], raw_addr[3]);
            println!("{}", ip);
            Ok(Address::SocketAddr(SocketAddr::V4(SocketAddrV4::new(
                ip, port,
            ))))
        }
        DOMAIN_ADDR => {
            let host = str::from_utf8(&raw_addr[0..raw_addr_len])
                .unwrap()
                .to_string();
            println!("DOMAIN_ADDR {}", host);
            Ok(Address::DomainAddr(host, port))
        }
        IPV6_ADDR => {
            let ip = Ipv6Addr::new(
                raw_addr[0] as u16 * 256 + raw_addr[1] as u16,
                raw_addr[2] as u16 * 256 + raw_addr[3] as u16,
                raw_addr[4] as u16 * 256 + raw_addr[5] as u16,
                raw_addr[6] as u16 * 256 + raw_addr[7] as u16,
                raw_addr[8] as u16 * 256 + raw_addr[9] as u16,
                raw_addr[10] as u16 * 256 + raw_addr[11] as u16,
                raw_addr[12] as u16 * 256 + raw_addr[13] as u16,
                raw_addr[14] as u16 * 256 + raw_addr[15] as u16,
            );
            println!("Ipv6 {}", ip);
            Ok(Address::SocketAddr(SocketAddr::V6(SocketAddrV6::new(
                ip, port, 0, 0,
            ))))
        }
        _ => Err(io::Error::new(io::ErrorKind::Other, "can't parse address")),
    }
}

pub async fn get_raw_address<T: Unpin + AsyncReadExt>(r: &mut T) -> io::Result<Vec<u8>> {
    let atyp = r.read_u8().await.unwrap();
    if DEBUG {
        println!("ATYP {}", atyp);
    }

    let mut raw_addr = [0u8; 260];
    raw_addr[0] = atyp;
    let mut i = 1;
    let raw_addr_len = match atyp {
        IPV4_ADDR => IPV4_LEN,
        DOMAIN_ADDR => {
            let len = r.read_u8().await.unwrap();
            raw_addr[1] = len;
            i = 2;
            len as usize
        }
        IPV6_ADDR => IPV6_LEN,
        _ => {
            println!("unsupported address type");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "unsupported address type",
            ));
        }
    };

    let _ = r.read_exact(&mut raw_addr[i..raw_addr_len + i + 2]).await;
    let a = &raw_addr[..raw_addr_len + i + 2];
    Ok(Vec::from(a))
}
