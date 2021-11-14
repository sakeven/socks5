use std::fmt::{Display, Formatter, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::str;
use std::vec;
use url::{Host, Url};

use log::debug;
use tokio::io;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub const IPV4_ADDR: u8 = 0x1;
pub const DOMAIN_ADDR: u8 = 0x3;
pub const IPV6_ADDR: u8 = 0x4;

pub const IPV4_LEN: usize = 4;
pub const IPV6_LEN: usize = 16;

#[derive(Debug)]
pub enum Address {
    SocketAddr(SocketAddr),
    DomainAddr(String, u16),
}

impl Address {
    pub fn is_domain(&self) -> bool {
        match self {
            Address::SocketAddr(_) => false,
            Address::DomainAddr(_, _) => true,
        }
    }

    pub fn domain(&self) -> String {
        match self {
            Address::DomainAddr(host, _) => host.clone(),
            _ => String::new(),
        }
    }

    pub async fn new_conn(self) -> io::Result<TcpStream> {
        return match self {
            Address::SocketAddr(_addr) => TcpStream::connect(_addr).await,
            Address::DomainAddr(ref _host, _port) => TcpStream::connect((&_host[..], _port)).await,
        };
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Address::SocketAddr(addr) => {
                write!(f, "{}", addr)
            }
            Address::DomainAddr(host, port) => match port {
                80 => write!(f, "http://{}", host),
                443 => write!(f, "https://{}", host),
                _ => write!(f, "{}:{}", host, port),
            },
        }
    }
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

    let raw_addr_len = match atyp {
        IPV4_ADDR => IPV4_LEN,
        DOMAIN_ADDR => r.read_u8().await.unwrap() as usize,
        IPV6_ADDR => IPV6_LEN,
        _ => {
            debug!("unsupported address type");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "unsupported address type",
            ));
        }
    };

    let mut raw_addr = [0u8; 260];
    let _ = r.read_exact(&mut raw_addr[0..raw_addr_len]).await;

    let port = r.read_u16().await.unwrap();

    match atyp {
        IPV4_ADDR => {
            let ip = Ipv4Addr::new(raw_addr[0], raw_addr[1], raw_addr[2], raw_addr[3]);
            debug!("{}", ip);
            Ok(Address::SocketAddr(SocketAddr::V4(SocketAddrV4::new(
                ip, port,
            ))))
        }
        DOMAIN_ADDR => {
            let host = str::from_utf8(&raw_addr[0..raw_addr_len])
                .unwrap()
                .to_string();
            debug!("DOMAIN_ADDR {}", host);
            get_address_from_url(host, port)
        }
        IPV6_ADDR => {
            let ip = Ipv6Addr::new(
                u16::from_be_bytes([raw_addr[0], raw_addr[1]]),
                u16::from_be_bytes([raw_addr[2], raw_addr[3]]),
                u16::from_be_bytes([raw_addr[4], raw_addr[5]]),
                u16::from_be_bytes([raw_addr[6], raw_addr[7]]),
                u16::from_be_bytes([raw_addr[8], raw_addr[9]]),
                u16::from_be_bytes([raw_addr[10], raw_addr[11]]),
                u16::from_be_bytes([raw_addr[12], raw_addr[13]]),
                u16::from_be_bytes([raw_addr[14], raw_addr[15]]),
            );
            debug!("Ipv6 {}", ip);
            Ok(Address::SocketAddr(SocketAddr::V6(SocketAddrV6::new(
                ip, port, 0, 0,
            ))))
        }
        _ => Err(io::Error::new(io::ErrorKind::Other, "can't parse address")),
    }
}

// get_address_from_url checks host if is a ipv4 or ipv6 address and returns enum Address.
pub fn get_address_from_url(host: String, port: u16) -> io::Result<Address> {
    let url = Url::parse(format!("https://{}", host).as_str()).unwrap();
    match url.host() {
        Some(Host::Ipv4(ipv4)) => {
            debug!("ipv4 addr");
            Ok(Address::SocketAddr(SocketAddr::new(IpAddr::V4(ipv4), port)))
        }
        Some(Host::Ipv6(ipv6)) => {
            debug!("ipv6 addr");
            Ok(Address::SocketAddr(SocketAddr::new(IpAddr::V6(ipv6), port)))
        }
        _ => {
            debug!("domain");
            Ok(Address::DomainAddr(host, port))
        }
    }
}

pub async fn get_raw_address<T: Unpin + AsyncReadExt>(r: &mut T) -> io::Result<Vec<u8>> {
    let atyp = r.read_u8().await.unwrap();

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

pub fn parse_address_from_vec(ary: &[u8]) -> io::Result<Address> {
    let atyp = ary[0];

    match atyp {
        IPV4_ADDR => {
            let raw_addr = &ary[1..1 + IPV4_LEN];
            let ip = Ipv4Addr::new(raw_addr[0], raw_addr[1], raw_addr[2], raw_addr[3]);
            let port = u16::from_be_bytes([ary[1 + IPV4_LEN], ary[IPV4_LEN + 2]]);
            debug!("{}", ip);
            Ok(Address::SocketAddr(SocketAddr::V4(SocketAddrV4::new(
                ip, port,
            ))))
        }
        DOMAIN_ADDR => {
            let len = ary[1] as usize;
            let raw_addr = &ary[2..2 + len];
            let host = str::from_utf8(&raw_addr).unwrap().to_string();
            let port = u16::from_be_bytes([ary[2 + len], ary[len + 3]]);
            debug!("DOMAIN_ADDR {}", host);
            get_address_from_url(host, port)
        }
        IPV6_ADDR => {
            let raw_addr = &ary[1..1 + IPV6_LEN];
            let port = u16::from_be_bytes([ary[1 + IPV6_LEN], ary[IPV6_LEN + 2]]);
            let ip = Ipv6Addr::new(
                u16::from_be_bytes([raw_addr[0], raw_addr[1]]),
                u16::from_be_bytes([raw_addr[2], raw_addr[3]]),
                u16::from_be_bytes([raw_addr[4], raw_addr[5]]),
                u16::from_be_bytes([raw_addr[6], raw_addr[7]]),
                u16::from_be_bytes([raw_addr[8], raw_addr[9]]),
                u16::from_be_bytes([raw_addr[10], raw_addr[11]]),
                u16::from_be_bytes([raw_addr[12], raw_addr[13]]),
                u16::from_be_bytes([raw_addr[14], raw_addr[15]]),
            );
            debug!("Ipv6 {}", ip);
            Ok(Address::SocketAddr(SocketAddr::V6(SocketAddrV6::new(
                ip, port, 0, 0,
            ))))
        }
        _ => {
            debug!("unsupported address type");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "unsupported address type",
            ));
        }
    }
}
