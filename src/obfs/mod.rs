use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use base64;
use bstr::ByteSlice;
use futures::ready;
use rand::RngCore;
use tokio::io;
use tokio::io::ReadBuf;

struct Obfs {
    init: bool,
    host: String,
}

impl Obfs {
    fn new(host: String) -> Self {
        Obfs { init: false, host }
    }
    fn obfs_http_request(&mut self, len: usize) -> String {
        if self.init {
            return "".to_string();
        }
        self.init = true;

        let mut rng = rand::thread_rng();

        let mut str = format!("{} {} HTTP/1.1\r\n", "GET", "/");
        str += &format!("Host: {}\r\n", self.host);
        str += &format!(
            "User-Agent: curl/7.{}.{}\r\n",
            rng.next_u32() % 54,
            rng.next_u32() % 2
        );
        str += &format!("Upgrade: websocket\r\n");
        str += &format!("Connection: Upgrade\r\n");

        let mut key = [0u8; 16];
        rng.fill_bytes(&mut key);
        let b64_url = base64::encode_config(key, base64::URL_SAFE);

        str += &format!("Sec-WebSocket-Key: {}\r\n", b64_url);
        str += &format!("Content-Length: {}\r\n\r\n", len);
        return str.to_string();
    }

    #[allow(dead_code)]
    fn obfs_http_response(&mut self) -> String {
        if self.init {
            return "".to_string();
        }
        self.init = true;

        let mut str = format!("HTTP/1.1 101 Switching Protocols\r\n");
        str += &format!("Server: nginx/1.{}.{}\r\n", 1, 2);
        str += &format!("Date: {}\r\n", "2020-01-12");
        str += &format!("Upgrade: websocket\r\n");
        str += &format!("Connection: Upgrade\r\n");
        str += &format!("Sec-WebSocket-Accept: {}\r\n", "abc");
        str += &format!("\r\n").to_string();
        return str.to_string();
    }
}

pub struct ObfsWriter<T>
where
    T: io::AsyncWrite + std::marker::Unpin,
{
    writer: T,
    inited: bool,
    obfs: Obfs,
}

impl<T> ObfsWriter<T>
where
    T: io::AsyncWrite + std::marker::Unpin,
{
    pub fn new(writer: T) -> ObfsWriter<T> {
        ObfsWriter {
            writer,
            inited: false,
            obfs: Obfs::new("baidu.com".to_string()),
        }
    }
}

impl<T> io::AsyncWrite for ObfsWriter<T>
where
    T: io::AsyncWrite + std::marker::Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let this = Pin::into_inner(self);

        if !this.inited {
            ready!(Pin::new(&mut this.writer)
                .poll_write(cx, this.obfs.obfs_http_request(buf.len()).as_bytes()))?;
            this.inited = true;
        }

        ready!(Pin::new(&mut this.writer).poll_write(cx, buf))?;
        Ok(buf.len()).into()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut Pin::into_inner(self).writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut Pin::into_inner(self).writer).poll_shutdown(cx)
    }
}

pub struct ObfsReader<T>
where
    T: io::AsyncRead + std::marker::Unpin,
{
    reader: T,
    buf: [u8; MAX_BUF_LEN],
    size: usize,
    pos: usize,
    inited: bool,
}

const MAX_BUF_LEN: usize = 256;

impl<T> ObfsReader<T>
where
    T: io::AsyncRead + std::marker::Unpin,
{
    pub fn new(reader: T) -> ObfsReader<T> {
        ObfsReader {
            reader,
            buf: [0; MAX_BUF_LEN],
            size: 0,
            pos: 0,
            inited: false,
        }
    }

    fn poll_read_http_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let last = self.size;
            let mut read_buf = ReadBuf::new(&mut self.buf[self.size..]);
            ready!(Pin::new(&mut self.reader).poll_read(cx, &mut read_buf)?);
            self.size += read_buf.filled().len();
            if self.size == last {
                return Err(ErrorKind::UnexpectedEof.into()).into();
            }
            let idx = self.buf[..self.size].find("\r\n\r\n");
            if idx.is_some() {
                self.pos = idx.unwrap() + 4;
                break;
            }
        }
        return Ok(()).into();
    }
}

impl<T> io::AsyncRead for ObfsReader<T>
where
    T: io::AsyncRead + std::marker::Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = Pin::into_inner(self);

        if !this.inited {
            ready!(this.poll_read_http_response(cx))?;
            this.inited = true;
        }

        if this.pos < this.size {
            let len = usize::min(buf.remaining(), this.buf[this.pos..this.size].len());
            buf.put_slice(&(this.buf[this.pos..this.pos + len]));
            this.pos += len;
            return Ok(()).into();
        }

        Pin::new(&mut this.reader).poll_read(cx, buf)
    }
}
