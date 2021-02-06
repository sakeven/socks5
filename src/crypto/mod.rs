mod ase;
mod chacha0;
mod interface;

use core::pin::Pin;
use core::task::Context;
use core::task::Poll;
use std::io::{Error, ErrorKind};

use futures::ready;
use tokio::io;
use tokio::io::ReadBuf;

const USE_CHACHA: bool = false;

pub struct CryptoWriter<T>
where
    T: io::AsyncWrite + std::marker::Unpin,
{
    crypto: Box<dyn interface::Encrypto + Send>,
    writer: T,
    inited: bool,
}

impl<T> CryptoWriter<T>
where
    T: io::AsyncWrite + std::marker::Unpin,
{
    pub fn new(writer: T, secret_key: &[u8; 32]) -> CryptoWriter<T> {
        let crypto: Box<dyn interface::Encrypto + Send> = if USE_CHACHA {
            Box::new(chacha0::ChaCha0::new(secret_key))
        } else {
            Box::new(ase::Aes128Gcm0::new(secret_key))
        };
        CryptoWriter {
            crypto: crypto,
            writer: writer,
            inited: false,
        }
    }
}

impl<T> io::AsyncWrite for CryptoWriter<T>
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
            let data = this.crypto.encrypt_init();
            ready!(Pin::new(&mut this.writer).poll_write(cx, data))?;
            this.inited = true;
        }

        let data = this.crypto.encrypt(buf);
        ready!(Pin::new(&mut this.writer).poll_write(cx, data))?;
        Ok(buf.len()).into()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut Pin::into_inner(self).writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut Pin::into_inner(self).writer).poll_shutdown(cx)
    }
}

pub struct CryptoReader<T>
where
    T: io::AsyncReadExt + std::marker::Unpin,
{
    crypto: Box<dyn interface::Decrypto + Send>,
    reader: T,
    buf: [u8; 4096],
    size: usize,
    pos: usize,
}

impl<T> CryptoReader<T>
where
    T: io::AsyncReadExt + std::marker::Unpin,
{
    pub fn new(reader: T, secret_key: &[u8; 32]) -> CryptoReader<T> {
        let crypto: Box<dyn interface::Decrypto + Send> = if USE_CHACHA {
            Box::new(chacha0::ChaCha0::new(secret_key))
        } else {
            Box::new(ase::Aes128Gcm0Decrypto::new(secret_key))
        };

        CryptoReader {
            crypto: crypto,
            reader: reader,
            buf: [0; 4096],
            size: 0,
            pos: 0,
        }
    }

    fn poll_read_exact(&mut self, cx: &mut Context<'_>, size: usize) -> Poll<io::Result<()>> {
        let mut read_buf = ReadBuf::new(&mut self.buf[..size]);
        while self.size < size {
            let last = self.size;
            ready!(Pin::new(&mut self.reader).poll_read(cx, &mut read_buf))?;
            self.size = read_buf.filled().len();
            if self.size == last || self.size == 0 {
                return Err(ErrorKind::UnexpectedEof.into()).into();
            }
        }
        return Ok(()).into();
    }
}

impl<T> io::AsyncRead for CryptoReader<T>
where
    T: io::AsyncReadExt + std::marker::Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = Pin::into_inner(self);
        if this.size > 0 {
            let len = usize::min(buf.remaining(), this.buf[this.pos..this.size].len());
            buf.put_slice(&(this.buf[this.pos..this.pos + len]));
            this.pos += len;
            if this.pos == this.size {
                this.size = 0;
                this.pos = 0;
            }
            return Ok(()).into();
        }
        loop {
            let size = this.crypto.next_size();
            if size <= -1 {
                this.size = 0;
                ready!(Pin::new(&mut this.reader).poll_read(cx, buf))?;
                let bbuf = buf.filled_mut();
                this.crypto.decrypt(bbuf);
                return Ok(()).into();
            } else if size == 0 {
                let len = usize::min(buf.remaining(), this.buf[this.pos..this.size].len());
                buf.put_slice(&(this.buf[this.pos..this.pos + len]));

                this.pos += len;
                if this.pos == this.size {
                    this.size = 0;
                    this.pos = 0;
                }
                return Ok(()).into();
            } else {
                this.size = 0;
                let vsize = size as usize;
                ready!(this.poll_read_exact(cx, vsize))?;
                this.size = this.crypto.decrypt(&mut this.buf[..this.size]);
            }
        }
    }
}
