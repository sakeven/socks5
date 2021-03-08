mod aes;
mod hkdf;
mod interface;

use core::pin::Pin;
use core::task::Context;
use core::task::Poll;
use std::io::{Error, ErrorKind};

use crypto::digest::Digest;
use crypto::md5::Md5;
use futures::ready;
use tokio::io;
use tokio::io::ReadBuf;

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
    pub fn new(writer: T, secret_key: &[u8]) -> CryptoWriter<T> {
        let crypto: Box<dyn interface::Encrypto + Send> =
            Box::new(aes::Aes128Gcm0::new(secret_key));
        CryptoWriter {
            crypto,
            writer,
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
    T: io::AsyncRead + std::marker::Unpin,
{
    crypto: Box<dyn interface::Decrypto + Send>,
    reader: T,
    buf: Vec<u8>,
    size: usize,
    pos: usize,
}

const MAX_BUF_LEN: usize = (1 << 16) - 1;

impl<T> CryptoReader<T>
where
    T: io::AsyncRead + std::marker::Unpin,
{
    pub fn new(reader: T, secret_key: &[u8]) -> CryptoReader<T> {
        let crypto: Box<dyn interface::Decrypto + Send> =
            Box::new(aes::Aes128Gcm0Decrypto::new(secret_key));

        CryptoReader {
            crypto,
            reader,
            buf: Vec::with_capacity(MAX_BUF_LEN),
            size: 0,
            pos: 0,
        }
    }

    fn poll_read_exact0(&mut self, cx: &mut Context<'_>, size: usize) -> Poll<io::Result<()>> {
        assert_eq!(self.pos, 0);
        assert_eq!(self.size, 0);
        assert_ne!(size, 0);
        unsafe {
            self.buf.set_len(size);
            self.buf.fill(0);
        }
        let mut read_buf = ReadBuf::new(&mut self.buf);
        while self.size < size {
            let last = self.size;
            ready!(Pin::new(&mut self.reader).poll_read(cx, &mut read_buf))?;
            self.size = read_buf.filled().len();
            if self.size == last {
                println!("eof");
                return Err(ErrorKind::UnexpectedEof.into()).into();
            }
        }
        return Ok(()).into();
    }
}

impl<T> io::AsyncRead for CryptoReader<T>
where
    T: io::AsyncRead + std::marker::Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        rbuf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = Pin::into_inner(self);
        if this.pos < this.size {
            let len = usize::min(rbuf.remaining(), this.buf[this.pos..this.size].len());
            rbuf.put_slice(&(this.buf[this.pos..this.pos + len]));
            this.pos += len;
            return Ok(()).into();
        }
        this.size = 0;
        this.pos = 0;

        loop {
            let size = this.crypto.next_size();
            if size == 0 {
                let len = usize::min(rbuf.remaining(), this.buf[this.pos..this.size].len());
                rbuf.put_slice(&(this.buf[this.pos..this.pos + len]));
                this.pos += len;
                return Ok(()).into();
            } else {
                ready!(this.poll_read_exact0(cx, size))?;
                println!("size {} {}", size, this.size);
                assert_eq!(size, this.size);
                if this.size == 0 {
                    return Ok(()).into();
                }
                this.size = this.crypto.decrypt(&mut this.buf);
            }
        }
    }
}

const MD5_SIZE: usize = 16;

pub fn evp_bytes_to_key(password: String, keylen: usize) -> Vec<u8> {
    let mut md5 = Md5::new();
    let cnt = (keylen - 1) / MD5_SIZE + 1;
    md5.input(&password.as_bytes());
    let mut ms = vec![0u8; cnt * MD5_SIZE];
    md5.result(&mut ms[..]);

    let mut data = vec![0u8; MD5_SIZE + password.len()];
    for i in 1..cnt {
        let pos = i << 4;
        data[..MD5_SIZE].copy_from_slice(&ms[((i - 1) << 4)..pos]);
        data[MD5_SIZE..MD5_SIZE + password.len()].copy_from_slice(&password.as_bytes());
        md5.reset();
        md5.input(&data);
        md5.result(&mut ms[pos..]);
    }

    unsafe {
        ms.set_len(keylen);
    }
    return ms;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_evp_bytes_to_key() {
        let key = evp_bytes_to_key("foobar".to_string(), 32);
        assert_eq!(
            key,
            [
                0x38, 0x58, 0xf6, 0x22, 0x30, 0xac, 0x3c, 0x91, 0x5f, 0x30, 0xc, 0x66, 0x43, 0x12,
                0xc6, 0x3f, 0x56, 0x83, 0x78, 0x52, 0x96, 0x14, 0xd2, 0x2d, 0xdb, 0x49, 0x23, 0x7d,
                0x2f, 0x60, 0xbf, 0xdf,
            ]
        );
    }
}
