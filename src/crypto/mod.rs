mod ase;
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
            Box::new(ase::Aes128Gcm0::new(secret_key));
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
    buf: [u8; 8192 * 3],
    size: usize,
    pos: usize,
}

impl<T> CryptoReader<T>
where
    T: io::AsyncReadExt + std::marker::Unpin,
{
    pub fn new(reader: T, secret_key: &[u8]) -> CryptoReader<T> {
        let crypto: Box<dyn interface::Decrypto + Send> =
            Box::new(ase::Aes128Gcm0Decrypto::new(secret_key));

        CryptoReader {
            crypto: crypto,
            reader: reader,
            buf: [0; 8192 * 3],
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

const MD5_SZIE: usize = 16;

pub fn evp_bytes_to_key(password: String, keylen: usize) -> Vec<u8> {
    let mut md5 = Md5::new();
    let cnt = (keylen - 1) / MD5_SZIE + 1;
    md5.input(&password.as_bytes());
    let mut ms = vec![0u8; cnt * MD5_SZIE];
    md5.result(&mut ms[..]);

    let mut data = vec![0u8; MD5_SZIE + password.len()];
    for i in 1..cnt {
        let pos = i << 4;
        data[..MD5_SZIE].copy_from_slice(&ms[((i - 1) << 4)..pos]);
        data[MD5_SZIE..MD5_SZIE + password.len()].copy_from_slice(&password.as_bytes());
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
