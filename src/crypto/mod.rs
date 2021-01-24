mod ase;
mod chacha0;
mod interface;

use core::pin::Pin;
use core::task::Context;
use core::task::Poll;
use std::io::Error;
use tokio::io;
use tokio::io::ReadBuf;

pub struct CryptoWriter<T>
where
    T: io::AsyncWrite + std::marker::Unpin,
{
    crypto: Box<dyn interface::Crypto + Send>,
    writer: T,
}

impl<T> CryptoWriter<T>
where
    T: io::AsyncWrite + std::marker::Unpin,
{
    pub fn new(writer: T, secret_key: &[u8; 32]) -> CryptoWriter<T> {
        let crypto: Box<dyn interface::Crypto + Send> = if true {
            Box::new(chacha0::ChaCha0::new(secret_key))
        } else {
            Box::new(ase::Aes128Gcm0::new(secret_key))
        };
        CryptoWriter {
            crypto: crypto,
            writer: writer,
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
        let data = this.crypto.encrypt(buf);
        Pin::new(&mut this.writer).poll_write(cx, data)
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
    crypto: Box<dyn interface::Crypto + Send>,
    reader: T,
}

impl<T> CryptoReader<T>
where
    T: io::AsyncRead + std::marker::Unpin,
{
    pub fn new(reader: T, nonce: [u8; 8], secret_key: &[u8; 32]) -> CryptoReader<T> {
        CryptoReader {
            crypto: Box::new(chacha0::ChaCha0::new_with_nonce(secret_key, &nonce)),
            reader: reader,
        }
    }
}

impl<T> io::AsyncRead for CryptoReader<T>
where
    T: io::AsyncRead + std::marker::Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = Pin::into_inner(self);
        let poll = Pin::new(&mut this.reader).poll_read(cx, buf);
        match poll {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(_) => {}
        }
        let bbuf = buf.filled_mut();
        this.crypto.decrypt(bbuf);
        Poll::Ready(Ok(()))
    }
}
