use core::pin::Pin;
use core::task::Context;
use core::task::Poll;

use chacha::{ChaCha, KeyStream};
use rand::{thread_rng, Rng};
use std::io::Error;
use tokio::io;
use tokio::io::ReadBuf;

pub struct CryptoWriter<T>
where
    T: io::AsyncWrite + std::marker::Sized + std::marker::Unpin,
{
    crypto: chacha::ChaCha,
    writer: T,
    vbuf: [u8; 2048],
    annoce: [u8; 8],
    inited: bool,
}

impl<T> CryptoWriter<T>
where
    T: io::AsyncWrite + std::marker::Sized + std::marker::Unpin,
{
    pub fn new(writer: T) -> CryptoWriter<T> {
        let secret_key = [
            0x29, 0xfa, 0x35, 0x60, 0x88, 0x45, 0xc6, 0xf9, 0xd8, 0xfe, 0x65, 0xe3, 0x22, 0x0e,
            0x5b, 0x05, 0x03, 0x4a, 0xa0, 0x9f, 0x9e, 0x27, 0xad, 0x0f, 0x6c, 0x90, 0xa5, 0x73,
            0xa8, 0x10, 0xe4, 0x94,
        ];
        let mut nonce = [0u8; 8];
        thread_rng().fill(&mut nonce[..]);

        let stream = ChaCha::new_chacha20(&secret_key, &nonce);
        CryptoWriter {
            crypto: stream,
            writer: writer,
            vbuf: [0; 2048],
            annoce: nonce,
            inited: false,
        }
    }
}

impl<T> io::AsyncWrite for CryptoWriter<T>
where
    T: io::AsyncWrite + std::marker::Sized + std::marker::Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let this = Pin::into_inner(self);
        if !this.inited {
            match Pin::new(&mut this.writer).poll_write(cx, &this.annoce) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(_) => {}
            }
            this.inited = true;
        }
        this.vbuf[..buf.len()].copy_from_slice(buf);
        this.crypto.xor_read(&mut this.vbuf[..buf.len()]).unwrap();
        Pin::new(&mut this.writer).poll_write(cx, &this.vbuf[..buf.len()])
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
    T: io::AsyncRead + std::marker::Sized + std::marker::Unpin,
{
    crypto: chacha::ChaCha,
    reader: T,
}

impl<T> CryptoReader<T>
where
    T: io::AsyncRead + std::marker::Sized + std::marker::Unpin,
{
    pub fn new(reader: T, nonce: [u8; 8]) -> CryptoReader<T> {
        let secret_key = [
            0x29, 0xfa, 0x35, 0x60, 0x88, 0x45, 0xc6, 0xf9, 0xd8, 0xfe, 0x65, 0xe3, 0x22, 0x0e,
            0x5b, 0x05, 0x03, 0x4a, 0xa0, 0x9f, 0x9e, 0x27, 0xad, 0x0f, 0x6c, 0x90, 0xa5, 0x73,
            0xa8, 0x10, 0xe4, 0x94,
        ];
        let stream = ChaCha::new_chacha20(&secret_key, &nonce);
        CryptoReader {
            crypto: stream,
            reader: reader,
        }
    }
}

impl<T> io::AsyncRead for CryptoReader<T>
where
    T: io::AsyncRead + std::marker::Sized + std::marker::Unpin,
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
        this.crypto.xor_read(bbuf).unwrap();
        Poll::Ready(Ok(()))
    }
}
