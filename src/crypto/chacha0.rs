use rand::{thread_rng, Rng};

use chacha::{ChaCha, KeyStream};

use super::interface::{Decrypto, Encrypto};

pub struct ChaCha0 {
    chacha: ChaCha,
    nonce: Box<[u8]>,
    inited: bool,
    vbuf: Vec<u8>,
}

impl ChaCha0 {
    pub fn new(secret_key: &[u8; 32]) -> Self {
        let mut nonce = Box::new([0u8; 8]);
        thread_rng().fill(&mut nonce[..]);
        ChaCha0 {
            chacha: ChaCha::new_chacha20(secret_key, &nonce),
            nonce: nonce,
            inited: false,
            vbuf: Vec::with_capacity(4096),
        }
    }

    pub fn new_with_nonce(secret_key: &[u8; 32], _nonce: &[u8]) -> Self {
        let mut nonce = Box::new([0u8; 8]);
        nonce.copy_from_slice(&_nonce[..8]);
        ChaCha0 {
            chacha: ChaCha::new_chacha20(secret_key, &nonce),
            nonce: nonce,
            inited: false,
            vbuf: Vec::with_capacity(4096),
        }
    }
}

impl Encrypto for ChaCha0 {
    fn encrypt_init(&mut self) -> &Vec<u8> {
        self.vbuf.clear();
        self.vbuf.extend_from_slice(&*self.nonce);
        self.inited = true;
        &self.vbuf
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> &Vec<u8> {
        self.vbuf.clear();
        self.vbuf.extend_from_slice(plaintext);
        self.chacha.xor_read(&mut self.vbuf[..]).unwrap();
        &self.vbuf
    }
}

impl Decrypto for ChaCha0 {
    fn decrypt(&mut self, plaintext: &mut [u8]) -> usize {
        if !self.inited {
            self.nonce.copy_from_slice(plaintext);
            self.inited = true;
            return 0;
        }
        self.chacha.xor_read(plaintext).unwrap();
        return plaintext.len();
    }

    fn next_size(&mut self) -> i32 {
        if self.inited {
            return -1;
        }
        8
    }
}
