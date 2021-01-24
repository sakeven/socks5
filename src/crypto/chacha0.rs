use rand::{thread_rng, Rng};

use chacha::{ChaCha, KeyStream};

use super::interface::Crypto;

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

impl Crypto for ChaCha0 {
    fn encrypt(&mut self, plaintext: &[u8]) -> &Vec<u8> {
        self.vbuf.clear();
        let mut idx = 0;
        if !self.inited {
            self.vbuf.extend_from_slice(&*self.nonce);
            self.inited = true;
            idx = self.nonce.len();
        }
        self.vbuf.extend_from_slice(plaintext);
        self.chacha.xor_read(&mut self.vbuf[idx..]).unwrap();
        &self.vbuf
    }

    fn decrypt(&mut self, plaintext: &mut [u8]) {
        self.chacha.xor_read(plaintext).unwrap();
    }
}
