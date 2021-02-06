use aes_gcm::aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use aes_gcm::Aes128Gcm;

use super::interface::{Decrypto, Encrypto};

const SALT_SIZE: usize = 16;

pub struct Aes128Gcm0 {
    ase: Aes128Gcm,
    nonce: Box<[u8]>,
    buf: Vec<u8>,
    salt: [u8; SALT_SIZE],
}

impl Aes128Gcm0 {
    pub fn new(secret_key: &[u8; 32]) -> Aes128Gcm0 {
        let key = GenericArray::from_slice(&secret_key[..16]);
        Aes128Gcm0 {
            ase: Aes128Gcm::new(key),
            nonce: Box::new([0u8; 12]),
            buf: Vec::with_capacity(2048),
            salt: [0; SALT_SIZE],
        }
    }
}

const TAG_SIZE: usize = 16;

impl Encrypto for Aes128Gcm0 {
    fn encrypt_init(&mut self) -> &Vec<u8> {
        self.buf.clear();
        self.buf.extend_from_slice(&self.salt[..]);
        &self.buf
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> &Vec<u8> {
        unsafe {
            self.buf.set_len(2 + TAG_SIZE);
        }
        let txt_len = plaintext.len();
        self.buf.extend_from_slice(plaintext);
        assert_eq!(self.buf.len(), 2 + TAG_SIZE + txt_len);

        let orig_len = plaintext.len();
        self.buf[0] = (orig_len >> 8) as u8;
        self.buf[1] = (orig_len % (1 << 8)) as u8;

        inc(&mut *self.nonce);
        let tag = self
            .ase
            .encrypt_in_place_detached((&(*self.nonce)).into(), b"", &mut self.buf[0..2])
            .unwrap();
        let tagslice = tag.as_slice();
        assert_eq!(tagslice.len(), TAG_SIZE);
        let length_tag_idx = 2 + tagslice.len();
        self.buf[2..length_tag_idx].clone_from_slice(tagslice);

        inc(&mut *self.nonce);
        let tag = self
            .ase
            .encrypt_in_place_detached((&(*self.nonce)).into(), b"", &mut self.buf[2 + tag.len()..])
            .unwrap();
        let tagslice = tag.as_slice();
        assert_eq!(tagslice.len(), TAG_SIZE);
        self.buf.extend_from_slice(tagslice);
        &self.buf
    }
}

enum DecrytState {
    Salt,
    DataLen,
    Data,
    Empty,
}

pub struct Aes128Gcm0Decrypto {
    ase: Aes128Gcm,
    nonce: Box<[u8]>,
    salt: [u8; SALT_SIZE],
    datalen: usize,
    state: DecrytState,
}

impl Aes128Gcm0Decrypto {
    pub fn new(secret_key: &[u8; 32]) -> Aes128Gcm0Decrypto {
        let key = GenericArray::from_slice(&secret_key[..16]);
        Aes128Gcm0Decrypto {
            ase: Aes128Gcm::new(key),
            nonce: Box::new([0u8; 12]),
            salt: [0u8; SALT_SIZE],
            datalen: 0,
            state: DecrytState::Salt,
        }
    }
}

impl Decrypto for Aes128Gcm0Decrypto {
    fn decrypt(&mut self, plaintext: &mut [u8]) -> usize {
        match self.state {
            DecrytState::Salt => {
                self.salt.clone_from_slice(plaintext);
                self.state = DecrytState::DataLen;
            }
            DecrytState::DataLen => {
                inc(&mut self.nonce);
                let mut buf: Vec<u8> = Vec::new();
                buf.extend_from_slice(plaintext);
                self.ase
                    .decrypt_in_place((&(*self.nonce)).into(), b"", &mut buf)
                    .unwrap();

                self.datalen = ((buf[0] as usize) << 8) + (buf[1] as usize);
                self.state = DecrytState::Data;
            }
            DecrytState::Data => {
                inc(&mut self.nonce);
                let mut buf: Vec<u8> = Vec::new();
                buf.extend_from_slice(plaintext);
                self.ase
                    .decrypt_in_place((&(*self.nonce)).into(), b"", &mut buf)
                    .unwrap();
                let len = plaintext.len() - TAG_SIZE;
                plaintext[..len].copy_from_slice(&buf[..len]);
                self.state = DecrytState::Empty;
                return len;
            }
            DecrytState::Empty => {}
        }
        return 0;
    }

    fn next_size(&mut self) -> i32 {
        match self.state {
            DecrytState::Salt => SALT_SIZE as i32,
            DecrytState::DataLen => 2 + TAG_SIZE as i32,
            DecrytState::Data => (self.datalen + TAG_SIZE) as i32,
            DecrytState::Empty => {
                self.state = DecrytState::DataLen;
                0
            }
        }
    }
}

fn inc(nonce: &mut [u8]) {
    for i in &mut *nonce {
        *i = ((*i as i32 + 1) % 256) as u8;
        if *i != 0 {
            return;
        }
    }
}
