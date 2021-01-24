use aes_gcm::aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use aes_gcm::Aes128Gcm;

use super::interface::Crypto;

pub struct Aes128Gcm0 {
    ase: Aes128Gcm,
    nonce: Box<[u8]>,
    buf: Vec<u8>,
}

impl Aes128Gcm0 {
    pub fn new(secret_key: &[u8; 32]) -> Aes128Gcm0 {
        let key = GenericArray::from_slice(secret_key);
        Aes128Gcm0 {
            ase: Aes128Gcm::new(key),
            nonce: Box::new([0u8; 32]),
            buf: Vec::new(),
        }
    }
}

const TAG_SIZE: usize = 16;

impl Crypto for Aes128Gcm0 {
    fn encrypt(&mut self, plaintext: &[u8]) -> &Vec<u8> {
        unsafe {
            self.buf.set_len(2 + TAG_SIZE);
        }
        self.buf.extend_from_slice(plaintext);
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

    fn decrypt(&mut self, plaintext: &mut [u8]) {
        let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message
        let mut a: Vec<u8> = Vec::new();
        self.ase.decrypt_in_place(nonce, b"", &mut a).unwrap();
    }
}

fn inc(nonce: &mut [u8]) {
    for i in &mut *nonce {
        *i += 1;
        if *i != 0 {
            return;
        }
    }
}
