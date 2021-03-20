use super::hkdf;
use aes_gcm::aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use aes_gcm::Aes128Gcm;

use super::interface::{Decrypto, Encrypto};

const SALT_SIZE: usize = 16;

pub struct Aes128Gcm0 {
    ase: Aes128Gcm,
    nonce: [u8; 12],
    buf: Vec<u8>,
    salt: [u8; SALT_SIZE],
    wait_consume: bool,
}

impl Aes128Gcm0 {
    pub fn new(secret_key: &[u8]) -> Aes128Gcm0 {
        let mut salt = [0; SALT_SIZE];
        random_salt(&mut salt[..]);

        let mut okm = [0u8; 64];
        hkdf::HkdfSha1::oneshot(&salt, secret_key, HKDF_INFO, &mut okm[..16]);
        let key = GenericArray::from_slice(&okm[..16]);
        Aes128Gcm0 {
            ase: Aes128Gcm::new(key),
            nonce: [0u8; 12],
            buf: Vec::with_capacity(2048),
            salt,
            wait_consume: false,
        }
    }
}

/// Generate random bytes into `salt`
pub fn random_salt(salt: &mut [u8]) {
    if salt.is_empty() {
        return ();
    }

    let mut rng = rand::thread_rng();
    loop {
        rand::Rng::fill(&mut rng, salt);
        let is_zeros = salt.iter().all(|&x| x == 0);
        if !is_zeros {
            break;
        }
    }
}

const TAG_SIZE: usize = 16;

impl Encrypto for Aes128Gcm0 {
    fn encrypt_init(&mut self) -> &Vec<u8> {
        if self.wait_consume {
            return &self.buf;
        }
        self.buf.clear();
        self.buf.extend_from_slice(&self.salt[..]);
        self.wait_consume = true;
        &self.buf
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> &Vec<u8> {
        if self.wait_consume {
            return &self.buf;
        }

        unsafe {
            self.buf.set_len(2 + TAG_SIZE);
        }
        let txt_len = plaintext.len();
        self.buf.extend_from_slice(plaintext);
        assert_eq!(self.buf.len(), 2 + TAG_SIZE + txt_len);

        let orig_len = plaintext.len();
        self.buf[0] = (orig_len >> 8) as u8;
        self.buf[1] = (orig_len % (1 << 8)) as u8;

        let tag = self
            .ase
            .encrypt_in_place_detached((&self.nonce).into(), b"", &mut self.buf[0..2])
            .unwrap();
        let tagslice = tag.as_slice();
        assert_eq!(tagslice.len(), TAG_SIZE);
        let length_tag_idx = 2 + tagslice.len();
        self.buf[2..length_tag_idx].clone_from_slice(tagslice);

        inc(&mut self.nonce);
        let tag = self
            .ase
            .encrypt_in_place_detached((&self.nonce).into(), b"", &mut self.buf[2 + tag.len()..])
            .unwrap();
        let tagslice = tag.as_slice();
        assert_eq!(tagslice.len(), TAG_SIZE);
        self.buf.extend_from_slice(tagslice);
        inc(&mut self.nonce);

        self.wait_consume = true;
        &self.buf
    }

    fn reset(&mut self) {
        self.wait_consume = false;
    }
}

#[derive(Debug)]
enum DecryptState {
    Salt,
    DataLen,
    Data,
    Empty,
}

pub struct Aes128Gcm0Decrypto {
    ase: Option<Aes128Gcm>,
    nonce: [u8; 12],
    secret_key: [u8; 16],
    datalen: usize,
    state: DecryptState,
}

impl Aes128Gcm0Decrypto {
    pub fn new(secret_key: &[u8]) -> Aes128Gcm0Decrypto {
        let mut sk = [0u8; 16];
        sk.copy_from_slice(&secret_key[..16]);
        Aes128Gcm0Decrypto {
            ase: None,
            nonce: [0u8; 12],
            secret_key: sk,
            datalen: 0,
            state: DecryptState::Salt,
        }
    }
}

const HKDF_INFO: &[u8; 9] = b"ss-subkey";

impl Decrypto for Aes128Gcm0Decrypto {
    fn decrypt(&mut self, plaintext: &mut Vec<u8>) -> usize {
        match self.state {
            DecryptState::Salt => {
                let mut salt = [0u8; SALT_SIZE];
                salt.clone_from_slice(plaintext);
                let mut okm = [0u8; 64];
                hkdf::HkdfSha1::oneshot(&salt, &self.secret_key, HKDF_INFO, &mut okm[..16]);
                let key = GenericArray::from_slice(&okm[..16]);
                self.ase = Some(Aes128Gcm::new(key));
                self.state = DecryptState::DataLen;
            }
            DecryptState::DataLen => {
                assert_eq!(plaintext.len(), TAG_SIZE + 2);
                self.datalen = 0;
                self.ase
                    .as_ref()
                    .unwrap()
                    .decrypt_in_place((&self.nonce).into(), b"", plaintext)
                    .unwrap();
                inc(&mut self.nonce);
                self.datalen = ((plaintext[0] as usize) << 8) + (plaintext[1] as usize);
                self.state = DecryptState::Data;
            }
            DecryptState::Data => {
                assert_eq!(self.datalen + TAG_SIZE, plaintext.len());
                self.ase
                    .as_ref()
                    .unwrap()
                    .decrypt_in_place((&self.nonce).into(), b"", plaintext)
                    .unwrap();
                inc(&mut self.nonce);
                self.state = DecryptState::Empty;
                return self.datalen;
            }
            DecryptState::Empty => {}
        }
        return 0;
    }

    fn next_size(&mut self) -> usize {
        match self.state {
            DecryptState::Salt => SALT_SIZE,
            DecryptState::DataLen => 2 + TAG_SIZE,
            DecryptState::Data => (self.datalen + TAG_SIZE),
            DecryptState::Empty => {
                self.state = DecryptState::DataLen;
                0
            }
        }
    }
}

fn inc(nonce: &mut [u8]) {
    for i in &mut *nonce {
        *i = ((*i as u16 + 1) % 256) as u8;
        if *i != 0 {
            return;
        }
    }
}
