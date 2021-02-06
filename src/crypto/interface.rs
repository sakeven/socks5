pub trait Encrypto {
    fn encrypt_init(&mut self) -> &Vec<u8>;
    fn encrypt(&mut self, plaintext: &[u8]) -> &Vec<u8>;
}

pub trait Decrypto {
    fn decrypt(&mut self, chiper: &mut [u8]) -> usize;
    fn next_size(&mut self) -> i32;
}
