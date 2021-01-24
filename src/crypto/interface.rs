pub trait Crypto {
    fn encrypt(&mut self, plaintext: &[u8]) -> &Vec<u8>;
    fn decrypt(&mut self, chiper: &mut [u8]);
}
