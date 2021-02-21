use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha1::Sha1;

pub struct HkdfSha1 {
    prk: [u8; Self::TAG_LEN],
}

type HmacSha1 = Hmac<Sha1>;

fn hmacsha1(key: &[u8], m: &[u8]) -> [u8; 20] {
    let mut hmac = HmacSha1::new(Sha1::new(), key);
    hmac.input(m);
    let mut res = [0; 20];
    hmac.raw_result(&mut res);
    res
}

impl HkdfSha1 {
    pub const TAG_LEN: usize = 20;

    pub fn new(salt: &[u8], ikm: &[u8]) -> Self {
        // HKDF-Extract(salt, IKM) -> PRK
        // PRK = HMAC-Hash(salt, IKM)
        let prk = if salt.is_empty() {
            let salt = [0u8; Self::TAG_LEN];
            hmacsha1(&salt, ikm)
        } else {
            hmacsha1(salt, ikm)
        };

        Self { prk }
    }

    pub fn expand(&self, info: &[u8], okm: &mut [u8]) {
        assert!(okm.len() <= Self::TAG_LEN * 255);
        // HKDF-Expand(PRK, info, L) -> OKM
        //
        // N = ceil(L/HashLen)
        // T = T(1) | T(2) | T(3) | ... | T(N)
        // OKM = first L octets of T
        //
        // where:
        // T(0) = empty string (zero length)
        // T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
        // T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
        // T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
        // ...
        //
        // (where the constant concatenated to the end of each T(n) is a
        // single octet.)
        let n = okm.len() / Self::TAG_LEN;
        let r = okm.len() % Self::TAG_LEN;

        if r > 0 {
            assert!(n + 1 <= core::u8::MAX as usize);
        } else {
            assert!(n <= core::u8::MAX as usize);
        }

        let mut hmac = HmacSha1::new(Sha1::new(), &self.prk);
        hmac.input(info);
        hmac.input(&[1]);

        let mut t = [0; Self::TAG_LEN];
        hmac.raw_result(&mut t);

        let len = core::cmp::min(okm.len(), t.len());
        okm[0..len].copy_from_slice(&t[..len]);

        for i in 1u8..n as u8 {
            hmac.reset();
            hmac.input(&t);
            hmac.input(info);
            hmac.input(&[i + 1]);

            t = [0; Self::TAG_LEN];
            hmac.raw_result(&mut t);

            let offset = i as usize * Self::TAG_LEN;
            okm[offset..offset + Self::TAG_LEN].copy_from_slice(&t);
        }
        // Last block
        if n > 0 && r > 0 {
            hmac.reset();
            hmac.input(&t);
            hmac.input(info);
            hmac.input(&[n as u8 + 1]);

            t = [0; Self::TAG_LEN];
            hmac.raw_result(&mut t);
            // NOTE: 允许最后一个 Block 不是完整长度的输出。
            let last_okm = &mut okm[n * Self::TAG_LEN..];
            let len = core::cmp::min(last_okm.len(), Self::TAG_LEN);
            println!("{:#02x?}", &t[..len]);
            last_okm[..len].copy_from_slice(&t[..len]);
        }
    }

    pub fn oneshot(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
        let hkdf = Self::new(salt, ikm);
        hkdf.expand(info, okm);
    }
}

#[cfg(test)]
fn hexdecode(s: &str) -> Vec<u8> {
    let h = s
        .replace("0x", "")
        .replace(" ", "")
        .replace("\n", "")
        .replace("\r", "");
    hex::decode(&h).unwrap()
}
#[test]
fn test_hmacsha1() {
    let key = b"key";
    let data = b"The quick brown fox jumps over the lazy dog";
    let result = "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9";
    assert_eq!(&hex::encode(&hmacsha1(key, data)), result);
}

#[test]
fn test_hkdf() {
    // Test Case 4
    let ikm = hexdecode("0x0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hexdecode("0x000102030405060708090a0b0c");
    let info = hexdecode("0xf0f1f2f3f4f5f6f7f8f9");
    let len = 42usize;

    let mut okm = vec![0u8; len];
    HkdfSha1::oneshot(&salt, &ikm, &info, &mut okm);

    assert_eq!(
        &hex::encode(&okm),
        "085a01ea1b10f36933068b56efa5ad81\
    a4f14b822f5b091568a9cdd4f155fda2\
    c22e422478d305f3f896\
    "
    );

    // Test Case 5
    let ikm = hexdecode(
        "0x000102030405060708090a0b0c0d0e0f\
101112131415161718191a1b1c1d1e1f\
202122232425262728292a2b2c2d2e2f\
303132333435363738393a3b3c3d3e3f\
404142434445464748494a4b4c4d4e4f\
",
    );
    let salt = hexdecode(
        "0x606162636465666768696a6b6c6d6e6f\
707172737475767778797a7b7c7d7e7f\
808182838485868788898a8b8c8d8e8f\
909192939495969798999a9b9c9d9e9f\
a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
",
    );
    let info = hexdecode(
        "0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff\
",
    );
    let len = 82usize;

    let mut okm = vec![0u8; len];
    HkdfSha1::oneshot(&salt, &ikm, &info, &mut okm);
    assert_eq!(
        &hex::encode(&okm),
        "0bd770a74d1160f7c9f12cd5912a06eb\
ff6adcae899d92191fe4305673ba2ffe\
8fa3f1a4e5ad79f3f334b3b202b2173c\
486ea37ce3d397ed034c7f9dfeb15c5e\
927336d0441f4c4300e2cff0d0900b52\
d3b4\
"
    );

    // Test Case 6
    let ikm = hexdecode("0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = [];
    let info = [];
    let len = 42usize;

    let mut okm = vec![0u8; len];
    HkdfSha1::oneshot(&salt, &ikm, &info, &mut okm);
    assert_eq!(
        &hex::encode(&okm),
        "0ac1af7002b3d761d1e55298da9d0506\
b9ae52057220a306e07b6b87e8df21d0\
ea00033de03984d34918\
"
    );

    // Test Case 7
    let ikm = hexdecode("0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
    // NOTE: not provided (defaults to HashLen zero octets)
    let salt = [];
    let info = [];
    let len = 42usize;

    let mut okm = vec![0u8; len];
    HkdfSha1::oneshot(&salt, &ikm, &info, &mut okm);
    assert_eq!(
        &hex::encode(&okm),
        "2c91117204d745f3500d636a62f64f0a\
b3bae548aa53d423b0d1f27ebba6f5e5\
673a081d70cce7acfc48\
"
    );
}
