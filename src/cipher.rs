use aes::{Aes128, Aes192, Aes256};
use chacha20::ChaCha20;
use cipher::{BlockCipher, BlockEncryptMut, KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::util::generate_key;

trait CipherCore {
    /// Encrypt data in place.
    fn encrypt_in_place(&mut self, _: &mut [u8]) {}

    /// Decrypt data in place.
    fn decrypt_in_place(&mut self, _: &mut [u8]) {}
}

struct Cfb<C: BlockCipher + BlockEncryptMut> {
    enc: cfb_mode::BufEncryptor<C>,
    dec: cfb_mode::BufDecryptor<C>,
}

type Aes128Cfb = Cfb<Aes128>;
type Aes192Cfb = Cfb<Aes192>;
type Aes256Cfb = Cfb<Aes256>;

type Aes128Ctr = Ctr128BE<Aes128>;
type Aes192Ctr = Ctr128BE<Aes192>;
type Aes256Ctr = Ctr128BE<Aes256>;

impl Aes128Cfb {
    fn new(key: &[u8], iv: &[u8]) -> Aes128Cfb {
        let enc = cfb_mode::BufEncryptor::<Aes128>::new(key.into(), iv.into());
        let dec = cfb_mode::BufDecryptor::<Aes128>::new(key.into(), iv.into());
        Aes128Cfb { enc, dec }
    }
}

impl Aes192Cfb {
    fn new(key: &[u8], iv: &[u8]) -> Aes192Cfb {
        let enc = cfb_mode::BufEncryptor::<Aes192>::new(key.into(), iv.into());
        let dec = cfb_mode::BufDecryptor::<Aes192>::new(key.into(), iv.into());
        Aes192Cfb { enc, dec }
    }
}

impl Aes256Cfb {
    fn new(key: &[u8], iv: &[u8]) -> Aes256Cfb {
        let enc = cfb_mode::BufEncryptor::<Aes256>::new(key.into(), iv.into());
        let dec = cfb_mode::BufDecryptor::<Aes256>::new(key.into(), iv.into());
        Aes256Cfb { enc, dec }
    }
}

impl CipherCore for Aes128Cfb {
    /// Encrypt data in place.
    fn encrypt_in_place(&mut self, data: &mut [u8]) {
        self.enc.encrypt(data);
    }

    /// Decrypt data in place.
    fn decrypt_in_place(&mut self, data: &mut [u8]) {
        self.dec.decrypt(data);
    }
}

impl CipherCore for Aes192Cfb {
    /// Encrypt data in place.
    fn encrypt_in_place(&mut self, data: &mut [u8]) {
        self.enc.encrypt(data);
    }

    /// Decrypt data in place.
    fn decrypt_in_place(&mut self, data: &mut [u8]) {
        self.dec.decrypt(data);
    }
}

impl CipherCore for Aes256Cfb {
    /// Encrypt data in place.
    fn encrypt_in_place(&mut self, data: &mut [u8]) {
        self.enc.encrypt(data);
    }

    /// Decrypt data in place.
    fn decrypt_in_place(&mut self, data: &mut [u8]) {
        self.dec.decrypt(data);
    }
}

impl CipherCore for Aes128Ctr {
    /// Encrypt data in place.
    fn encrypt_in_place(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }

    /// Decrypt data in place.
    fn decrypt_in_place(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }
}

impl CipherCore for Aes192Ctr {
    /// Encrypt data in place.
    fn encrypt_in_place(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }

    /// Decrypt data in place.
    fn decrypt_in_place(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }
}

impl CipherCore for Aes256Ctr {
    /// Encrypt data in place.
    fn encrypt_in_place(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }

    /// Decrypt data in place.
    fn decrypt_in_place(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }
}

impl CipherCore for ChaCha20 {
    /// Encrypt data in place.
    fn encrypt_in_place(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }

    /// Decrypt data in place.
    fn decrypt_in_place(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }
}

pub struct Cipher {
    key: Vec<u8>,
    key_len: usize,
    iv: Vec<u8>,
    iv_len: usize,
    enc: Option<Box<dyn CipherCore + Send + Sync + 'static>>,
    dec: Option<Box<dyn CipherCore + Send + Sync + 'static>>,
    cipher_method: Method,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum Method {
    #[serde(rename = "aes-128-cfb")]
    Aes128Cfb,
    #[serde(rename = "aes-192-cfb")]
    Aes192Cfb,
    #[serde(rename = "aes-256-cfb")]
    Aes256Cfb,
    #[serde(rename = "aes-128-ctr")]
    Aes128Ctr,
    #[serde(rename = "aes-192-ctr")]
    Aes192Ctr,
    #[serde(rename = "aes-256-ctr")]
    Aes256Ctr,
    #[serde(rename = "chacha20")]
    ChaCha20,
}

impl Cipher {
    pub fn new(method: Method, password: &str) -> Cipher {
        let (key_len, iv_len) = match method {
            Method::Aes128Cfb => (16, 16),
            Method::Aes192Cfb => (24, 16),
            Method::Aes256Cfb => (32, 16),
            Method::Aes128Ctr => (16, 16),
            Method::Aes192Ctr => (24, 16),
            Method::Aes256Ctr => (32, 16),
            Method::ChaCha20 => (32, 12),
        };

        let key = generate_key(password.as_bytes(), key_len);
        Cipher {
            key: Vec::from(&key[..]),
            key_len,
            iv_len,
            iv: vec![0u8; iv_len],
            enc: None,
            dec: None,
            cipher_method: method,
        }
    }

    pub fn init_encrypt(&mut self) {
        if self.iv.is_empty() {
            self.iv = vec![0u8; self.iv_len];
            rand::rng().fill(&mut self.iv[..]);
        }
        self.enc = Some(self.new_cipher(&self.iv));
    }

    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    pub fn iv_len(&self) -> usize {
        self.iv_len
    }

    pub fn iv_mut(&mut self) -> &mut [u8] {
        &mut self.iv[..]
    }

    pub fn is_encrypt_inited(&self) -> bool {
        self.enc.is_some()
    }

    pub fn is_decrypt_inited(&self) -> bool {
        self.dec.is_some()
    }

    fn new_cipher(&self, iv: &[u8]) -> Box<dyn CipherCore + Send + Sync + 'static> {
        let key: &[u8] = &self.key;
        match self.cipher_method {
            Method::Aes128Cfb => Box::new(Aes128Cfb::new(key, iv)),
            Method::Aes192Cfb => Box::new(Aes192Cfb::new(key, iv)),
            Method::Aes256Cfb => Box::new(Aes256Cfb::new(key, iv)),
            Method::Aes128Ctr => Box::new(Aes128Ctr::new(key.into(), iv.into())),
            Method::Aes192Ctr => Box::new(Aes192Ctr::new(key.into(), iv.into())),
            Method::Aes256Ctr => Box::new(Aes256Ctr::new(key.into(), iv.into())),
            Method::ChaCha20 => Box::new(ChaCha20::new(key.into(), iv.into())),
        }
    }

    pub fn init_decrypt(&mut self) {
        self.dec = Some(self.new_cipher(&self.iv));
    }

    pub fn encrypt_in_place(&mut self, input: &mut [u8]) {
        if let Some(enc) = &mut self.enc {
            enc.encrypt_in_place(input);
        }
    }

    pub fn decrypt_in_place(&mut self, input: &mut [u8]) {
        if let Some(dec) = &mut self.dec {
            dec.decrypt_in_place(input)
        }
    }

    #[must_use]
    pub fn reset(&self) -> Cipher {
        Cipher {
            key: self.key.clone(),
            iv: vec![0u8; self.iv_len],
            iv_len: self.iv_len,
            key_len: self.key_len,
            enc: None,
            dec: None,
            cipher_method: self.cipher_method,
        }
    }
}
