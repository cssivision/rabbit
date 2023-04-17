use aes::{Aes128, Aes192, Aes256};
use cfb_mode::Cfb;
use chacha20::ChaCha20;
use cipher::{consts::U16, AsyncStreamCipher, BlockCipher, BlockEncrypt, NewCipher, StreamCipher};
use ctr::Ctr128BE;
use rand::distributions::Standard;
use rand::{thread_rng, Rng};

use crate::util::generate_key;

pub trait SymmetricCipher {
    /// Encrypt data in place.
    fn encrypt(&mut self, data: &mut [u8]);

    /// Decrypt data in place.
    fn decrypt(&mut self, data: &mut [u8]);
}

impl<C: BlockCipher + BlockEncrypt> SymmetricCipher for Cfb<C> {
    /// Encrypt data in place.
    fn encrypt(&mut self, data: &mut [u8]) {
        AsyncStreamCipher::encrypt(self, data)
    }

    /// Decrypt data in place.
    fn decrypt(&mut self, data: &mut [u8]) {
        AsyncStreamCipher::decrypt(self, data)
    }
}

impl<B: BlockEncrypt + BlockCipher<BlockSize = U16>> SymmetricCipher for Ctr128BE<B> {
    /// Encrypt data in place.
    fn encrypt(&mut self, data: &mut [u8]) {
        StreamCipher::apply_keystream(self, data)
    }

    /// Decrypt data in place.
    fn decrypt(&mut self, data: &mut [u8]) {
        StreamCipher::apply_keystream(self, data)
    }
}

impl SymmetricCipher for ChaCha20 {
    /// Encrypt data in place.
    fn encrypt(&mut self, data: &mut [u8]) {
        StreamCipher::apply_keystream(self, data)
    }

    /// Decrypt data in place.
    fn decrypt(&mut self, data: &mut [u8]) {
        StreamCipher::apply_keystream(self, data)
    }
}

type Aes128Cfb = Cfb<Aes128>;
type Aes192Cfb = Cfb<Aes192>;
type Aes256Cfb = Cfb<Aes256>;
type Aes128Ctr = Ctr128BE<Aes128>;
type Aes192Ctr = Ctr128BE<Aes192>;
type Aes256Ctr = Ctr128BE<Aes256>;

pub struct Cipher {
    key: Vec<u8>,
    key_len: usize,
    iv: Vec<u8>,
    iv_len: usize,
    enc: Option<Box<dyn SymmetricCipher>>,
    dec: Option<Box<dyn SymmetricCipher>>,
    cipher_method: CipherMethod,
}

#[derive(Clone, Copy, Debug)]
enum CipherMethod {
    Aes128Cfb,
    Aes192Cfb,
    Aes256Cfb,
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr,
    ChaCha20,
}

impl Cipher {
    pub fn new(method: &str, password: &str) -> Cipher {
        let (key_len, cipher_method, iv_len) = match method {
            "aes-128-cfb" => (16, CipherMethod::Aes128Cfb, 16),
            "aes-192-cfb" => (24, CipherMethod::Aes192Cfb, 16),
            "aes-256-cfb" => (32, CipherMethod::Aes256Cfb, 16),
            "aes-128-ctr" => (16, CipherMethod::Aes128Ctr, 16),
            "aes-192-ctr" => (24, CipherMethod::Aes192Ctr, 16),
            "aes-256-ctr" => (32, CipherMethod::Aes256Ctr, 16),
            "chacha20" => (32, CipherMethod::ChaCha20, 12),
            _ => panic!("method not supported"),
        };

        let key = generate_key(password.as_bytes(), key_len);
        Cipher {
            key: Vec::from(&key[..]),
            key_len,
            iv_len,
            iv: vec![0u8; iv_len],
            enc: None,
            dec: None,
            cipher_method,
        }
    }

    pub fn init_encrypt(&mut self) {
        if self.iv.is_empty() {
            let rng = thread_rng();
            self.iv = rng.sample_iter(&Standard).take(self.iv_len).collect();
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

    fn new_cipher(&self, iv: &[u8]) -> Box<dyn SymmetricCipher> {
        let key: &[u8] = &self.key;
        match self.cipher_method {
            CipherMethod::Aes128Cfb => {
                Box::new(Aes128Cfb::new_from_slices(key, iv).expect("init cipher error"))
            }
            CipherMethod::Aes192Cfb => {
                Box::new(Aes192Cfb::new_from_slices(key, iv).expect("init cipher error"))
            }
            CipherMethod::Aes256Cfb => {
                Box::new(Aes256Cfb::new_from_slices(key, iv).expect("init cipher error"))
            }
            CipherMethod::Aes128Ctr => Box::new(Aes128Ctr::new(key.into(), iv.into())),
            CipherMethod::Aes192Ctr => Box::new(Aes192Ctr::new(key.into(), iv.into())),
            CipherMethod::Aes256Ctr => Box::new(Aes256Ctr::new(key.into(), iv.into())),
            CipherMethod::ChaCha20 => Box::new(ChaCha20::new(key.into(), iv.into())),
        }
    }

    pub fn init_decrypt(&mut self) {
        self.dec = Some(self.new_cipher(&self.iv));
    }

    pub fn encrypt(&mut self, input: &mut [u8]) {
        if let Some(enc) = &mut self.enc {
            enc.encrypt(input);
        }
    }

    pub fn decrypt(&mut self, input: &mut [u8]) {
        if let Some(dec) = &mut self.dec {
            dec.decrypt(input)
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
