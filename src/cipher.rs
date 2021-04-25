use crate::util::generate_key;
use aes::{Aes128, Aes256};
use cfb_mode::cipher::{NewStreamCipher, StreamCipher};
use cfb_mode::Cfb;

use rand::distributions::Standard;
use rand::{thread_rng, Rng};

type Aes128Cfb = Cfb<Aes128>;
type Aes256Cfb = Cfb<Aes256>;

pub struct Cipher {
    pub key: Vec<u8>,
    pub key_len: usize,
    pub iv: Vec<u8>,
    pub iv_len: usize,
    pub enc: Option<Box<dyn StreamCipher + Send + 'static>>,
    pub dec: Option<Box<dyn StreamCipher + Send + 'static>>,
}

impl Cipher {
    pub fn new(method: &str, password: &str) -> Cipher {
        let key_len = match method {
            "aes-256-cfb" => 32,
            "aes-128-cfb" => 16,
            _ => panic!("method not supported"),
        };

        let key = generate_key(password.as_bytes(), key_len);
        let iv_len = 16;
        Cipher {
            key: Vec::from(&key[..]),
            key_len,
            iv_len,
            iv: vec![0u8; iv_len],
            enc: None,
            dec: None,
        }
    }

    pub fn init_encrypt(&mut self) {
        if self.iv.is_empty() {
            let rng = thread_rng();
            self.iv = rng.sample_iter(&Standard).take(self.iv.len()).collect();
        }
        self.enc = if self.key_len == 16 {
            Some(Box::new(
                Aes128Cfb::new_var(&self.key, &self.iv).expect("init enc error"),
            ))
        } else {
            Some(Box::new(
                Aes256Cfb::new_var(&self.key, &self.iv).expect("init enc error"),
            ))
        };
    }

    pub fn init_decrypt(&mut self, iv: &[u8]) {
        self.dec = if self.key_len == 16 {
            Some(Box::new(
                Aes128Cfb::new_var(&self.key, iv).expect("init dec error"),
            ))
        } else {
            Some(Box::new(
                Aes256Cfb::new_var(&self.key, iv).expect("init dec error"),
            ))
        };
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

    pub fn reset(&self) -> Cipher {
        Cipher {
            key: self.key.clone(),
            iv: vec![],
            key_len: self.key_len,
            iv_len: self.iv_len,
            enc: None,
            dec: None,
        }
    }
}
