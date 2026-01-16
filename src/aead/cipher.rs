use std::io;

use aes_gcm::{aead::Aead, Key, KeyInit, Nonce};
use serde::{Deserialize, Serialize};

use crate::util::{generate_key, hkdf_sha1};

trait CipherCore {
    /// encrypt data.
    fn encrypt(&mut self, _: &mut [u8]) -> io::Result<Vec<u8>> {
        unimplemented!()
    }

    /// decrypt data.
    fn decrypt(&mut self, _: &mut [u8]) -> io::Result<Vec<u8>> {
        unimplemented!()
    }
}

struct Aes256Gcm {
    nonce: Vec<u8>,
    inner: aes_gcm::Aes256Gcm,
}

pub struct Cipher {
    key: Vec<u8>,
    key_len: usize,
    salt_len: usize,
    nonce_len: usize,
    tag_len: usize,
    enc: Option<Box<dyn CipherCore + Send + Sync + 'static>>,
    dec: Option<Box<dyn CipherCore + Send + Sync + 'static>>,
    cipher_method: Method,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum Method {
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
}

fn increment_nonce(b: &mut [u8]) {
    for byte in b.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}

impl Aes256Gcm {
    fn new(key: &[u8], salt: &[u8]) -> Aes256Gcm {
        let mut subkey = vec![0u8; key.len()];
        let _ = hkdf_sha1(key, salt, b"ss-subkey", &mut subkey);
        let key = Key::<aes_gcm::Aes256Gcm>::from_slice(key);
        Aes256Gcm {
            nonce: vec![0u8; 12],
            inner: aes_gcm::Aes256Gcm::new(key),
        }
    }
}

impl CipherCore for Aes256Gcm {
    /// encrypt data.
    fn encrypt(&mut self, data: &mut [u8]) -> io::Result<Vec<u8>> {
        let nonce = Nonce::from_slice(&self.nonce);
        let ciphertext = self
            .inner
            .encrypt(&nonce, data.as_ref())
            .map_err(|e| io::Error::other(e.to_string()))?;
        increment_nonce(&mut self.nonce);
        Ok(ciphertext)
    }

    /// decrypt data.
    fn decrypt(&mut self, data: &mut [u8]) -> io::Result<Vec<u8>> {
        let nonce = Nonce::from_slice(&self.nonce);
        let plaintext = self
            .inner
            .decrypt(&nonce, data.as_ref())
            .map_err(|e| io::Error::other(e.to_string()))?;
        increment_nonce(&mut self.nonce);
        Ok(plaintext)
    }
}

impl Cipher {
    pub fn new(method: Method, password: &str) -> Cipher {
        let (key_len, salt_len, nonce_len, tag_len) = match method {
            Method::Aes256Gcm => (32, 32, 12, 16),
        };

        let key = generate_key(password.as_bytes(), key_len);
        Cipher {
            key: Vec::from(&key[..]),
            key_len,
            salt_len,
            nonce_len,
            tag_len,
            enc: None,
            dec: None,
            cipher_method: method,
        }
    }

    pub fn init_encrypt(&mut self) {}

    pub fn is_encrypt_inited(&self) -> bool {
        self.enc.is_some()
    }

    pub fn is_decrypt_inited(&self) -> bool {
        self.dec.is_some()
    }

    fn new_cipher(&self, iv: &[u8]) -> Box<dyn CipherCore + Send + Sync + 'static> {
        let key: &[u8] = &self.key;
        match self.cipher_method {
            Method::Aes256Gcm => Box::new(Aes256Gcm::new(key, iv)),
        }
    }

    pub fn init_decrypt(&mut self) {}

    pub fn encrypt(&mut self, input: &mut [u8]) {
        if let Some(enc) = &mut self.enc {
            enc.encrypt(input);
        }
    }

    pub fn decrypt_in_place(&mut self, input: &mut [u8]) {
        if let Some(dec) = &mut self.dec {
            dec.decrypt(input);
        }
    }

    #[must_use]
    pub fn reset(&self) -> Cipher {
        Cipher {
            key: self.key.clone(),
            salt_len: self.salt_len,
            key_len: self.key_len,
            nonce_len: self.nonce_len,
            tag_len: self.tag_len,
            enc: None,
            dec: None,
            cipher_method: self.cipher_method,
        }
    }
}
