use std::io;

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{
    aead::AeadInPlace, Key, KeyInit, Nonce,
};
use chacha20::ChaCha20;
use cipher::{BlockCipher, BlockEncryptMut, KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::util::{generate_key, hkdf_sha1};

trait CipherCore {
    /// Encrypt data in place.
    fn encrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()>;

    /// Decrypt data in place.
    fn decrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()>;
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

type Aes128Gcm = AesGcm<aes_gcm::Aes128Gcm>;
type Aes256Gcm = AesGcm<aes_gcm::Aes256Gcm>;

macro_rules! impl_cfb {
    ($name:ident, $cipher:ty) => {
        impl $name {
            fn new(key: &[u8], iv: &[u8]) -> $name {
                let enc = cfb_mode::BufEncryptor::<$cipher>::new(key.into(), iv.into());
                let dec = cfb_mode::BufDecryptor::<$cipher>::new(key.into(), iv.into());
                $name { enc, dec }
            }
        }

        impl CipherCore for $name {
            /// Encrypt data in place.
            fn encrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()> {
                self.enc.encrypt(data);
                Ok(())
            }

            /// Decrypt data in place.
            fn decrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()> {
                self.dec.decrypt(data);
                Ok(())
            }
        }
    };
}

impl_cfb!(Aes128Cfb, Aes128);
impl_cfb!(Aes192Cfb, Aes192);
impl_cfb!(Aes256Cfb, Aes256);

macro_rules! impl_ctr {
    ($name:ident) => {
        impl CipherCore for $name {
            /// Encrypt data in place.
            fn encrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()> {
                self.apply_keystream(data);
                Ok(())
            }

            /// Decrypt data in place.
            fn decrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()> {
                self.apply_keystream(data);
                Ok(())
            }
        }
    };
}

impl_ctr!(Aes128Ctr);
impl_ctr!(Aes192Ctr);
impl_ctr!(Aes256Ctr);

impl CipherCore for ChaCha20 {
    /// Encrypt data in place.
    fn encrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()> {
        self.apply_keystream(data);
        Ok(())
    }

    /// Decrypt data in place.
    fn decrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()> {
        self.apply_keystream(data);
        Ok(())
    }
}

struct AesGcm<G>
where
    G: AeadInPlace + KeyInit,
{
    inner: G,
    nonce: Vec<u8>,
}

fn increment_nonce(nonce: &mut [u8]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}

impl<G> AesGcm<G>
where
    G: AeadInPlace + KeyInit,
{
    fn new(key: &[u8], salt: &[u8]) -> AesGcm<G> {
        // Use HKDF-SHA1 to derive subkey from key and salt
        let mut subkey = vec![0u8; key.len()];
        hkdf_sha1(key, salt, b"ss-subkey", &mut subkey)
            .expect("HKDF-SHA1 key derivation failed");
        let key = Key::<G>::from_slice(&subkey);
        AesGcm {
            inner: G::new(key),
            nonce: salt.to_vec(),
        }
    }
}


impl<G> CipherCore for AesGcm<G>
where
    G: AeadInPlace + KeyInit + Send + Sync + 'static,
{
    /// Encrypt data in place.
    /// Note: For GCM, the buffer must have at least 16 bytes of extra space
    /// after the plaintext to store the authentication tag.
    /// The input buffer should contain plaintext in the first (len - 16) bytes,
    /// and the last 16 bytes are reserved for the authentication tag.
    /// After encryption, the buffer will contain ciphertext in the first (len - 16) bytes
    /// and the authentication tag in the last 16 bytes.
    fn encrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()> {
        // GCM tag is 16 bytes, so we need to separate plaintext and tag space
        if data.len() < 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer too small for GCM tag",
            ));
        }
        let plaintext_len = data.len() - 16;
        let (plaintext_slice, tag_space) = data.split_at_mut(plaintext_len);

        // Convert to Vec for encrypt_in_place (which requires Buffer trait)
        let mut buffer = plaintext_slice.to_vec();
        
        let nonce = Nonce::from_slice(&self.nonce);
        // Use encrypt_in_place: it will encrypt buffer and append tag
        // After encryption: buffer contains [ciphertext][tag]
        match self.inner.encrypt_in_place(nonce, &[], &mut buffer) {
            Ok(()) => {
                // encrypt_in_place appends the tag to the buffer
                // buffer now contains [ciphertext][tag], total length = plaintext_len + 16
                if buffer.len() == plaintext_len + 16 {
                    // Copy ciphertext back to plaintext_slice
                    plaintext_slice.copy_from_slice(&buffer[..plaintext_len]);
                    // Copy tag to tag_space
                    tag_space.copy_from_slice(&buffer[plaintext_len..]);
                    increment_nonce(&mut self.nonce);
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "GCM encryption output length mismatch",
                    ))
                }
            }
            Err(e) => Err(io::Error::other(format!("GCM encryption failed: {e}"))),
        }
    }

    /// Decrypt data in place.
    /// Note: For GCM, the last 16 bytes are assumed to be the authentication tag.
    fn decrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()> {
        if data.len() < 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer too small for GCM tag",
            ));
        }
        // Convert to Vec for decrypt_in_place (which requires Buffer trait)
        let mut buffer = data.to_vec();

        let nonce = Nonce::from_slice(&self.nonce);
        // Use decrypt_in_place: it will decrypt buffer and verify the tag
        // The buffer layout: [ciphertext][tag]
        // After decryption: buffer contains [plaintext] (tag is consumed/verified)
        match self.inner.decrypt_in_place(nonce, &[], &mut buffer) {
            Ok(()) => {
                // decrypt_in_place verifies the tag and decrypts in place
                // The plaintext is now in buffer, copy it back to data
                let plaintext_len = buffer.len();
                if plaintext_len <= data.len() {
                    data[..plaintext_len].copy_from_slice(&buffer);
                    increment_nonce(&mut self.nonce);
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "GCM decryption output length mismatch",
                    ))
                }
            }
            Err(e) => Err(io::Error::other(format!(
                "GCM decryption failed (authentication failed): {e}"
            ))),
        }
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
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
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
            Method::Aes128Gcm => (16, 12),
            Method::Aes256Gcm => (32, 12),
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

    /// Get the IV (or salt for GCM methods).
    /// For GCM methods (AES-128-GCM, AES-256-GCM), this returns the salt.
    /// For other methods, this returns the IV.
    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    /// Get the length of IV (or salt for GCM methods).
    /// For GCM methods (AES-128-GCM, AES-256-GCM), this returns the salt length.
    /// For other methods, this returns the IV length.
    pub fn iv_len(&self) -> usize {
        self.iv_len
    }

    /// Get mutable reference to the IV (or salt for GCM methods).
    /// For GCM methods (AES-128-GCM, AES-256-GCM), this is the salt.
    /// For other methods, this is the IV.
    pub fn iv_mut(&mut self) -> &mut [u8] {
        &mut self.iv[..]
    }

    pub fn is_encrypt_inited(&self) -> bool {
        self.enc.is_some()
    }

    pub fn is_decrypt_inited(&self) -> bool {
        self.dec.is_some()
    }

    fn new_cipher(&self, iv_or_salt: &[u8]) -> Box<dyn CipherCore + Send + Sync + 'static> {
        let key: &[u8] = &self.key;
        match self.cipher_method {
            Method::Aes128Cfb => Box::new(Aes128Cfb::new(key, iv_or_salt)),
            Method::Aes192Cfb => Box::new(Aes192Cfb::new(key, iv_or_salt)),
            Method::Aes256Cfb => Box::new(Aes256Cfb::new(key, iv_or_salt)),
            Method::Aes128Ctr => Box::new(Aes128Ctr::new(key.into(), iv_or_salt.into())),
            Method::Aes192Ctr => Box::new(Aes192Ctr::new(key.into(), iv_or_salt.into())),
            Method::Aes256Ctr => Box::new(Aes256Ctr::new(key.into(), iv_or_salt.into())),
            Method::ChaCha20 => Box::new(ChaCha20::new(key.into(), iv_or_salt.into())),
            // For GCM methods, iv_or_salt is actually salt
            Method::Aes128Gcm => Box::new(Aes128Gcm::new(key, iv_or_salt)),
            Method::Aes256Gcm => Box::new(Aes256Gcm::new(key, iv_or_salt)),
        }
    }

    pub fn init_decrypt(&mut self) {
        self.dec = Some(self.new_cipher(&self.iv));
    }

    pub fn encrypt_in_place(&mut self, input: &mut [u8]) -> io::Result<()> {
        if let Some(enc) = &mut self.enc {
            enc.encrypt_in_place(input)
        } else {
            Err(io::Error::other("encryption not initialized"))
        }
    }

    pub fn decrypt_in_place(&mut self, input: &mut [u8]) -> io::Result<()> {
        if let Some(dec) = &mut self.dec {
            dec.decrypt_in_place(input)
        } else {
            Err(io::Error::other("decryption not initialized"))
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
