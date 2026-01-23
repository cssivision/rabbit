use std::io;

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{aead::AeadInPlace, Nonce};
use camellia::{Camellia128, Camellia192, Camellia256};
use cipher::{
    consts::{U12, U8},
    generic_array::GenericArray,
    BlockCipher, BlockEncryptMut, Key, KeyInit, KeyIvInit, StreamCipher,
};
use ctr::Ctr128BE;

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::util::{generate_key, hkdf_sha1};

const AEAD2022_IDENTITY_SUBKEY_CONTEXT: &str = "shadowsocks 2022 identity subkey";
const AEAD_SUBKEY_INFO: &[u8] = b"ss-subkey";

trait CipherCore {
    /// Encrypt data in place.
    fn encrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()>;

    /// Decrypt data in place.
    fn decrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()>;
}

/// CFB mode cipher.
struct Cfb<C: BlockCipher + BlockEncryptMut> {
    enc: cfb_mode::BufEncryptor<C>,
    dec: cfb_mode::BufDecryptor<C>,
}

/// AES-128 CFB mode cipher.
type Aes128Cfb = Cfb<Aes128>;
/// AES-192 CFB mode cipher.
type Aes192Cfb = Cfb<Aes192>;
/// AES-256 CFB mode cipher.
type Aes256Cfb = Cfb<Aes256>;

/// Camellia-128 CFB mode cipher.
type Camellia128Cfb = Cfb<Camellia128>;
/// Camellia-192 CFB mode cipher.
type Camellia192Cfb = Cfb<Camellia192>;
/// Camellia-256 CFB mode cipher.
type Camellia256Cfb = Cfb<Camellia256>;

/// AES-128 CTR mode cipher.
type Aes128Ctr = Ctr128BE<Aes128>;
/// AES-192 CTR mode cipher.
type Aes192Ctr = Ctr128BE<Aes192>;
/// AES-256 CTR mode cipher.
type Aes256Ctr = Ctr128BE<Aes256>;

/// AES-128 GCM mode cipher.
type Aes128Gcm = AesGcm<aes_gcm::Aes128Gcm>;
/// AES-192 GCM mode cipher.
type Aes192Gcm = AesGcm<aes_gcm::AesGcm<aes::Aes192, U12>>;
/// AES-256 GCM mode cipher.
type Aes256Gcm = AesGcm<aes_gcm::Aes256Gcm>;

// ChaCha20 is a type alias for ChaCha20Legacy
type ChaCha20 = chacha20::ChaCha20Legacy;
// ChaCha20Ietf is a type alias for ChaCha20
type ChaCha20Ietf = chacha20::ChaCha20;

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

impl_cfb!(Camellia128Cfb, Camellia128);
impl_cfb!(Camellia192Cfb, Camellia192);
impl_cfb!(Camellia256Cfb, Camellia256);

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

impl CipherCore for ChaCha20Ietf {
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

fn derive_blake3_subkey(key: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut key_material = key.to_vec();
    key_material.extend_from_slice(salt);
    blake3::derive_key(AEAD2022_IDENTITY_SUBKEY_CONTEXT, &key_material).to_vec()
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

/// Shared AEAD encrypt/decrypt implementation to avoid repetition across AEAD ciphers.
macro_rules! impl_aead_methods {
    ($make_nonce:expr) => {
        /// Encrypt data in place. Buffer must reserve 16 bytes for the authentication tag.
        fn encrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()> {
            if data.len() < 16 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "buffer too small for AEAD tag",
                ));
            }
            let plaintext_len = data.len() - 16;
            let (plaintext_slice, tag_space) = data.split_at_mut(plaintext_len);
            let mut buffer = plaintext_slice.to_vec();

            let nonce = $make_nonce(&self.nonce);
            match self.inner.encrypt_in_place(nonce, &[], &mut buffer) {
                Ok(()) => {
                    if buffer.len() == plaintext_len + 16 {
                        plaintext_slice.copy_from_slice(&buffer[..plaintext_len]);
                        tag_space.copy_from_slice(&buffer[plaintext_len..]);
                        increment_nonce(&mut self.nonce);
                        Ok(())
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "AEAD encryption output length mismatch",
                        ))
                    }
                }
                Err(e) => Err(io::Error::other(format!("AEAD encryption failed: {e}"))),
            }
        }

        /// Decrypt data in place. Assumes the last 16 bytes are the authentication tag.
        fn decrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()> {
            if data.len() < 16 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "buffer too small for AEAD tag",
                ));
            }
            let mut buffer = data.to_vec();

            let nonce = $make_nonce(&self.nonce);
            match self.inner.decrypt_in_place(nonce, &[], &mut buffer) {
                Ok(()) => {
                    let plaintext_len = buffer.len();
                    if plaintext_len <= data.len() {
                        data[..plaintext_len].copy_from_slice(&buffer);
                        increment_nonce(&mut self.nonce);
                        Ok(())
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "AEAD decryption output length mismatch",
                        ))
                    }
                }
                Err(e) => Err(io::Error::other(format!(
                    "AEAD decryption failed (authentication failed): {e}"
                ))),
            }
        }
    };
}

impl<G> AesGcm<G>
where
    G: AeadInPlace + KeyInit,
{
    fn new(key: &[u8], salt: &[u8]) -> AesGcm<G> {
        // Use HKDF-SHA1 to derive subkey from key and salt
        let mut subkey = vec![0u8; key.len()];
        hkdf_sha1(key, salt, AEAD_SUBKEY_INFO, &mut subkey)
            .expect("HKDF-SHA1 key derivation failed");
        let key = Key::<G>::from_slice(&subkey);
        AesGcm {
            inner: G::new(key),
            nonce: vec![0u8; 12],
        }
    }
}

impl<G> CipherCore for AesGcm<G>
where
    G: AeadInPlace + KeyInit + Send + Sync + 'static,
{
    impl_aead_methods!(Nonce::from_slice);
}

struct Blake3Aes128Gcm {
    inner: aes_gcm::Aes128Gcm,
    nonce: Vec<u8>,
}

impl Blake3Aes128Gcm {
    fn new(key: &[u8], salt: &[u8]) -> Blake3Aes128Gcm {
        let subkey = derive_blake3_subkey(key, salt);
        let key = Key::<aes_gcm::Aes128Gcm>::from_slice(&subkey[..16]);
        Blake3Aes128Gcm {
            inner: aes_gcm::Aes128Gcm::new(key),
            nonce: vec![0u8; 12],
        }
    }
}

impl CipherCore for Blake3Aes128Gcm {
    impl_aead_methods!(Nonce::from_slice);
}

struct Blake3Aes256Gcm {
    inner: aes_gcm::Aes256Gcm,
    nonce: Vec<u8>,
}

impl Blake3Aes256Gcm {
    fn new(key: &[u8], salt: &[u8]) -> Blake3Aes256Gcm {
        let subkey = derive_blake3_subkey(key, salt);
        let key = Key::<aes_gcm::Aes256Gcm>::from_slice(&subkey[..32]);
        Blake3Aes256Gcm {
            inner: aes_gcm::Aes256Gcm::new(key),
            nonce: vec![0u8; 12],
        }
    }
}

impl CipherCore for Blake3Aes256Gcm {
    impl_aead_methods!(Nonce::from_slice);
}

struct Blake3ChaCha20Poly1305 {
    inner: chacha20poly1305::XChaCha20Poly1305,
    nonce: Vec<u8>,
}

impl Blake3ChaCha20Poly1305 {
    fn new(key: &[u8], salt: &[u8]) -> Blake3ChaCha20Poly1305 {
        let subkey = derive_blake3_subkey(key, salt);
        let key = chacha20poly1305::Key::from_slice(&subkey[..32]);
        Blake3ChaCha20Poly1305 {
            inner: chacha20poly1305::XChaCha20Poly1305::new(key),
            nonce: vec![0u8; 24],
        }
    }
}

impl CipherCore for Blake3ChaCha20Poly1305 {
    impl_aead_methods!(chacha20poly1305::XNonce::from_slice);
}

struct ChaCha20IetfPoly1305 {
    inner: chacha20poly1305::ChaCha20Poly1305,
    nonce: Vec<u8>,
}

struct ChaCha20Poly1305 {
    inner: chacha20poly1305::ChaChaPoly1305<ChaCha20, U8>,
    nonce: Vec<u8>,
}

impl ChaCha20Poly1305 {
    fn new(key: &[u8], salt: &[u8]) -> ChaCha20Poly1305 {
        // Use HKDF-SHA1 to derive subkey from key and salt
        let mut subkey = vec![0u8; key.len()];
        hkdf_sha1(key, salt, AEAD_SUBKEY_INFO, &mut subkey)
            .expect("HKDF-SHA1 key derivation failed");
        let key = chacha20poly1305::Key::from_slice(&subkey);
        ChaCha20Poly1305 {
            inner: chacha20poly1305::ChaChaPoly1305::<ChaCha20, U8>::new(key),
            nonce: vec![0u8; 8],
        }
    }
}

impl CipherCore for ChaCha20Poly1305 {
    impl_aead_methods!(GenericArray::<u8, U8>::from_slice);
}

impl ChaCha20IetfPoly1305 {
    fn new(key: &[u8], salt: &[u8]) -> ChaCha20IetfPoly1305 {
        // Use HKDF-SHA1 to derive subkey from key and salt
        let mut subkey = vec![0u8; key.len()];
        hkdf_sha1(key, salt, AEAD_SUBKEY_INFO, &mut subkey)
            .expect("HKDF-SHA1 key derivation failed");
        let key = chacha20poly1305::Key::from_slice(&subkey);
        ChaCha20IetfPoly1305 {
            inner: chacha20poly1305::ChaCha20Poly1305::new(key),
            nonce: vec![0u8; 12],
        }
    }
}

impl CipherCore for ChaCha20IetfPoly1305 {
    impl_aead_methods!(chacha20poly1305::Nonce::from_slice);
}

struct XChaCha20IetfPoly1305 {
    inner: chacha20poly1305::XChaCha20Poly1305,
    nonce: Vec<u8>,
}

impl XChaCha20IetfPoly1305 {
    fn new(key: &[u8], salt: &[u8]) -> XChaCha20IetfPoly1305 {
        // Use HKDF-SHA1 to derive subkey from key and salt
        let mut subkey = vec![0u8; key.len()];
        hkdf_sha1(key, salt, b"ss-subkey", &mut subkey).expect("HKDF-SHA1 key derivation failed");
        let key = chacha20poly1305::Key::from_slice(&subkey);
        XChaCha20IetfPoly1305 {
            inner: chacha20poly1305::XChaCha20Poly1305::new(key),
            nonce: vec![0u8; 24],
        }
    }
}

impl CipherCore for XChaCha20IetfPoly1305 {
    impl_aead_methods!(chacha20poly1305::XNonce::from_slice);
}

pub struct Cipher {
    key: Vec<u8>,
    key_len: usize,
    iv_or_salt_len: usize,
    encrypt_iv_or_salt: Vec<u8>,
    decrypt_iv_or_salt: Vec<u8>,
    encrypt: Option<Box<dyn CipherCore + Send + Sync + 'static>>,
    decrypt: Option<Box<dyn CipherCore + Send + Sync + 'static>>,
    method: Method,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum Method {
    #[serde(rename = "aes-128-cfb")]
    Aes128Cfb,
    #[serde(rename = "aes-192-cfb")]
    Aes192Cfb,
    #[serde(rename = "aes-256-cfb")]
    Aes256Cfb,
    #[serde(rename = "camellia-128-cfb")]
    Camellia128Cfb,
    #[serde(rename = "camellia-192-cfb")]
    Camellia192Cfb,
    #[serde(rename = "camellia-256-cfb")]
    Camellia256Cfb,
    #[serde(rename = "aes-128-ctr")]
    Aes128Ctr,
    #[serde(rename = "aes-192-ctr")]
    Aes192Ctr,
    #[serde(rename = "aes-256-ctr")]
    Aes256Ctr,
    #[serde(rename = "chacha20")]
    ChaCha20,
    #[serde(rename = "chacha20-ietf")]
    ChaCha20Ietf,
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Blake3Aes128Gcm,
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Blake3Aes256Gcm,
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Blake3ChaCha20Poly1305,
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "aes-192-gcm")]
    Aes192Gcm,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
    #[serde(rename = "chacha20-ietf-poly1305")]
    ChaCha20IetfPoly1305,
    #[serde(rename = "xchacha20-ietf-poly1305")]
    XChaCha20IetfPoly1305,
}

fn is_aead2022(method: &Method) -> bool {
    matches!(
        method,
        Method::Blake3Aes128Gcm | Method::Blake3Aes256Gcm | Method::Blake3ChaCha20Poly1305
    )
}

impl Cipher {
    /// Create a new cipher.
    /// The password is used to derive the key for the cipher.
    /// The method is the cipher method to use.
    pub fn new(method: Method, password: &str) -> io::Result<Cipher> {
        let (key_len, iv_or_salt_len) = match method {
            Method::Aes128Cfb => (16, 16),
            Method::Aes192Cfb => (24, 16),
            Method::Aes256Cfb => (32, 16),
            Method::Camellia128Cfb => (16, 16),
            Method::Camellia192Cfb => (24, 16),
            Method::Camellia256Cfb => (32, 16),
            Method::Aes128Ctr => (16, 16),
            Method::Aes192Ctr => (24, 16),
            Method::Aes256Ctr => (32, 16),
            Method::ChaCha20 => (32, 16),
            Method::ChaCha20Ietf => (32, 16),
            Method::Blake3Aes128Gcm => (16, 16),
            Method::Blake3Aes256Gcm => (32, 32),
            Method::Blake3ChaCha20Poly1305 => (32, 32),
            Method::Aes128Gcm => (16, 16),
            Method::Aes192Gcm => (24, 24),
            Method::Aes256Gcm => (32, 32),
            Method::ChaCha20Poly1305 => (32, 32),
            Method::ChaCha20IetfPoly1305 => (32, 32),
            Method::XChaCha20IetfPoly1305 => (32, 32),
        };

        let key = if is_aead2022(&method) {
            if password.len() != key_len {
                return Err(io::Error::other(format!(
                    "key length must be {} for 2022 AEAD ciphers",
                    key_len
                )));
            }
            password.as_bytes().to_vec()
        } else {
            generate_key(password.as_bytes(), key_len)
        };

        Ok(Cipher {
            key,
            key_len,
            iv_or_salt_len,
            encrypt_iv_or_salt: vec![0u8; iv_or_salt_len],
            decrypt_iv_or_salt: vec![0u8; iv_or_salt_len],
            encrypt: None,
            decrypt: None,
            method,
        })
    }

    /// Initialize the encryption cipher.
    pub fn init_encrypt(&mut self) {
        let iv_or_salt = if self.is_aead2022() {
            let mut iv_or_salt = vec![0u8; self.iv_or_salt_len];
            rand::rng().fill(&mut iv_or_salt[..]);
            self.encrypt_iv_or_salt.copy_from_slice(&iv_or_salt);
            iv_or_salt
        } else {
            self.decrypt_iv_or_salt.clone()
        };
        self.encrypt = Some(self.new_cipher(&iv_or_salt));
    }

    /// Initialize the decryption cipher.
    pub fn init_decrypt(&mut self) {
        self.decrypt = Some(self.new_cipher(&self.decrypt_iv_or_salt));
    }

    /// Get the IV (or salt for GCM methods).
    /// For GCM methods (AES-128-GCM, AES-192-GCM, AES-256-GCM,
    /// Blake3Aes128Gcm, Blake3Aes256Gcm, Blake3ChaCha20Poly1305,
    /// ChaCha20Poly1305, ChaCha20IetfPoly1305, XChaCha20IetfPoly1305), this returns the salt.
    /// For other methods, this returns the IV.
    pub fn encrypt_iv_or_salt(&self) -> &[u8] {
        &self.encrypt_iv_or_salt
    }

    /// Get the IV (or salt for GCM methods).
    /// For GCM methods (AES-128-GCM, AES-192-GCM, AES-256-GCM,
    /// Blake3Aes128Gcm, Blake3Aes256Gcm, Blake3ChaCha20Poly1305,
    /// ChaCha20Poly1305, ChaCha20IetfPoly1305, XChaCha20IetfPoly1305), this returns the salt.
    /// For other methods, this returns the IV.
    pub fn decrypt_iv_or_salt(&self) -> &[u8] {
        &self.decrypt_iv_or_salt
    }

    /// Get the length of IV (or salt for GCM/ChaCha20-Poly1305 methods).
    /// For GCM methods (AES-128-GCM, AES-192-GCM, AES-256-GCM) and ChaCha20-Poly1305, this returns the salt length.
    /// For other methods, this returns the IV length.
    pub fn iv_or_salt_len(&self) -> usize {
        self.iv_or_salt_len
    }

    /// Get mutable reference to the IV (or salt for GCM/ChaCha20-Poly1305 methods).
    /// For GCM methods (AES-128-GCM, AES-192-GCM, AES-256-GCM) and ChaCha20-Poly1305, this is the salt.
    /// For other methods, this is the IV.
    pub fn decrypt_iv_or_salt_mut(&mut self) -> &mut [u8] {
        &mut self.decrypt_iv_or_salt[..]
    }

    pub fn encrypt_iv_or_salt_mut(&mut self) -> &mut [u8] {
        &mut self.encrypt_iv_or_salt[..]
    }

    fn new_cipher(&self, iv_or_salt: &[u8]) -> Box<dyn CipherCore + Send + Sync + 'static> {
        let key: &[u8] = &self.key;
        match self.method {
            Method::Aes128Cfb => Box::new(Aes128Cfb::new(key, iv_or_salt)),
            Method::Aes192Cfb => Box::new(Aes192Cfb::new(key, iv_or_salt)),
            Method::Aes256Cfb => Box::new(Aes256Cfb::new(key, iv_or_salt)),
            Method::Camellia128Cfb => Box::new(Camellia128Cfb::new(key, iv_or_salt)),
            Method::Camellia192Cfb => Box::new(Camellia192Cfb::new(key, iv_or_salt)),
            Method::Camellia256Cfb => Box::new(Camellia256Cfb::new(key, iv_or_salt)),
            Method::Aes128Ctr => Box::new(Aes128Ctr::new(key.into(), iv_or_salt.into())),
            Method::Aes192Ctr => Box::new(Aes192Ctr::new(key.into(), iv_or_salt.into())),
            Method::Aes256Ctr => Box::new(Aes256Ctr::new(key.into(), iv_or_salt.into())),
            Method::ChaCha20 => Box::new(ChaCha20::new(key.into(), iv_or_salt.into())),
            Method::ChaCha20Ietf => Box::new(ChaCha20Ietf::new(key.into(), iv_or_salt.into())),
            Method::Blake3Aes128Gcm => Box::new(Blake3Aes128Gcm::new(key, iv_or_salt)),
            Method::Blake3Aes256Gcm => Box::new(Blake3Aes256Gcm::new(key, iv_or_salt)),
            Method::Blake3ChaCha20Poly1305 => {
                Box::new(Blake3ChaCha20Poly1305::new(key, iv_or_salt))
            }
            // For GCM methods, iv_or_salt is actually salt
            Method::Aes128Gcm => Box::new(Aes128Gcm::new(key, iv_or_salt)),
            Method::Aes192Gcm => Box::new(Aes192Gcm::new(key, iv_or_salt)),
            Method::Aes256Gcm => Box::new(Aes256Gcm::new(key, iv_or_salt)),
            // For ChaCha20-Poly1305, iv_or_salt is actually salt
            Method::ChaCha20Poly1305 => Box::new(ChaCha20Poly1305::new(key, iv_or_salt)),
            // For ChaCha20-IETF-Poly1305, iv_or_salt is actually salt
            Method::ChaCha20IetfPoly1305 => Box::new(ChaCha20IetfPoly1305::new(key, iv_or_salt)),
            // For XChaCha20-Poly1305, iv_or_salt is actually salt
            Method::XChaCha20IetfPoly1305 => Box::new(XChaCha20IetfPoly1305::new(key, iv_or_salt)),
        }
    }

    pub fn tag_size(&self) -> usize {
        if self.is_aead() {
            16
        } else {
            0
        }
    }

    /// Check if the cipher is an AEAD cipher.
    pub fn is_aead(&self) -> bool {
        matches!(
            self.method,
            Method::Aes128Gcm
                | Method::Aes192Gcm
                | Method::Aes256Gcm
                | Method::ChaCha20Poly1305
                | Method::ChaCha20IetfPoly1305
                | Method::XChaCha20IetfPoly1305
                | Method::Blake3Aes128Gcm
                | Method::Blake3Aes256Gcm
                | Method::Blake3ChaCha20Poly1305
        )
    }

    /// Check if the cipher is a 2022 AEAD cipher.
    pub fn is_aead2022(&self) -> bool {
        is_aead2022(&self.method)
    }

    /// Encrypt data in place.
    pub fn encrypt_in_place(&mut self, input: &mut [u8]) -> io::Result<()> {
        if let Some(enc) = &mut self.encrypt {
            enc.encrypt_in_place(input)
        } else {
            Err(io::Error::other("encryption not initialized"))
        }
    }

    /// Decrypt data in place.
    pub fn decrypt_in_place(&mut self, input: &mut [u8]) -> io::Result<()> {
        if let Some(dec) = &mut self.decrypt {
            dec.decrypt_in_place(input)
        } else {
            Err(io::Error::other("decryption not initialized"))
        }
    }

    /// Reset the cipher.
    #[must_use]
    pub fn reset(&self) -> Cipher {
        Cipher {
            key: self.key.clone(),
            encrypt_iv_or_salt: vec![0u8; self.iv_or_salt_len],
            decrypt_iv_or_salt: vec![0u8; self.iv_or_salt_len],
            iv_or_salt_len: self.iv_or_salt_len,
            key_len: self.key_len,
            encrypt: None,
            decrypt: None,
            method: self.method,
        }
    }
}
