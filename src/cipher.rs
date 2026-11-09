use std::convert::TryFrom;
use std::io;

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::{AeadInOut, Tag, inout::InOutBuf};
use aws_lc_rs::aead::{Aad, Algorithm, LessSafeKey, Nonce as RawNonce, UnboundKey};
use base64::Engine;
use camellia::{Camellia128, Camellia192, Camellia256};
use cipher::{BlockCipherEncrypt, KeyInit, KeyIvInit, StreamCipher, array::Array, consts::U8};
use ctr::Ctr128BE;

use serde::{Deserialize, Serialize};

use crate::util::{derive_blake3_subkey, generate_key, hkdf_sha1};

const AEAD_SUBKEY_INFO: &[u8] = b"ss-subkey";

trait CipherCore {
    /// Encrypt data in place.
    fn encrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()>;

    /// Decrypt data in place.
    fn decrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()>;
}

/// CFB mode cipher.
struct Cfb<C: BlockCipherEncrypt> {
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

// ChaCha20 is a type alias for ChaCha20Legacy
type ChaCha20 = chacha20::ChaCha20Legacy;
// ChaCha20Ietf is a type alias for ChaCha20
type ChaCha20Ietf = chacha20::ChaCha20;
// Salsa20 is a type alias for Salsa20
type Salsa20 = salsa20::Salsa20;

macro_rules! impl_cfb {
    ($name:ident, $cipher:ty) => {
        impl $name {
            fn new(key: &[u8], iv: &[u8]) -> $name {
                let enc = cfb_mode::BufEncryptor::<$cipher>::new_from_slices(key, iv)
                    .expect("invalid CFB key/iv length");
                let dec = cfb_mode::BufDecryptor::<$cipher>::new_from_slices(key, iv)
                    .expect("invalid CFB key/iv length");
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

impl CipherCore for Salsa20 {
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

/// AEAD engine backed by AWS-LC.
///
/// AWS-LC ships hand-written assembly for AES-GCM and ChaCha20-Poly1305, which
/// is several times faster than the portable RustCrypto implementation it
/// replaces. The record format is unchanged.
struct AwsLcAead {
    key: LessSafeKey,
    nonce: Vec<u8>,
}

impl AwsLcAead {
    fn new(algorithm: &'static Algorithm, key: &[u8]) -> AwsLcAead {
        let key = UnboundKey::new(algorithm, key).expect("invalid AEAD key length");
        AwsLcAead {
            key: LessSafeKey::new(key),
            nonce: vec![0u8; 12],
        }
    }

    /// Legacy AEAD method: the session key is HKDF-SHA1(key, salt).
    fn new_legacy(algorithm: &'static Algorithm, key: &[u8], salt: &[u8]) -> AwsLcAead {
        let mut subkey = vec![0u8; key.len()];
        hkdf_sha1(key, salt, AEAD_SUBKEY_INFO, &mut subkey)
            .expect("HKDF-SHA1 key derivation failed");
        AwsLcAead::new(algorithm, &subkey)
    }

    /// SIP022 method: the session key is the BLAKE3 XOF of key and seed.
    fn new_blake3(
        algorithm: &'static Algorithm,
        key: &[u8],
        salt: &[u8],
        key_len: usize,
    ) -> AwsLcAead {
        let subkey = derive_blake3_subkey(key, salt);
        AwsLcAead::new(algorithm, &subkey[..key_len])
    }

    fn nonce(&self) -> RawNonce {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.nonce);
        RawNonce::assume_unique_for_key(nonce)
    }
}

/// Seal `buffer` in place with a one-off key and 96 bit nonce, appending the
/// 16 byte authentication tag.
///
/// This is the stateless form of the same primitive `AwsLcAead` wraps. The
/// AEAD-2022 UDP path needs it because every datagram derives a fresh session
/// subkey from its session id, so there is no stream-scoped cipher to reuse.
fn aead_seal(
    algorithm: &'static Algorithm,
    key: &[u8],
    nonce: &[u8],
    buffer: &mut Vec<u8>,
) -> io::Result<()> {
    let key = UnboundKey::new(algorithm, key)
        .map_err(|e| io::Error::other(format!("invalid AEAD key length: {e:?}")))?;
    let nonce = RawNonce::try_assume_unique_for_key(nonce)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid nonce"))?;
    let tag = LessSafeKey::new(key)
        .seal_in_place_separate_tag(nonce, Aad::empty(), buffer.as_mut_slice())
        .map_err(|e| io::Error::other(format!("AEAD encryption failed: {e:?}")))?;
    buffer.extend_from_slice(tag.as_ref());
    Ok(())
}

/// Open `buffer` in place with a one-off key and 96 bit nonce, stripping the
/// 16 byte authentication tag.
///
/// The plaintext stays at the front of `buffer`, which is truncated to its
/// length.
fn aead_open(
    algorithm: &'static Algorithm,
    key: &[u8],
    nonce: &[u8],
    buffer: &mut Vec<u8>,
) -> io::Result<()> {
    let key = UnboundKey::new(algorithm, key)
        .map_err(|e| io::Error::other(format!("invalid AEAD key length: {e:?}")))?;
    let nonce = RawNonce::try_assume_unique_for_key(nonce)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid nonce"))?;
    let plaintext_len = LessSafeKey::new(key)
        .open_in_place(nonce, Aad::empty(), buffer.as_mut_slice())
        .map_err(|e| {
            io::Error::other(format!(
                "AEAD decryption failed (authentication failed): {e:?}"
            ))
        })?
        .len();
    buffer.truncate(plaintext_len);
    Ok(())
}

/// Seal `buffer` in place with the per-packet AEAD of a SIP022 method,
/// appending the 16 byte authentication tag.
///
/// AEAD-2022 derives a fresh session subkey for every datagram, so the caller
/// only supplies the method, the subkey and the 96 bit nonce. The ChaCha20
/// variant uses a 192 bit nonce and the pre-shared key directly, which is the
/// one case AWS-LC cannot serve.
pub fn udp_seal(method: Method, key: &[u8], nonce: &[u8], buffer: &mut Vec<u8>) -> io::Result<()> {
    match method {
        Method::Blake3Aes128Gcm => aead_seal(&aws_lc_rs::aead::AES_128_GCM, key, nonce, buffer),
        Method::Blake3Aes256Gcm => aead_seal(&aws_lc_rs::aead::AES_256_GCM, key, nonce, buffer),
        Method::Blake3ChaCha20Poly1305 => xchacha_seal(key, nonce, buffer),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{method:?} is not a 2022 AEAD method"),
        )),
    }
}

/// Open `buffer` in place with the per-packet AEAD of a SIP022 method,
/// stripping the 16 byte authentication tag.
pub fn udp_open(method: Method, key: &[u8], nonce: &[u8], buffer: &mut Vec<u8>) -> io::Result<()> {
    match method {
        Method::Blake3Aes128Gcm => aead_open(&aws_lc_rs::aead::AES_128_GCM, key, nonce, buffer),
        Method::Blake3Aes256Gcm => aead_open(&aws_lc_rs::aead::AES_256_GCM, key, nonce, buffer),
        Method::Blake3ChaCha20Poly1305 => xchacha_open(key, nonce, buffer),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{method:?} is not a 2022 AEAD method"),
        )),
    }
}

/// Seal `buffer` in place with a one-off key and 192 bit nonce
/// (XChaCha20-Poly1305), appending the 16 byte authentication tag.
///
/// AWS-LC has no XChaCha20, so this is the one AEAD-2022 path that stays on
/// RustCrypto.
fn xchacha_seal(key: &[u8], nonce: &[u8], buffer: &mut Vec<u8>) -> io::Result<()> {
    use aes_gcm::aead::{AeadInOut, Buffer};

    let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let nonce = chacha20poly1305::XNonce::try_from(nonce)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid nonce"))?;
    cipher
        .encrypt_in_place(&nonce, &[], buffer as &mut dyn Buffer)
        .map_err(|e| io::Error::other(format!("AEAD encryption failed: {e}")))
}

/// Open `buffer` in place with a one-off key and 192 bit nonce
/// (XChaCha20-Poly1305), stripping the 16 byte authentication tag.
fn xchacha_open(key: &[u8], nonce: &[u8], buffer: &mut Vec<u8>) -> io::Result<()> {
    use aes_gcm::aead::{AeadInOut, Buffer};

    let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let nonce = chacha20poly1305::XNonce::try_from(nonce)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid nonce"))?;
    cipher
        .decrypt_in_place(&nonce, &[], buffer as &mut dyn Buffer)
        .map_err(|e| {
            io::Error::other(format!(
                "AEAD decryption failed (authentication failed): {e}"
            ))
        })
}

impl CipherCore for AwsLcAead {
    /// Encrypt data in place, writing the detached tag into the reserved tail.
    fn encrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()> {
        if data.len() < 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer too small for AEAD tag",
            ));
        }
        let plaintext_len = data.len() - 16;
        let (plaintext, tag_space) = data.split_at_mut(plaintext_len);
        let tag = self
            .key
            .seal_in_place_separate_tag(self.nonce(), Aad::empty(), plaintext)
            .map_err(|e| io::Error::other(format!("AEAD encryption failed: {e:?}")))?;
        tag_space.copy_from_slice(tag.as_ref());
        increment_nonce(&mut self.nonce);
        Ok(())
    }

    /// Decrypt data in place. The last 16 bytes are the authentication tag.
    fn decrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()> {
        if data.len() < 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer too small for AEAD tag",
            ));
        }
        self.key
            .open_in_place(self.nonce(), Aad::empty(), data)
            .map_err(|e| {
                io::Error::other(format!(
                    "AEAD decryption failed (authentication failed): {e:?}"
                ))
            })?;
        increment_nonce(&mut self.nonce);
        Ok(())
    }
}

fn increment_nonce(nonce: &mut [u8]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}

/// Shared AEAD encrypt/decrypt implementation for the RustCrypto backends.
///
/// Only the ciphers AWS-LC does not provide go through this: the 8 byte nonce
/// ChaCha20-Poly1305 variant and XChaCha20-Poly1305.
macro_rules! impl_aead_methods {
    ($make_nonce:expr, $tag_ty:ty) => {
        /// Encrypt data in place. Buffer must reserve 16 bytes for the authentication tag.
        ///
        /// The plaintext is encrypted directly inside `data`; the detached tag is
        /// written into the reserved tail, so no intermediate buffer is allocated.
        fn encrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()> {
            if data.len() < 16 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "buffer too small for AEAD tag",
                ));
            }
            let plaintext_len = data.len() - 16;
            let (plaintext, tag_space) = data.split_at_mut(plaintext_len);

            let nonce = $make_nonce(self.nonce.as_slice());
            let tag = self
                .inner
                .encrypt_inout_detached(&nonce, &[], InOutBuf::from(plaintext))
                .map_err(|e| io::Error::other(format!("AEAD encryption failed: {e}")))?;

            if tag.len() != tag_space.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "AEAD encryption output length mismatch",
                ));
            }
            tag_space.copy_from_slice(&tag);
            increment_nonce(&mut self.nonce);
            Ok(())
        }

        /// Decrypt data in place. Assumes the last 16 bytes are the authentication tag.
        ///
        /// The ciphertext is decrypted directly inside `data`; the tag is only
        /// borrowed, so no intermediate buffer is allocated.
        fn decrypt_in_place(&mut self, data: &mut [u8]) -> io::Result<()> {
            if data.len() < 16 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "buffer too small for AEAD tag",
                ));
            }
            let plaintext_len = data.len() - 16;
            let (ciphertext, tag_space) = data.split_at_mut(plaintext_len);

            let tag = Tag::<$tag_ty>::try_from(&tag_space[..]).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "AEAD tag length does not match the cipher",
                )
            })?;
            let nonce = $make_nonce(self.nonce.as_slice());
            self.inner
                .decrypt_inout_detached(&nonce, &[], InOutBuf::from(ciphertext), &tag)
                .map_err(|e| {
                    io::Error::other(format!(
                        "AEAD decryption failed (authentication failed): {e}"
                    ))
                })?;
            increment_nonce(&mut self.nonce);
            Ok(())
        }
    };
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
        let key = chacha20poly1305::Key::try_from(subkey.as_slice()).expect("invalid key length");
        ChaCha20Poly1305 {
            inner: chacha20poly1305::ChaChaPoly1305::<ChaCha20, U8>::new(&key),
            nonce: vec![0u8; 8],
        }
    }
}

impl CipherCore for ChaCha20Poly1305 {
    impl_aead_methods!(
        |n| Array::<u8, U8>::try_from(n).expect("invalid nonce length"),
        chacha20poly1305::ChaChaPoly1305<ChaCha20, U8>
    );
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
        let key = chacha20poly1305::Key::try_from(subkey.as_slice()).expect("invalid key length");
        XChaCha20IetfPoly1305 {
            inner: chacha20poly1305::XChaCha20Poly1305::new(&key),
            nonce: vec![0u8; 24],
        }
    }
}

impl CipherCore for XChaCha20IetfPoly1305 {
    impl_aead_methods!(
        |n| chacha20poly1305::XNonce::try_from(n).expect("invalid nonce length"),
        chacha20poly1305::XChaCha20Poly1305
    );
}

/// Per-session value that turns the long-term key into a working cipher.
///
/// The kind depends on the method: an AEAD cipher derives its session subkey
/// from a random salt, while a stream cipher takes an IV that initializes the
/// keystream directly. Both are public, short-lived, and regenerated for every
/// session, which is what separates them from the key itself.
#[derive(Debug, Clone)]
pub enum Seed {
    /// AEAD methods: random salt, used as the HKDF salt of the session subkey.
    Salt(Vec<u8>),
    /// Stream ciphers: IV that initializes the keystream.
    Iv(Vec<u8>),
}

impl Seed {
    /// A zero-filled seed of the kind that `method` uses.
    fn zeroed(method: &Method, len: usize) -> Seed {
        if is_aead(method) {
            Seed::Salt(vec![0u8; len])
        } else {
            Seed::Iv(vec![0u8; len])
        }
    }

    /// An all-zero seed of the same kind and length.
    fn zeroed_like(&self) -> Seed {
        match self {
            Seed::Salt(bytes) => Seed::Salt(vec![0u8; bytes.len()]),
            Seed::Iv(bytes) => Seed::Iv(vec![0u8; bytes.len()]),
        }
    }

    /// Raw bytes of the seed.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Seed::Salt(bytes) | Seed::Iv(bytes) => bytes,
        }
    }

    /// Mutable raw bytes, for filling the seed from the wire or from the RNG.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        match self {
            Seed::Salt(bytes) | Seed::Iv(bytes) => bytes,
        }
    }
}

pub struct Cipher {
    key: Vec<u8>,
    key_len: usize,
    /// Seed used when encrypting, written at the start of an outgoing stream.
    encrypt_seed: Seed,
    /// Seed used when decrypting, read from the start of an incoming stream.
    decrypt_seed: Seed,
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
    #[serde(rename = "salsa20")]
    Salsa20,
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

fn is_aead(method: &Method) -> bool {
    matches!(
        method,
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

/// Whether `method` is one of the SIP022 AEAD-2022 methods.
pub fn is_aead2022(method: &Method) -> bool {
    matches!(
        method,
        Method::Blake3Aes128Gcm | Method::Blake3Aes256Gcm | Method::Blake3ChaCha20Poly1305
    )
}

impl Method {
    /// Whether this is the ChaCha20-Poly1305 SIP022 method.
    ///
    /// It differs from the AES variants in more than the cipher: its datagrams
    /// carry a 24 byte random nonce in place of the encrypted 16 byte separate
    /// header, and they are sealed with the pre-shared key rather than a
    /// per-session subkey.
    pub fn is_chacha2022(&self) -> bool {
        matches!(self, Method::Blake3ChaCha20Poly1305)
    }

    /// Key length in bytes, for methods that take a pre-shared key.
    ///
    /// Only meaningful for the AEAD-2022 methods, whose key comes from the
    /// configuration verbatim rather than being derived from a password.
    pub fn psk_len(&self) -> usize {
        match self {
            Method::Blake3Aes128Gcm => 16,
            // The keyed-BLAKE3 methods and both 256 bit ciphers use 32 bytes.
            _ => 32,
        }
    }
}

impl Cipher {
    /// Create a new cipher.
    /// The password is used to derive the key for the cipher.
    /// The method is the cipher method to use.
    pub fn new(method: Method, password: &str) -> io::Result<Cipher> {
        let (key_len, seed_len) = match method {
            Method::Aes128Cfb => (16, 16),
            Method::Aes192Cfb => (24, 16),
            Method::Aes256Cfb => (32, 16),
            Method::Camellia128Cfb => (16, 16),
            Method::Camellia192Cfb => (24, 16),
            Method::Camellia256Cfb => (32, 16),
            Method::Aes128Ctr => (16, 16),
            Method::Aes192Ctr => (24, 16),
            Method::Aes256Ctr => (32, 16),
            Method::ChaCha20 => (32, 8),
            Method::ChaCha20Ietf => (32, 12),
            Method::Salsa20 => (32, 8),
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
            let psk = base64::prelude::BASE64_STANDARD
                .decode(password)
                .map_err(io::Error::other)?;
            if psk.len() != key_len {
                return Err(io::Error::other(format!(
                    "key length must be {} for 2022 AEAD ciphers",
                    key_len
                )));
            }
            psk
        } else {
            generate_key(password.as_bytes(), key_len)
        };

        let seed = Seed::zeroed(&method, seed_len);
        Ok(Cipher {
            key,
            key_len,
            encrypt_seed: seed.clone(),
            decrypt_seed: seed,
            encrypt: None,
            decrypt: None,
            method,
        })
    }

    /// Initialize the encryption cipher from the current encrypt seed.
    pub fn init_encrypt(&mut self) {
        self.encrypt = Some(self.make_core(self.encrypt_seed.as_bytes()));
    }

    /// Initialize the decryption cipher from the current decrypt seed.
    pub fn init_decrypt(&mut self) {
        self.decrypt = Some(self.make_core(self.decrypt_seed.as_bytes()));
    }

    /// Seed that opens an outgoing stream: a salt for AEAD methods, an IV for
    /// stream ciphers.
    pub fn encrypt_seed(&self) -> &Seed {
        &self.encrypt_seed
    }

    /// Seed that opens an incoming stream.
    pub fn decrypt_seed(&self) -> &Seed {
        &self.decrypt_seed
    }

    /// Mutable encrypt seed, for randomizing it before a new session.
    pub fn encrypt_seed_mut(&mut self) -> &mut Seed {
        &mut self.encrypt_seed
    }

    /// Mutable decrypt seed, for filling it from the wire before
    /// `init_decrypt`.
    pub fn decrypt_seed_mut(&mut self) -> &mut Seed {
        &mut self.decrypt_seed
    }

    /// Length of the seed in bytes.
    pub fn seed_len(&self) -> usize {
        self.encrypt_seed.as_bytes().len()
    }

    fn make_core(&self, seed: &[u8]) -> Box<dyn CipherCore + Send + Sync + 'static> {
        let key: &[u8] = &self.key;
        match self.method {
            Method::Aes128Cfb => Box::new(Aes128Cfb::new(key, seed)),
            Method::Aes192Cfb => Box::new(Aes192Cfb::new(key, seed)),
            Method::Aes256Cfb => Box::new(Aes256Cfb::new(key, seed)),
            Method::Camellia128Cfb => Box::new(Camellia128Cfb::new(key, seed)),
            Method::Camellia192Cfb => Box::new(Camellia192Cfb::new(key, seed)),
            Method::Camellia256Cfb => Box::new(Camellia256Cfb::new(key, seed)),
            Method::Aes128Ctr => {
                Box::new(Aes128Ctr::new_from_slices(key, seed).expect("invalid CTR key/iv"))
            }
            Method::Aes192Ctr => {
                Box::new(Aes192Ctr::new_from_slices(key, seed).expect("invalid CTR key/iv"))
            }
            Method::Aes256Ctr => {
                Box::new(Aes256Ctr::new_from_slices(key, seed).expect("invalid CTR key/iv"))
            }
            Method::ChaCha20 => {
                Box::new(ChaCha20::new_from_slices(key, seed).expect("invalid ChaCha20 key/iv"))
            }
            Method::ChaCha20Ietf => {
                Box::new(ChaCha20Ietf::new_from_slices(key, seed).expect("invalid ChaCha20 key/iv"))
            }
            Method::Salsa20 => {
                Box::new(Salsa20::new_from_slices(key, seed).expect("invalid Salsa20 key/iv"))
            }
            Method::Blake3Aes128Gcm => Box::new(AwsLcAead::new_blake3(
                &aws_lc_rs::aead::AES_128_GCM,
                key,
                seed,
                16,
            )),
            Method::Blake3Aes256Gcm => Box::new(AwsLcAead::new_blake3(
                &aws_lc_rs::aead::AES_256_GCM,
                key,
                seed,
                32,
            )),
            Method::Blake3ChaCha20Poly1305 => Box::new(AwsLcAead::new_blake3(
                &aws_lc_rs::aead::CHACHA20_POLY1305,
                key,
                seed,
                32,
            )),
            // AEAD methods treat the seed as a salt
            Method::Aes128Gcm => Box::new(AwsLcAead::new_legacy(
                &aws_lc_rs::aead::AES_128_GCM,
                key,
                seed,
            )),
            Method::Aes192Gcm => Box::new(AwsLcAead::new_legacy(
                &aws_lc_rs::aead::AES_192_GCM,
                key,
                seed,
            )),
            Method::Aes256Gcm => Box::new(AwsLcAead::new_legacy(
                &aws_lc_rs::aead::AES_256_GCM,
                key,
                seed,
            )),
            Method::ChaCha20Poly1305 => Box::new(ChaCha20Poly1305::new(key, seed)),
            Method::ChaCha20IetfPoly1305 => Box::new(AwsLcAead::new_legacy(
                &aws_lc_rs::aead::CHACHA20_POLY1305,
                key,
                seed,
            )),
            // For XChaCha20-Poly1305, prefix is actually salt
            Method::XChaCha20IetfPoly1305 => Box::new(XChaCha20IetfPoly1305::new(key, seed)),
        }
    }

    /// Largest payload that fits in one encrypted record.
    ///
    /// The length field is a u16, but the AEAD protocols only accept records up
    /// to 0x3fff, so stay within that bound.
    pub fn max_payload_size(&self) -> usize {
        if self.is_aead2022() {
            0xffff
        } else if self.is_aead() {
            0x3fff
        } else {
            64 * 1024
        }
    }

    pub fn tag_size(&self) -> usize {
        if self.is_aead() { 16 } else { 0 }
    }

    /// Check if the cipher is an AEAD cipher.
    pub fn is_aead(&self) -> bool {
        is_aead(&self.method)
    }

    /// Check if the cipher is a 2022 AEAD cipher.
    pub fn is_aead2022(&self) -> bool {
        is_aead2022(&self.method)
    }

    /// Cipher method.
    pub fn method(&self) -> Method {
        self.method
    }

    /// Pre-shared key (already decoded from base64 for the 2022 methods).
    pub fn key(&self) -> &[u8] {
        &self.key
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
        // Never seed the decrypt seed from the *old* encrypt seed (all zeros
        // for a freshly built cipher): that silently made every UDP packet use
        // an all-zero salt. The real value comes from the wire frame
        // (`CipherStream`) or from the UDP datagram header.
        let mut encrypt_seed = self.encrypt_seed.zeroed_like();
        rand::fill(encrypt_seed.as_mut_bytes());
        let mut decrypt_seed = self.decrypt_seed.zeroed_like();
        rand::fill(decrypt_seed.as_mut_bytes());

        Cipher {
            key: self.key.clone(),
            encrypt_seed,
            decrypt_seed,
            key_len: self.key_len,
            encrypt: None,
            decrypt: None,
            method: self.method,
        }
    }
}
