use openssl::symm;
use openssl::error::ErrorStack;
use util::generate_key;

pub struct Cipher {
    pub cipher: symm::Cipher,
    pub key: Vec<u8>,
    pub d_iv: Vec<u8>,
    pub e_iv: Vec<u8>,
    pub iv_len: usize,
}

impl Cipher {
    pub fn new(method: &str, password: &str) -> Cipher {
        let cipher = match method {
            "aes-256-cfb" => symm::Cipher::aes_256_cfb128(),
            _ => panic!("method not supported"),
        };

        let key = generate_key(password.as_bytes(), cipher.key_len());
        Cipher {
            cipher: cipher,
            key: Vec::from(&key[..]),
            d_iv: vec![],
            e_iv: vec![],
            iv_len: cipher.iv_len().unwrap_or_default(),
        }
    }

    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        symm::encrypt(
            self.cipher.clone(),
            &self.key,
            Some(self.e_iv.to_vec().as_slice()),
            data,
        )
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        symm::decrypt(
            self.cipher.clone(),
            &self.key,
            Some(self.d_iv.to_vec().as_slice()),
            data,
        )
    }
}
