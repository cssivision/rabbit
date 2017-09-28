use openssl::symm;
use openssl::sha::sha256;
use openssl::error::ErrorStack;

pub struct Cipher {
    pub cipher: symm::Cipher,
    pub key: Vec<u8>,
    pub iv: Option<Vec<u8>>,
}

impl Cipher {
    pub fn new(method: &str, password: &str) -> Cipher {
        let cipher = match method {
            "aes-256-cfb" => symm::Cipher::aes_256_cfb128(),
            _ => panic!("method not supported"),
        };
        let key = sha256(password.as_bytes());
        Cipher {
            cipher: cipher,
            key: Vec::from(&key[..]),
            iv: None,
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        unimplemented!()
    }
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        unimplemented!()
    }
}
