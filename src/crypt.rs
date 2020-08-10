//! Various encryption-related utilities

use aes_soft::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use rand::{thread_rng, Rng};
use sha2::digest::Digest;
use sha2::Sha256;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

fn hash(key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.input(key.as_bytes());
    hasher.result().into()
}

pub fn gen_iv() -> [u8; 16] {
    thread_rng().gen()
}

pub fn encrypt_with(key: &str, value: &[u8], iv: &[u8]) -> Vec<u8> {
    let key = hash(key);
    let cipher = Aes256Cbc::new_var(&key, iv).unwrap();

    cipher.encrypt_vec(value)
}

pub fn decrypt_with(key: &str, value: &[u8], iv: &[u8]) -> Option<Vec<u8>> {
    let key = hash(key);
    let cipher = Aes256Cbc::new_var(&key, iv).unwrap();

    match cipher.decrypt_vec(value) {
        Ok(v) => Some(v),
        Err(_) => None,
    }
}
