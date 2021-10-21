use std::{collections::HashMap, convert::TryInto};

use crate::*;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::StreamCipher;
use aes::{cipher::FromBlockCipher, Aes128, Aes128Ctr, NewBlockCipher};
use hex::encode;
use ring::rand::{SecureRandom, SystemRandom};
use scrypt::{scrypt, ScryptParams};
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone, Default)]
pub struct LocalKeystore<'a> {
    keystores: HashMap<String, KeystoreObj<'a>>,
}

impl LocalKeystore<'_> {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Default)]
struct KeystoreObj<'a> {
    ciphertext: String,
    cipher: &'a str,
    cipherparams: Cipherparams,
    kdf: &'a str,
    kdfparams: Kdfparams,
    mac: String,
}

impl KeystoreObj<'_> {
    fn new(
        ciphertext: String,
        cipherparams: Cipherparams,
        kdfparams: Kdfparams,
        mac: String,
    ) -> Self {
        Self {
            ciphertext,
            cipher: "aes-128-ctr",
            cipherparams,
            kdf: "scrypt",
            kdfparams,
            mac,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Cipherparams {
    iv: String,
}

impl Cipherparams {
    fn new(iv: String) -> Self {
        Self { iv }
    }
}

#[derive(Debug, Clone)]
struct Kdfparams {
    dklen: u32,
    salt: String,
    n: u32,
    r: u32,
    p: u32,
}

impl Default for Kdfparams {
    fn default() -> Self {
        Self {
            dklen: 16,
            n: 8192,
            r: 8,
            p: 1,
            salt: "".to_string(),
        }
    }
}

fn random_bytes(length: u32) -> Result<Vec<u8>, CKMError> {
    match length {
        128 | 256 => {
            let size = length / 8;
            let mut key = vec![0u8; size.try_into().unwrap()];
            _random_generator(&mut key);
            Ok(key)
        }
        _ => Err(CKMError::NotFound("length is not right".to_string())),
    }
}

impl Keystore for LocalKeystore<'_> {
    fn generate_entropy(&self, length: u32) -> Result<String, CKMError> {
        match random_bytes(length) {
            Ok(v) => Ok(encode(v)),
            Err(e) => Err(e),
        }
    }

    fn get_key(&self, password: &str, key_id: &str) -> Result<String, CKMError> {
        todo!()
    }

    fn write_key(mut self, password: &str, key: &str) -> Result<String, CKMError> {
        let mut store_id = [0u8; 16];
        _random_generator(&mut store_id);
        let (password_hash, salt) = _password_hash(password);

        let mut encrypted_key_bytes = key.as_bytes().to_vec();
        let (_, iv) = _encrypt(&password_hash, &mut encrypted_key_bytes);

        let mut mac = password.as_bytes().to_vec();
        mac.extend(&encrypted_key_bytes);

        let mut hasher = Sha3_256::default();
        hasher.input(&mac);
        let mac_bytes = hasher.result();
        let cipherparams = Cipherparams::new(encode(iv));
        let kdf_params = Kdfparams {
            salt: encode(salt),
            ..Default::default()
        };
        let keystore_obj = KeystoreObj::new(
            encode(encrypted_key_bytes),
            cipherparams,
            kdf_params,
            encode(mac_bytes),
        );
        self.keystores.insert(encode(store_id), keystore_obj);
        println!("{:?}", self.keystores);
        Ok(encode(store_id))
    }
}

fn _encrypt<'a>(key: &[u8; 16], data: &'a mut Vec<u8>) -> (&'a mut Vec<u8>, Vec<u8>) {
    let mut nonce = [0u8; 16].to_vec();
    _random_generator(&mut nonce);
    let mut wrap_key = GenericArray::from_slice(key);
    let iv = GenericArray::from_slice(&nonce);
    let mut cipher = Aes128Ctr::from_block_cipher(Aes128::new(&wrap_key), iv);
    cipher.apply_keystream(data);
    (data, nonce)
}

fn _password_hash(password: &str) -> ([u8; 16], [u8; 16]) {
    let password_bytes = password.as_bytes();
    let mut salt = [0u8; 16];
    let mut password_hash = [0u8; 16];
    _random_generator(&mut salt);
    let params = ScryptParams::new(13, 8, 1).unwrap();
    scrypt(&password_bytes, &salt, &params, &mut password_hash);
    (password_hash, salt)
}

fn _random_generator(data: &mut [u8]) -> Result<&mut [u8], CKMError> {
    let system_random = SystemRandom::new();
    match system_random.fill(data) {
        Ok(_) => Ok(data),
        Err(_e) => Err(CKMError::RandomError),
    }
}
