use std::{collections::HashMap, convert::TryInto};

use crate::*;
use aes::cipher::StreamCipher;
use ring::rand::{SecureRandom, SystemRandom};
use hex::encode;
use aes::{Aes128, Aes128Ctr, NewBlockCipher, cipher::FromBlockCipher};
use aes::cipher::{
    generic_array::GenericArray,
};

#[derive(Debug, Clone)]
pub struct LocalKeystore<'a> {
    keystores: HashMap<String,KeystoreObj<'a>>
}

impl LocalKeystore<'_> {
    pub fn new() -> Self {
        Self { keystores: HashMap::new() }
    }
}


#[derive(Debug, Clone)]
struct KeystoreObj<'a> {
    ciphertext: String,
    cipher: &'a str,
    cipherparams: Cipherparams,
    kdf: &'a str,
    kdfparams: Kdfparams,
    mac: String,
}

impl KeystoreObj<'_> {
    fn new(ciphertext: String, cipherparams: Cipherparams, kdfparams: Kdfparams, mac: String) -> Self {
        Self { ciphertext, cipher: "aes-128-ctr", cipherparams, kdf:"scrypt", kdfparams, mac }
    }
}


#[derive(Debug, Clone)]
struct Cipherparams {
    iv: String,
}

impl Cipherparams {
    fn new(iv: String) -> Self {
        Self {
            iv
        }
    }
}

#[derive(Debug, Clone)]
struct Kdfparams {
    dklen: u32,
    salt: String,
    n: u32,
    r: u32,
    p: u32
}

impl Default for Kdfparams {
    fn default() -> Self {
        Self {
            dklen: 32,
            n: 8192,
            r: 8,
            p:1,
            salt: "".to_string()
        }
    }
}

fn random_bytes(length: u32) -> Result<Vec<u8>, CKMError>{
    match length {
        128 | 256 => {
            let size = length / 8;
            let mut key = vec![0u8; size.try_into().unwrap()];
            let system_random = SystemRandom::new();
            return match system_random.fill(&mut key) {
                Ok(_) => Ok(key),
                Err(_e) => Err(CKMError::NotFound("generate error".to_string()))
            };
        },
        _ => Err(CKMError::NotFound("length is not right".to_string())),
    }
}

impl Keystore for LocalKeystore<'_> {
    fn generate_entropy(&self, length: u32) -> Result<String, CKMError> {
        match random_bytes(length) {
            Ok(v) => {
                Ok(encode(v))
            },
            Err(e) => Err(e)
        }
    }

    fn get_key(&self, password: &str, key_id: &str) -> Result<String, CKMError> {
        todo!()
    }

    fn write_key(&self, password: &str, key: &str) -> Result<String, CKMError> {
        let key = b"very secret key.";
        let mut data = [1,2,3,4,5,6,7].to_vec();
        _encrypt(key, &mut data);
        println!("{:?}", data);
        Ok(encode(data))
    }
}

fn _encrypt<'a>(key: &[u8; 16], data: &'a mut Vec<u8>)  -> &'a mut Vec<u8> {
    let mut nonce = [0u8; 16];
    let system_random = SystemRandom::new();
    system_random.fill(&mut nonce);
    let mut wrap_key =  GenericArray::from_slice(key);
    let iv = GenericArray::from_slice(&nonce);
    let mut cipher = Aes128Ctr::from_block_cipher(Aes128::new(&wrap_key), iv);
    cipher.apply_keystream(data);
    data
}