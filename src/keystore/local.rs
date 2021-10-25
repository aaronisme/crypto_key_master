use std::{collections::HashMap, convert::TryInto};
use std::str;

use crate::*;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{StreamCipher, StreamCipherSeek};
use aes::{cipher::FromBlockCipher, Aes128, Aes128Ctr, NewBlockCipher};
use hex::{encode, decode};
use ring::rand::{SecureRandom, SystemRandom};
use scrypt::{scrypt, ScryptParams};
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone, Default)]
pub struct LocalKeystore {
    keystores: HashMap<String, KeystoreObj>,
}

impl LocalKeystore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone)]
struct KeystoreObj {
    ciphertext: Vec<u8>,
    cipher: String,
    cipherparams: Cipherparams,
    kdf: String,
    kdfparams: Kdfparams,
    mac: Vec<u8>,
}

impl KeystoreObj {
    fn new(
        ciphertext: Vec<u8>,
        cipherparams: Cipherparams,
        kdfparams: Kdfparams,
        mac: Vec<u8>,
    ) -> Self {
        Self {
            ciphertext,
            cipher: "aes-128-ctr".to_string(),
            cipherparams,
            kdf: "scrypt".to_string(),
            kdfparams,
            mac,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Cipherparams {
    iv: Vec<u8>,
}

impl Cipherparams {
    fn new(iv: Vec<u8>) -> Self {
        Self { iv }
    }
}

#[derive(Debug, Clone)]
struct Kdfparams {
    dklen: u32,
    salt: Vec<u8>,
    log_n: u8,
    r: u32,
    p: u32,
}

impl Default for Kdfparams {
    fn default() -> Self {
        Self {
            dklen: 16,
            log_n: 13,
            r: 8,
            p: 1,
            salt: Vec::new(),
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

impl Keystore for LocalKeystore {
    fn generate_entropy(&self, length: u32) -> Result<Vec<u8>, CKMError> {
        match random_bytes(length) {
            Ok(v) => Ok(v),
            Err(e) => Err(e),
        }
    }

    fn get_key(&self, password: &str, key_id: String) -> Result<Vec<u8>, CKMError> {
        let value = self.keystores.get(&key_id);
        value
        .ok_or(CKMError::NotExist)
        .map(|obj| {
            match _verify_password(&obj.mac, &password.to_string(), &obj.ciphertext) {
                true => {
                    let mut password_hash = vec![0; obj.kdfparams.dklen.try_into().unwrap()];
                    let password_bytes = password.as_bytes();
                    let salt =  &obj.kdfparams.salt;
                    let params = ScryptParams::new(obj.kdfparams.log_n, obj.kdfparams.r, obj.kdfparams.p).unwrap();
                    scrypt(password_bytes, salt, &params, &mut password_hash);
                    _decrypt(&obj.ciphertext, &password_hash, &obj.cipherparams.iv)
                },
                false => todo!(),
            }
        })
    }

    fn write_key(&mut self, password: &str, key: &str) -> Result<String, CKMError> {
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
        let cipherparams = Cipherparams::new(iv);
        let kdf_params = Kdfparams {
            salt: salt.to_vec(),
            ..Default::default()
        };
        let keystore_obj = KeystoreObj::new(
            encrypted_key_bytes,
            cipherparams,
            kdf_params,
            mac_bytes.to_vec(),
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

fn _decrypt(ciphertext:  &Vec<u8>, password: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    let passord_bytes = GenericArray::from_slice(password);
    let iv_bytes = GenericArray::from_slice(iv);
    
    let mut cipher = Aes128Ctr::from_block_cipher(Aes128::new(&passord_bytes), iv_bytes);
    let mut ciphertext_bytes = ciphertext.clone();
    cipher.seek(0);
    cipher.apply_keystream(&mut ciphertext_bytes);
    ciphertext_bytes
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

fn _verify_password(mac: &Vec<u8>, password: &String, ciphertext: &Vec<u8>) -> bool {

    let mut pass_bytes = password.as_bytes().to_vec();
    let ciphertext_bytes = ciphertext;

    pass_bytes.extend(ciphertext_bytes);
    let mut hasher = Sha3_256::default();
    hasher.input(&pass_bytes);
    let mac_bytes = hasher.result();
    mac == &mac_bytes.to_vec()
}



#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_verify_password() {
        let mac_hash = "d7190eb194ff9494625514b6d178c87f99c5973e28c398969d2233f2960a573e";
        let result = _verify_password(&decode(mac_hash).unwrap(), &"123".to_string(), &"456".as_bytes().to_vec());
        assert_eq!(result, true);
        let mac_hash = "d7190eb194ff9494625514b6d178c87f99c5973e28c398969d2233f2960a573d";
        let result = _verify_password(&decode(mac_hash).unwrap(), &"123".to_string(), &"456".as_bytes().to_vec());
        assert_eq!(result, false);
    }

    #[test]
    fn test_decrypt () {
        let a = "622cd4755e6e6a89068bdcd1e886ac10".to_string();
        let c = "d92871".to_string();
        let iv = "0385eaa610fe1dee1d1f48d161ee4dae".to_string();
        let a = _decrypt(&decode(c).unwrap(), &decode(a).unwrap(), &decode(iv).unwrap());
        assert_eq!(str::from_utf8(&a).unwrap(), "456")
    }

}
