use std::convert::TryInto;

use crate::*;
use ring::rand::{SecureRandom, SystemRandom};
use hex::encode;

#[derive(Default, Debug, Clone)]
pub struct LocalKeystore {}

fn random_bytes(length: u32) -> Result<Vec<u8>, CKMError>{
    let size: u32;
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

impl Keystore for LocalKeystore {
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
        todo!()
    }
}