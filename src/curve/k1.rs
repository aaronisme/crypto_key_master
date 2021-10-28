use crate::{CurveSign, CKMError};

use ecdsa::{SigningKey, signature::{Signature, Signer}};
use k256::Secp256k1;
use hex::*;

pub struct K1 {}

impl CurveSign for K1 {
    fn derive_key(&self, store: &impl crate::Keystore, path: &str) -> Result<String, CKMError> {
        todo!()
    }

    fn sign(&self, request: crate::SignRequest, store: &impl crate::Keystore) -> Result<String, CKMError> {
        let test_private_key = "0000000000000000000000000000000000000000000000000000000000000003";
        let bytes = decode(test_private_key).unwrap();
        let key: SigningKey<Secp256k1> = SigningKey::from_bytes(&bytes).unwrap();
        let message = b"hello";

        let sig = key.try_sign(message).unwrap();
        
        let sighex = sig.as_bytes();
        Ok(encode(sighex))
    }
}

fn _k1_sign_message(key_bytes: &[u8], message_bytes: &[u8]) -> Result<String, CKMError>{
    let key: SigningKey<Secp256k1> = SigningKey::from_bytes(key_bytes).map_err(|e| CKMError::FileReadError)?;
    let sig = key.try_sign(message_bytes).map_err(|e| CKMError::FileReadError)?;
    Ok(encode(sig.as_bytes()))
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign() {
        let test_private_key = "0000000000000000000000000000000000000000000000000000000000000003";
        let bytes = decode(test_private_key).unwrap();
        let key: SigningKey<Secp256k1> = SigningKey::from_bytes(&bytes).unwrap();
        let message = b"hello";

        let sig = key.try_sign(message).unwrap();
        
        let sighex = sig.as_bytes();
        let r = &sighex[0..32];
        let s = &sighex[32..];
        println!("r:{:?}", encode(r));
        println!("s:{:?}", encode(s));
    }
}