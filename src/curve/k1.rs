use crate::{CurveSign, CKMError, SigningSignature, SignRequest, Keystore};

use ecdsa::{SigningKey, signature::{Signature, Signer}};
use k256::Secp256k1;
use hex::*;

pub struct K1 {}

impl CurveSign for K1 {
    fn derive_key(&self, path: &str, password: &str, store: &impl Keystore) -> Result<Vec<u8>, CKMError> {
        todo!()
    }

    fn sign(&self, request: SignRequest, password: &str, store: &impl Keystore) -> Result<SigningSignature, CKMError> {
        let key = self.derive_key(request.path, password, store)?;
        let message = request.unsigend_data;
        _k1_sign_message(&key, &message)
    }
}

fn _k1_sign_message(key_bytes: &[u8], message_bytes: &[u8]) -> Result<SigningSignature, CKMError>{
    let key: SigningKey<Secp256k1> = SigningKey::from_bytes(key_bytes).map_err(|e| CKMError::FileReadError)?;
    let sig = key.try_sign(message_bytes).map_err(|e| CKMError::FileReadError)?.as_bytes();
    Ok(SigningSignature {
        r: encode(&sig[0..32]),
        s: encode(&sig[32..]),
        v: None
    })
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