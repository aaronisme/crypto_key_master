use std::convert::TryInto;

use crate::{CurveSign, CKMError, SigningSignature, SignRequest, Keystore};

use ecdsa::{SigningKey, signature::{Signature, Signer}};
use k256::Secp256k1;
use hex::*;
use bip32::{Seed, XPrv};

pub struct K1 {}

impl CurveSign for K1 {
    fn derive_key(&self, request: &SignRequest, password: &str, store: &impl Keystore) -> Result<Vec<u8>, CKMError> {
        let key = store.get_key(password, request.key_id.to_string())?;
        let seed_bytes: [u8; 64] = key.try_into().map_err(|_e| CKMError::FileReadError)?;
        let seed = Seed::new(seed_bytes);
        let path = request.path;
        let child_xprv = 
        XPrv::derive_from_path(&seed, &path.parse().map_err(|_e|CKMError::FileReadError)?)
        .map_err(|_e|CKMError::FileReadError)?;
        let priv_key = child_xprv.private_key();
        Ok(priv_key.to_bytes().to_vec())
    }

    fn sign(&self, request: &SignRequest, password: &str, store: &impl Keystore) -> Result<SigningSignature, CKMError> {
        let key = self.derive_key(request, password, store)?;
        let message = &request.unsigend_data;
        _k1_sign_message(&key, message)
    }
}

fn _k1_sign_message(key_bytes: &[u8], message_bytes: &[u8]) -> Result<SigningSignature, CKMError>{
    let key: SigningKey<Secp256k1> = SigningKey::from_bytes(key_bytes).map_err(|e| CKMError::FileReadError)?;
    let sig = key.try_sign(message_bytes).map_err(|_e| CKMError::FileReadError)?;
    // https://www.reddit.com/r/rust/comments/kd7s60/i_dont_understand_this_temporary_value_is_freed/
    let sig_bytes = sig.as_bytes();
    let r = encode(&sig_bytes[0..32]);
    let s = encode(&sig_bytes[32..]);
    Ok(SigningSignature {
        r,
        s,
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