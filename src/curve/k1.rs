use std::convert::TryInto;

use crate::{CKMError, CurveSign, Keystore, SignRequest, SigningSignature};

use bip32::{Seed, XPrv};
use ecdsa::{
    signature::{Signature, Signer},
    SigningKey,
};
use hex::*;
use k256::Secp256k1;

pub struct K1 {}

impl CurveSign for K1 {
    fn derive_key(
        &self,
        request: &SignRequest,
        password: &str,
        store: &impl Keystore,
    ) -> Result<Vec<u8>, CKMError> {
        let key = store.get_key(password, request.key_id.to_string())?;
        let seed_bytes: [u8; 64] = key.try_into().map_err(|_e| CKMError::SigningError)?;
        let seed = Seed::new(seed_bytes);
        let path = request.path;
        let child_xprv =
            XPrv::derive_from_path(&seed, &path.parse().map_err(|_e| CKMError::SigningError)?)
                .map_err(|_e| CKMError::FileReadError)?;
        let priv_key = child_xprv.private_key();
        Ok(priv_key.to_bytes().to_vec())
    }

    fn sign(
        &self,
        request: &SignRequest,
        password: &str,
        store: &impl Keystore,
    ) -> Result<SigningSignature, CKMError> {
        let key = self.derive_key(request, password, store)?;
        let message = &request.unsigend_data;
        _k1_sign_message(&key, message)
    }
}

fn _k1_sign_message(key_bytes: &[u8], message_bytes: &[u8]) -> Result<SigningSignature, CKMError> {
    let key: SigningKey<Secp256k1> =
        SigningKey::from_bytes(key_bytes).map_err(|e| CKMError::SigningError)?;
    let sig = key
        .try_sign(message_bytes)
        .map_err(|_e| CKMError::SigningError)?;
    // https://www.reddit.com/r/rust/comments/kd7s60/i_dont_understand_this_temporary_value_is_freed/
    let sig_bytes = sig.as_bytes();
    let r = encode(&sig_bytes[0..32]);
    let s = encode(&sig_bytes[32..]);
    Ok(SigningSignature { r, s, v: None })
}

#[cfg(test)]
mod tests {
    use crate::{fake::FakeKeystore, Curve};

    use super::*;
    use hex::encode;

    #[test]
    fn test_derive() {
        let fake_store = FakeKeystore {};

        let k1 = K1 {};

        let password = "pass";

        let request = SignRequest {
            path: "m/44'/0'/0'/0/0",
            unsigend_data: "hello".as_bytes().to_vec(),
            key_id: "123456",
            curve: Curve::Secp256k1,
        };

        let key_bytes = k1.derive_key(&request, password, &fake_store).unwrap();
        let key = encode(key_bytes);
        assert_eq!(
            key.as_str(),
            "e284129cc0922579a535bbf4d1a3b25773090d28c909bc0fed73b5e0222cc372"
        );
    }

    #[test]
    fn test_sign() {
        let fake_store = FakeKeystore {};

        let k1 = K1 {};

        let password = "pass";

        let request = SignRequest {
            path: "m/44'/0'/0'/0/0",
            unsigend_data: "hello".as_bytes().to_vec(),
            key_id: "123456",
            curve: Curve::Secp256k1,
        };

        let sig = k1.sign(&request, password, &fake_store).unwrap();

        let sig_expect = SigningSignature {
            r: "38a047f20caca5618cc56b0947939372a4c9c34cc05dd59dd75ef31f2323839d".to_string(),
            s: "0a6e719280a0503794715ae4403d09aec3664629f94435581a45a446d7c7ad2d".to_string(),
            v: None,
        };
        assert_eq!(sig_expect, sig);
    }
}
