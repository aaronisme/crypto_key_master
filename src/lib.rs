mod curve;
mod error;
mod keystore;

pub use curve::{k1::K1, CurveSign, SigningSignature};
pub use error::CKMError;
pub use keystore::*;

pub enum Curve {
    Secp256k1,
    Secp256R1,
    Ed25519,
}

pub struct SignRequest<'a> {
    pub path: &'a str,
    pub unsigend_data: Vec<u8>,
    pub key_id: &'a str,
    pub curve: Curve,
}

pub struct KeyMaster<Store = LocalKeystore> {
    inner: KeyMasterInner<Store>,
}

pub struct KeyMasterInner<Store> {
    store: Store,
}

impl<Store: Keystore> KeyMaster<Store> {
    pub fn new(store: Store) -> Self {
        Self {
            inner: KeyMasterInner { store },
        }
    }

    pub fn sign(
        &self,
        sign_request: SignRequest,
        password: &str,
    ) -> Result<SigningSignature, CKMError> {
        dispatch(sign_request, password, &self.inner.store)
    }

    pub fn generate_entropy(&self, length: u32) -> Result<Vec<u8>, CKMError> {
        self.inner.store.generate_entropy(length)
    }

    pub fn write_seed(&mut self, password: &str, seed: String) -> Result<String, CKMError> {
        self.inner.store.write_key(password, seed)
    }
}

pub fn dispatch(
    sign_request: SignRequest,
    password: &str,
    store: &impl Keystore,
) -> Result<SigningSignature, CKMError> {
    match sign_request.curve {
        Curve::Secp256k1 => {
            let k1 = K1 {};
            k1.sign(&sign_request, password, store)
        }
        _ => todo!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeKeystore;
    #[test]
    fn sample_usage() {
        let fake_store = FakeKeystore {};

        let mut key_master = KeyMaster {
            inner: KeyMasterInner { store: fake_store },
        };

        let entropy = key_master.generate_entropy(32).unwrap();
        assert_eq!(entropy, vec![0u8; 32]);

        let key_id = key_master.write_seed("123", "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4".to_string()).unwrap();

        assert_eq!(key_id, "123456".to_string());

        let request = SignRequest {
            path: "m/44'/0'/0'/0/0",
            unsigend_data: "hello".as_bytes().to_vec(),
            key_id: "123456",
            curve: Curve::Secp256k1,
        };

        let sig = key_master.sign(request, "123").unwrap();

        let sig_expect = SigningSignature {
            r: "38a047f20caca5618cc56b0947939372a4c9c34cc05dd59dd75ef31f2323839d".to_string(),
            s: "0a6e719280a0503794715ae4403d09aec3664629f94435581a45a446d7c7ad2d".to_string(),
            v: None,
        };
        assert_eq!(sig_expect, sig);
    }
}
