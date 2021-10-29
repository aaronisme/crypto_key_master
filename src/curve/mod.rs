use crate::{SignRequest, Keystore, CKMError};

mod k1;

pub struct SigningSignature {
    r: String,
    s: String,
    v: Option<String>,
}


pub trait CurveSign {
    fn derive_key(&self, request: &SignRequest, password: &str, store: &impl Keystore) -> Result<Vec<u8>, CKMError>;
    fn sign(&self, request: &SignRequest, password: &str, store: &impl Keystore) -> Result<SigningSignature, CKMError>;
}