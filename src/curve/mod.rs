use crate::{CKMError, Keystore, SignRequest};

pub(crate) mod k1;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SigningSignature {
    pub r: String,
    pub s: String,
    pub v: Option<String>,
}

pub trait CurveSign {
    fn derive_key(
        &self,
        request: &SignRequest,
        password: &str,
        store: &impl Keystore,
    ) -> Result<Vec<u8>, CKMError>;
    fn sign(
        &self,
        request: &SignRequest,
        password: &str,
        store: &impl Keystore,
    ) -> Result<SigningSignature, CKMError>;
}
