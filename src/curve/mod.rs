use crate:: {Signature, Keystore, Signature};

pub trait CurveSign {
    fn derive_key(&self, store: &impl Keystore, path: &str) -> Result<String, CKMError>;
    fn sign(&self, request: SignRequest, store: &impl Keystore) -> Result<Signature, CKMError>;
}