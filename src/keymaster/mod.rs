
pub struct Signature {
    r: String,
    s: String,
}


pub trait KeyMaster {
    fn sign(&self, path: &str, hex: &str, password: &str, curve: &str) -> Result<Signature, CKMError>;
}


