

pub trait KeyStore {
    /// generate the entropy to provide to outside world
    fn generate_entropy() -> Result<String, CKMError>;

    /// get the key by id 
    fn get_key(&self, password: &str, key_id: &str) -> Result<String, CKMError>;

    /// write key to store
    fn write_key(&self, password: &str, key: &str) -> Result<String, CKMError>;
}