
pub mod local;

pub use local::LocalKeystore;
use crate::CKMError;


pub trait Keystore {
    /// generate the entropy to provide to outside world
    fn generate_entropy(&self, length: u32) -> Result<String, CKMError>;

    /// get the key by id 
    fn get_key(&self, password: &str, key_id: &str) -> Result<String, CKMError>;

    /// write key to store
    fn write_key(&self, password: &str, key: &str) -> Result<String, CKMError>;
}


#[cfg(test)]
mod tests {
    
    use super::*;

    #[test]
    fn test_generate_entropy() {
        let localKeystore = LocalKeystore::default();
        keystore_test_entropy(localKeystore);
    }

    

    fn keystore_test_entropy(keystore: impl Keystore) {
        let a = keystore.generate_entropy(128).unwrap();
        assert_eq!(a.len(), 32);
        let b = keystore.generate_entropy(256).unwrap();
        assert_eq!(b.len(), 64);
    }
    
}
