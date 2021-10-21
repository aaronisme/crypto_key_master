pub mod local;

use crate::CKMError;
pub use local::LocalKeystore;

pub trait Keystore {
    /// generate the entropy to provide to outside world
    fn generate_entropy(&self, length: u32) -> Result<String, CKMError>;

    /// get the key by id
    fn get_key(&self, password: &str, key_id: &str) -> Result<String, CKMError>;

    /// write key to store
    fn write_key(self, password: &str, key: &str) -> Result<String, CKMError>;
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_generate_entropy() {
        let local_keystore = LocalKeystore::new();
        keystore_test_entropy(local_keystore);
    }

    #[test]
    fn test_write_key() {
        let mut local_keystore = LocalKeystore::new();
        keystore_write_key(local_keystore);
    }

    fn keystore_test_entropy(keystore: impl Keystore) {
        let a = keystore.generate_entropy(128).unwrap();
        assert_eq!(a.len(), 32);
        let b = keystore.generate_entropy(256).unwrap();
        assert_eq!(b.len(), 64);
    }

    fn keystore_write_key(keystore: impl Keystore) {
        let v = keystore.write_key("123", "456").unwrap();
        println!("{:?}", v);
        assert_eq!(v, "123");
    }
}
