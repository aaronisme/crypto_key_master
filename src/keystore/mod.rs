pub(crate) mod fake;
mod local;

use crate::CKMError;
pub use local::LocalKeystore;

/// Keystore trait for storing keys, it can be local file or secure element etc.
pub trait Keystore {
    /// generate the entropy to provide to outside world
    fn generate_entropy(&self, length: u32) -> Result<Vec<u8>, CKMError>;

    /// get the key by id
    fn get_key(&self, password: &str, key_id: String) -> Result<Vec<u8>, CKMError>;

    /// write key to store
    fn write_key(&mut self, password: &str, key: String) -> Result<String, CKMError>;
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::str;

    #[test]
    fn test_generate_entropy() {
        let local_keystore = LocalKeystore::new();
        keystore_test_entropy(local_keystore);
    }

    #[test]
    fn test_get_write() {
        let mut local_keystore = LocalKeystore::new();
        let v = local_keystore.write_key("123", "456".to_string()).unwrap();
        let c = local_keystore.get_key("123", v).unwrap();
        assert_eq!(str::from_utf8(&c).unwrap(), "456");
    }

    fn keystore_test_entropy(keystore: impl Keystore) {
        let a = keystore.generate_entropy(128).unwrap();
        assert_eq!(a.len(), 16);
        let b = keystore.generate_entropy(256).unwrap();
        assert_eq!(b.len(), 32);
    }
}
