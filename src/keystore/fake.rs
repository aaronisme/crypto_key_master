use crate::{CKMError, Keystore};
use hex::decode;

#[derive(Debug, Clone, Default)]
pub(crate) struct FakeKeystore {}

impl Keystore for FakeKeystore {
    fn generate_entropy(&self, length: u32) -> Result<Vec<u8>, CKMError> {
        let fakeBuffer = vec![0u8; 32];
        Ok(fakeBuffer)
    }

    fn get_key(&self, password: &str, key_id: String) -> Result<Vec<u8>, CKMError> {
        let fakeSeed = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
        let result = decode(fakeSeed).map_err(|_e| CKMError::SerializeError)?;
        Ok(result)
    }

    fn write_key(&mut self, password: &str, key: String) -> Result<String, crate::CKMError> {
        Ok("123456".to_string())
    }
}
