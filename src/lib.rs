mod keystore;
mod error;

pub use keystore::Keystore;
pub use error::CKMError;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
