use thiserror::Error;


#[derive(Debug, Error)]
pub enum CKMError {
    #[error("not found {0}")]
    NotFound(String),


    #[error("random generator error")]
    RandomError,

    #[error("Key not exist")]
    NotExist,

    #[error("none known error")]
    Unknown,

    #[error("password invalid")]
    PasswordInvalid,
}