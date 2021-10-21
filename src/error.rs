use thiserror::Error;


#[derive(Debug, Error)]
pub enum CKMError {
    #[error("not found {0}")]
    NotFound(String),


    #[error("random generator error")]
    RandomError,
    
    #[error("none known error")]
    Unknown,
}