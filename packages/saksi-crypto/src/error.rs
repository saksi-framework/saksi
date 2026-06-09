use thiserror::Error;

pub type CryptoResult<T> = Result<T, CryptoError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid scalar encoding")]
    InvalidScalar,

    #[error("invalid ristretto point encoding")]
    InvalidPoint,

    #[error("invalid protocol parameters: {0}")]
    InvalidParameters(&'static str),

    #[error("proof verification failed")]
    VerificationFailed,
}
