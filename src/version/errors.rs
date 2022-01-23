//! All the errors generated & used by different file format versions

use thiserror::Error;

#[derive(Debug, Error)]
#[error("Encryption failed")]
pub struct EncryptError;

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error("Decryption failed")]
    BadCrypt,

    #[error("Decryption result gave non UTF-8 bytes (likely incorrect key?)")]
    BadUtf8,
}

#[derive(Debug, Error)]
pub enum UnsupportedFeature {
    #[error("TOTP values are not supported with your current file version")]
    Totp,
}

#[derive(Debug, Error)]
pub enum SetFieldError {
    #[error("Cannot set {0} field: contents have not been decrypted")]
    ContentsNotUnlocked(super::ValueKind),
}

/// An error resulting from `FieldRef::value`
#[derive(Debug, Error)]
pub enum GetValueError {
    #[error("Cannot view protected field: contents have not been decrypted")]
    ContentsNotUnlocked,

    #[error("{0}")]
    Decrypt(DecryptError),

    #[error("This field has an invalid TOTP secret")]
    BadTotpSecret,
}

/// An error resulting from `FieldMut::swap_encryption`
#[derive(Debug, Error)]
pub enum SwapEncryptionError {
    #[error("Contents have not been decrypted")]
    ContentsNotUnlocked,

    #[error("{0}")]
    Encrypt(EncryptError),
    #[error("{0}")]
    Decrypt(DecryptError),

    #[error("Encryption cannot be disabled on TOTP fields")]
    IsTotp,
}

impl From<DecryptError> for GetValueError {
    fn from(e: DecryptError) -> Self {
        GetValueError::Decrypt(e)
    }
}

impl From<EncryptError> for SwapEncryptionError {
    fn from(e: EncryptError) -> Self {
        SwapEncryptionError::Encrypt(e)
    }
}

impl From<DecryptError> for SwapEncryptionError {
    fn from(e: DecryptError) -> Self {
        SwapEncryptionError::Decrypt(e)
    }
}
