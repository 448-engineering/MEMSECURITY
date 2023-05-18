/// Wraps `core::result::Result` with the `MemSecurityErr` as the `Err()` value
pub type MemSecurityResult<T> = Result<T, MemSecurityErr>;

/// Errors encountered in execution of the code in this crate
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum MemSecurityErr {
    /// An error was encountered while encrypting the data
    EncryptionErr,
    /// An error was encountered when decrypting data using XChaCha12Poly1305
    DecryptionError,
}
