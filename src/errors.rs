/// Wraps `core::result::Result` with the `MemSecurityErr` as the `Err()` value
pub type MemSecurityResult<T> = Result<T, MemSecurityErr>;

/// Errors encountered in execution of the code in this crate
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum MemSecurityErr {
    /// An error was encountered while encrypting the data
    #[cfg(feature = "encryption")]
    EncryptionErr,
    /// An error was encountered when decrypting data using XChaCha12Poly1305    
    #[cfg(feature = "encryption")]
    DecryptionError,
    /// The length of the arrays should be the same
    InvalidArrayLength {
        /// The length defined in generic value `N` in `const N: usize`
        const_n_len: usize,
        /// The length of the mutable array `&mut [u8; N]`
        buffer_len: usize,
    },
    /// The length of the arrays should be the same
    InvalidSliceLength {
        /// The length defined in generic value `N` in `const N: usize`
        expected: usize,
        /// The length of the `&[u8]` slice
        found: usize,
    },
}
