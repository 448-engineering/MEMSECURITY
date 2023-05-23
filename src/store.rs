use crate::{ZeroizeArray, ZeroizeBytesArray};

#[cfg(feature = "random")]
use nanorand::{BufferedRng, ChaCha8, Rng};

/// The length of XNonce type (192-bits/24-bytes).
pub const XNONCE_LENGTH: usize = 24;
/// The length of Poly1305 tag.
pub const TAG_LENGTH: usize = 16;

/// The encrypted nonce and ciphertext of the input that needs to be protected in memory.
/// It declares a struct with a const generic `N` of type usize. This generic is used to define the length
/// of the cipher text at compile time providing constant security guarantees about the length of the ciphertext.
/// The `xnonce` is a field of the XNonce is XChaCha12Poly1305.
/// #### Its structure is:
/// ```rust
/// use chacha20poly1305::XNonce;
/// use memsecurity::ZeroizeBytesArray;
///
/// pub struct EncryptedMem<const N: usize> {
///     ciphertext: ZeroizeBytesArray<N>,
///     xnonce: XNonce,
///  }   
/// ```
///
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedMem<const N: usize> {
    ciphertext: ZeroizeBytesArray<N>,
    xnonce: ZeroizeArray<XNONCE_LENGTH>,
}

impl<const N: usize> EncryptedMem<N> {
    /// Instantiate a new `EncryptedMem` struct with sensible defaults.
    /// This initializes a nonce as `[0u8; XNONCE_LENGTH]` , generates 8 random bytes using `BufferedRng::new(ChaCha8::new())`
    /// which is using ChaCha8 to generate random bytes and then add the bytes to the initialized nonce array .
    /// The nonce array and an initialized with defaults `ZeroizeBytesArray` is used to generate the outcome of initializing an `EncryptedMem` struct.
    /// The `ZeroizeBytesArray` initialized with an additional `TAG_LENGTH bytes` for the Poly1305 tag.
    pub fn new() -> Self {
        let mut nonce_buffer = [0u8; XNONCE_LENGTH];
        let mut rng = BufferedRng::new(ChaCha8::new());
        rng.fill(&mut nonce_buffer);

        let outcome = EncryptedMem {
            ciphertext: ZeroizeBytesArray::with_additional_capacity(TAG_LENGTH),
            xnonce: ZeroizeArray::new(nonce_buffer),
        };

        nonce_buffer[..].copy_from_slice(&[0u8; XNONCE_LENGTH]); //TODO check if zeroing this necessary

        outcome
    }

    /// Instantiate a new `EncryptedMem` struct with sensible defaults.
    /// This initializes a nonce as `[0u8; XNONCE_LENGTH]` , generates 8 random bytes using `BufferedRng::new(ChaCha8::new())`
    /// which is using ChaCha8 to generate random bytes and then add the bytes to the initialized nonce array .
    /// The nonce array and an initialized with defaults `ZeroizeBytesArray` is used to generate the outcome of initializing an `EncryptedMem` struct.
    /// The `ZeroizeBytesArray` initialized with an additional bytes specified by the `capacity` argument of the method
    pub fn new_with_added_capacity(capacity: usize) -> Self {
        let mut nonce_buffer = [0u8; XNONCE_LENGTH];
        let mut rng = BufferedRng::new(ChaCha8::new());
        rng.fill(&mut nonce_buffer);

        let outcome = EncryptedMem {
            ciphertext: ZeroizeBytesArray::with_additional_capacity(capacity),
            xnonce: ZeroizeArray::new(nonce_buffer),
        };

        nonce_buffer[..].copy_from_slice(&[0u8; XNONCE_LENGTH]); //TODO check if zeroing this necessary

        outcome
    }

    /// Add the ciphertext to the initialized struct
    pub fn add_ciphertext(&mut self, ciphertext: ZeroizeBytesArray<N>) -> &mut Self {
        self.ciphertext = ciphertext;

        self
    }

    /// Get the ciphertext
    pub fn ciphertext(&self) -> &ZeroizeBytesArray<N> {
        &self.ciphertext
    }

    /// Expose `XNonce`
    pub fn xnonce(&self) -> ZeroizeArray<XNONCE_LENGTH> {
        self.xnonce.clone()
    }
}
