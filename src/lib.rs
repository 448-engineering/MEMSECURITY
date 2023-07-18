#![forbid(unsafe_code)]
#![forbid(missing_docs)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "symm_asymm")]
mod cryptography_structures;
#[cfg(feature = "symm_asymm")]
pub use cryptography_structures::*;

#[cfg(feature = "encryption")]
mod store;
#[cfg(feature = "encryption")]
pub use store::*;

#[cfg(feature = "encryption")]
mod keygen;
#[cfg(feature = "encryption")]
pub use keygen::*;

#[cfg(feature = "symm_asymm")]
mod zeroizable_arrays;
#[cfg(feature = "symm_asymm")]
pub use zeroizable_arrays::*;

mod errors;
pub use errors::*;

#[cfg(feature = "random")]
mod random;
#[cfg(feature = "random")]
pub use random::*;

#[cfg(feature = "symm_asymm")]
mod traits;
#[cfg(feature = "symm_asymm")]
pub use traits::*;

/// Re-export  crates
#[cfg(feature = "encryption")]
pub use aead;
#[cfg(feature = "encryption")]
pub use arrayvec;
#[cfg(feature = "encryption")]
pub use blake3;
#[cfg(feature = "encryption")]
pub use bytes;
#[cfg(feature = "encryption")]
pub use chacha20poly1305;
#[cfg(feature = "encryption")]
pub use lazy_static;
#[cfg(feature = "random")]
pub use rand_chacha;
#[cfg(feature = "random")]
pub use rand_core;
pub use zeroize;

// TODO Test different nonces
// TODO Test different cipher and plaintext

#[cfg(tests)]
mod sanity_tests {
    use memsecurity::{prelude::*, zeroize::Zeroize};

    #[test]
    fn csprng() {
        // Create a new array of 32 bytes that is randomly generated and cryptographically secure
        let plaintext_bytes1 = CsprngArray::<32>::csprng();
        let plaintext_bytes2 = CsprngArray::<64>::csprng();
        assert_eq!(
            plaintext_bytes1.expose().len(),
            plaintext_bytes2.expose().len()
        );
        assert_ne!(plaintext_bytes1, plaintext_bytes2);

        let plaintext_bytes1 = CsprngArray::<32>::csprng();
        let plaintext_bytes2 = CsprngArray::<32>::csprng();
        assert_eq!(
            plaintext_bytes1.expose().len(),
            plaintext_bytes2.expose().len()
        );
        assert_ne!(plaintext_bytes1, plaintext_bytes2);
    }

    #[test]
    fn cipher() {
        let mut foo = EncryptedMem::<32>::new();

        let mut plaintext_bytes = CsprngArray::<32>::csprng();
        let data = ZeroizeBytesArray::new_with_data(plaintext_bytes.expose());
        foo.encrypt(&data).unwrap();
        let decrypted = foo.decrypt().unwrap();

        assert_eq!(data, decrypted);
        plaintext_bytes.zeroize();
        assert_eq!(plaintext_bytes.expose(), [0u8; 32]);
    }
}
