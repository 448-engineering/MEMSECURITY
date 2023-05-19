#![forbid(unsafe_code)]
#![forbid(missing_docs)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "encryption")]
mod store;
#[cfg(feature = "encryption")]
pub use store::*;

#[cfg(feature = "encryption")]
mod keygen;
#[cfg(feature = "encryption")]
pub use keygen::*;

mod zeroizable_arrays;
pub use zeroizable_arrays::*;

#[cfg(feature = "encryption")]
mod errors;
#[cfg(feature = "encryption")]
pub use errors::*;

// TODO Test different nonces
// TODO Test different cipher and plaintext

#[cfg(tests)]
mod sanity_tests {
    use memsecurity::*;

    #[test]
    fn csprng() {
        // Create a new array of 32 bytes that is randomly generated and cryptographically secure
        let plaintext_bytes1 = ZeroizeBytesArray::<32>::csprng();
        let plaintext_bytes2 = ZeroizeBytesArray::<32>::csprng();
        assert_eq!(
            plaintext_bytes1.expose().len(),
            plaintext_bytes2.expose().len()
        );
        assert_ne!(plaintext_bytes1, plaintext_bytes2);

        let plaintext_bytes1 = ZeroizeArray::<32>::csprng();
        let plaintext_bytes2 = ZeroizeArray::<32>::csprng();
        assert_eq!(
            plaintext_bytes1.expose().len(),
            plaintext_bytes2.expose().len()
        );
        assert_ne!(plaintext_bytes1, plaintext_bytes2);

        let plaintext_bytes1 = ZeroizeBytes::csprng::<32>();
        let plaintext_bytes2 = ZeroizeBytes::csprng::<32>();
        assert_eq!(
            plaintext_bytes1.expose().len(),
            plaintext_bytes2.expose().len()
        );
        assert_ne!(plaintext_bytes1, plaintext_bytes2);
    }

    #[test]
    fn cipher() {
        let mut foo = EncryptedMem::<32>::new();

        let plaintext_bytes = ZeroizeBytesArray::csprng();
        foo.encrypt(&plaintext_bytes).unwrap();
        let decrypted = foo.decrypt().unwrap();

        assert_eq!(plaintext_bytes, decrypted);
    }
}
