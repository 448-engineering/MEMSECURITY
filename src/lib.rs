#![forbid(unsafe_code)]
#![forbid(missing_docs)]
#![forbid(missing_doc_code_examples)]
#![doc = include_str!("../README.md")]

mod store;
pub use store::*;
mod keygen;
pub use keygen::*;

mod zeroizable_arrays;
pub use zeroizable_arrays::*;

mod errors;
pub use errors::*;

// TODO Test different nonces
// TODO Test different cipher and plaintext

#[cfg(test)]
mod sanity_tests {
    use crate::*;

    #[test]
    fn correctness_test() {
        let sealing_vault =
            SealingKeyVault::<32, DEFAULT_VAULT_PAGES, DEFAULT_VAULT_PAGE_SIZE>::new();

        let mut store = EncryptedMem::<32>::new();
        let plaintext = ZeroizeArray::new([4u8; 32]);

        store.encrypt(&plaintext, sealing_vault.sealing_key().chacha_key());

        dbg!(&store.ciphertext().expose().as_ref());

        let decrypted = store.decrypt(sealing_vault.sealing_key().chacha_key());

        let decrypted: [u8; 32] = decrypted[..].try_into().unwrap();

        assert_eq!(
            &plaintext.expose_borrowed().as_slice(),
            &decrypted.as_slice()
        );
    }
}
