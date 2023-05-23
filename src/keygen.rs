//! This module contains types and methods used to create a sealing key that stretches across multiple
//! memory pages ensuring impossible key recovery if certain attacks are used to try and recover the key.
//! These attacks are specified in the crate documentation.
//!
//! The structure of the sealing key is defined internally and not accessible outside this module.
//! ```rust
//! struct SealingKey<const N: usize, const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize>(
//!     [[u8; VAULT_PAGE_SIZE]; VAULT_PAGES],
//! );
//! ```
//! This sealing key also implements `Zeroize` where the memory is zeroed on drop.
//!
//!

/// The number of pages used to accommodate one page of 4KiB in size.
pub const DEFAULT_VAULT_PAGES: usize = 4;
/// A size in KiB of one page (a page is a fixed-size block of memory used by the operating system to manage memory)
pub const DEFAULT_VAULT_PAGE_SIZE: usize = 4096_usize;

struct SealingKeyPages([[u8; DEFAULT_VAULT_PAGE_SIZE]; DEFAULT_VAULT_PAGES]);

mod keymaker {

    use super::{SealingKeyPages, DEFAULT_VAULT_PAGES, DEFAULT_VAULT_PAGE_SIZE};
    use crate::{
        EncryptedMem, MemSecurityErr, MemSecurityResult, ZeroizeBytes, ZeroizeBytesArray,
        TAG_LENGTH,
    };
    use bytes::BytesMut;
    use chacha20poly1305::{
        aead::{AeadInPlace, KeyInit},
        Key, XChaCha12Poly1305, XNonce,
    };
    use nanorand::{ChaCha8, Rng};

    lazy_static::lazy_static! {
        static ref PREKEY: SealingKeyPages = {

        let mut pages = [[0u8; DEFAULT_VAULT_PAGE_SIZE]; DEFAULT_VAULT_PAGES];

        (0..DEFAULT_VAULT_PAGES).for_each(|vault_page_index| {
            let mut chacha_rng = ChaCha8::new();
            let mut random_bytes = [0; DEFAULT_VAULT_PAGE_SIZE];
            (0..DEFAULT_VAULT_PAGE_SIZE).for_each(|index| {
                random_bytes[index] = chacha_rng.generate::<u8>();
            });

            pages[vault_page_index] = random_bytes;
        });

        SealingKeyPages(pages)
    };

    }

    impl<const N: usize> EncryptedMem<N> {
        fn sealing_key(&self) -> ZeroizeBytes {
            let mut blake3_hasher = blake3::Hasher::new();

            PREKEY.0.iter().for_each(|page| {
                blake3_hasher.update(page);
            });

            let mut key = ZeroizeBytes::new_with_capacity(32);

            key.set_bytes_mut(BytesMut::from(
                blake3_hasher.finalize().as_bytes().as_slice(),
            ));

            key
        }

        /// Perform encryption on the plaintext. This a plaintext as a `ZeroizeArray<N>` with the length of the specified in `N`.
        /// It encrypts the plaintext using up the `self.xnonce` as the nonce for ChaCha stream cipher.
        pub fn encrypt(
            &mut self,
            plaintext: &ZeroizeBytesArray<N>,
        ) -> MemSecurityResult<&mut Self> {
            let cipher =
                XChaCha12Poly1305::new(&Key::from_slice(self.sealing_key().expose_borrowed()));

            let mut buffer = BytesMut::with_capacity(N + TAG_LENGTH); // Note: buffer needs 16-bytes overhead for auth tag
            buffer.extend_from_slice(plaintext.expose_borrowed());
            // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
            match cipher
                .encrypt_in_place(
                    &XNonce::from_slice(self.xnonce().expose_borrowed()),
                    b"",
                    &mut buffer,
                ) //TODO Check if tag is being added
                {
                    Ok(_) => (),
                    Err(_) => return Err(MemSecurityErr::EncryptionErr)
                }

            let ciphertext =
                ZeroizeBytesArray::with_additional_capacity(TAG_LENGTH).set_bytes_mut(buffer);

            self.add_ciphertext(ciphertext);

            Ok(self)
        }

        /// Decrypts the `self.ciphertext` using the `self.nonce`
        pub fn decrypt(&mut self) -> MemSecurityResult<ZeroizeBytesArray<N>> {
            let cipher =
                XChaCha12Poly1305::new(&Key::from_slice(self.sealing_key().expose_borrowed()));

            let mut buffer = BytesMut::with_capacity(N + TAG_LENGTH); // Note: buffer needs 16-bytes overhead for auth tag
            buffer.extend_from_slice(self.ciphertext().expose_borrowed());

            // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
            match cipher.decrypt_in_place(
                &XNonce::from_slice(self.xnonce().expose_borrowed()),
                b"",
                &mut buffer,
            ) {
                Ok(_) => Ok(ZeroizeBytesArray::new().set_bytes_mut(buffer)),
                Err(_) => {
                    buffer.fill(0); // Zero out the partially decrypted plaintext
                    drop(buffer); // Drop the partially leaked plaintext

                    Err(MemSecurityErr::DecryptionError)
                }
            }
        }
    }
}
