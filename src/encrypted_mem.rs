//! This module contains types and methods used to create a sealing key that stretches across multiple
//! memory pages ensuring impossible key recovery if certain attacks are used to try and recover the key.
//! These attacks are specified in the crate documentation.
//!
//!
//!
#[cfg(all(feature = "symm_asymm", feature = "random"))]
use crate::{CsprngArraySimple, ZeroizeBytes};
use chacha20poly1305::XNonce;
use core::fmt;

/// The number of pages used to accommodate one page of 4KiB in size.
pub const DEFAULT_VAULT_PAGES: usize = 4;
/// A size in KiB of one page (a page is a fixed-size block of memory used by the operating system to manage memory)
pub const DEFAULT_VAULT_PAGE_SIZE: usize = 4096_usize;
/// The tag for ChaCha20Poly1305 stream cipher
pub const POLY1305_TAG_SIZE: usize = 16;
/// The layout of the bytes used to create the key
pub type VaultPagesLayout<const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize> =
    [[u8; VAULT_PAGE_SIZE]; VAULT_PAGES];

/// A struct that holds the encrypted secret and performs encryption and decryption on the secret.
/// #### Structure
/// ```rs
/// pub struct EncryptedMem {
///     ciphertext: ZeroizeBytes,
///     nonce: XNonce,
/// }
/// ```

pub struct EncryptedMem {
    ciphertext: ZeroizeBytes,
    nonce: XNonce,
}

impl fmt::Debug for EncryptedMem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedMem")
            .field(
                "ciphertext",
                &blake3::hash(self.ciphertext.expose_borrowed()),
            )
            .field("nonce", &blake3::hash(&self.nonce))
            .finish()
    }
}

impl EncryptedMem {
    /// Initializes a new [EncryptedMem]
    /// #### Usage
    /// ```rs
    /// let data = EncryptedMem::new();
    /// ```
    pub fn new() -> Self {
        let nonce = CsprngArraySimple::gen_u24_array();

        assert_ne!(nonce.expose(), [0u8; 24]);

        EncryptedMem {
            ciphertext: ZeroizeBytes::new(),
            nonce: nonce.expose().into(),
        }
    }

    /// Expose the ciphertext
    pub fn ciphertext(&self) -> &ZeroizeBytes {
        &self.ciphertext
    }

    /// Expose Nonce
    pub fn nonce(&self) -> &XNonce {
        &self.nonce
    }
}

/// The struct used to hold the sealing key used for encrypt data
/// while it's loaded in memory.
/// #### Structure
/// ```rs
/// pub struct SealingKey<const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize>(
///     [[u8; VAULT_PAGE_SIZE]; VAULT_PAGES],
/// );
/// ```
pub struct SealingKey<const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize>(
    [[u8; VAULT_PAGE_SIZE]; VAULT_PAGES],
);

mod key_ops {
    use super::SealingKey;
    use crate::{
        CsprngArray, EncryptedMem, MemSecurityErr, MemSecurityResult, ZeroizeBytes,
        DEFAULT_VAULT_PAGES, DEFAULT_VAULT_PAGE_SIZE,
    };
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha12Poly1305,
    };
    use once_cell::sync::Lazy;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    static SEALING_KEY: Lazy<SealingKey<DEFAULT_VAULT_PAGE_SIZE, DEFAULT_VAULT_PAGES>> =
        Lazy::new(|| SealingKey::new());

    impl<const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize>
        SealingKey<VAULT_PAGES, VAULT_PAGE_SIZE>
    {
        fn new() -> Self {
            let mut pages = [[0u8; VAULT_PAGE_SIZE]; VAULT_PAGES];

            (0..VAULT_PAGES).for_each(|vault_page_index| {
                pages[vault_page_index] = CsprngArray::<VAULT_PAGE_SIZE>::gen().expose().clone();
            });

            let mut outcome = SealingKey(pages);
            outcome.lock_pages();

            outcome
        }

        #[allow(unsafe_code)]
        fn lock_pages(&mut self) {
            self.0.iter_mut().for_each(|page| unsafe {
                memsec::mlock(page.as_mut_slice().as_mut_ptr(), VAULT_PAGE_SIZE);
                //TODO Handle this bool
            });
        }

        #[allow(unsafe_code)]
        fn munlock_pages(&mut self) {
            self.0.iter_mut().for_each(|page| unsafe {
                memsec::munlock(page.as_mut_slice().as_mut_ptr(), VAULT_PAGE_SIZE);
                //TODO Handle this bool
            });
        }

        fn kek(&self) -> [u8; blake3::OUT_LEN] {
            let mut hasher = blake3::Hasher::new();
            self.0.iter().for_each(|page| {
                hasher.update(page);
            });

            hasher.finalize().as_bytes().clone()
        }

        #[allow(unsafe_code)]
        fn mlock_kek(&self, ptr: *mut u8) -> bool {
            unsafe { memsec::mlock(ptr, blake3::OUT_LEN) }
        }

        #[allow(unsafe_code)]
        fn munlock_kek(&self, ptr: *mut u8) -> bool {
            unsafe { memsec::munlock(ptr, blake3::OUT_LEN) }
        }
    }

    impl<const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize> Zeroize
        for SealingKey<VAULT_PAGES, VAULT_PAGE_SIZE>
    {
        fn zeroize(&mut self) {
            self.0 = [[0u8; VAULT_PAGE_SIZE]; VAULT_PAGES];
        }
    }

    impl<const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize> ZeroizeOnDrop
        for SealingKey<VAULT_PAGES, VAULT_PAGE_SIZE>
    {
    }

    impl<const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize> Drop
        for SealingKey<VAULT_PAGES, VAULT_PAGE_SIZE>
    {
        fn drop(&mut self) {
            self.munlock_pages();

            #[cfg(debug_assertions)]
            self.0
                .iter()
                .for_each(|page| debug_assert_eq!(page, &[0u8; VAULT_PAGE_SIZE]))
        }
    }

    impl EncryptedMem {
        /// Performs an encryption operation.
        pub fn encrypt<T: Zeroize + AsRef<[u8]>>(
            &mut self,
            plaintext: &T,
        ) -> MemSecurityResult<&mut Self> {
            let mut kek = SEALING_KEY.kek();
            let kek_ptr = kek.as_mut_ptr();
            SEALING_KEY.mlock_kek(kek_ptr); //TODO Handle this bool

            let cipher = XChaCha12Poly1305::new(&kek.into());

            let outcome = match cipher.encrypt(&self.nonce, plaintext.as_ref()) {
                Ok(ciphertext) => Ok(ciphertext),
                Err(_) => Err(MemSecurityErr::EncryptionErr),
            };

            SEALING_KEY.munlock_kek(kek_ptr); //TODO Handle this bool

            debug_assert_eq!(kek, [0u8; blake3::OUT_LEN]);

            self.ciphertext = ZeroizeBytes::new_with_data(&outcome?);

            Ok(self)
        }

        /// Performs an decryption operation.
        pub fn decrypt(&self) -> MemSecurityResult<ZeroizeBytes> {
            let mut kek = SEALING_KEY.kek();
            let kek_ptr = kek.as_mut_ptr();
            SEALING_KEY.mlock_kek(kek_ptr); //TODO Handle this bool

            let cipher = XChaCha12Poly1305::new(&kek.into());

            let outcome =
                match cipher.decrypt(&self.nonce, self.ciphertext.expose_borrowed().as_ref()) {
                    Ok(plaintext) => Ok(ZeroizeBytes::new_with_data(&plaintext)),
                    Err(_) => Err(MemSecurityErr::EncryptionErr),
                };

            SEALING_KEY.munlock_kek(kek_ptr); //TODO Handle this bool

            debug_assert_eq!(kek, [0u8; blake3::OUT_LEN]);

            outcome
        }

        /// Hash some bytes with Blake3 using a key to create a HMAC
        pub fn blake3_hmac<T: Zeroize + AsRef<[u8]>>(plaintext: T) -> blake3::Hash {
            let mut kek = SEALING_KEY.kek();
            let kek_ptr = kek.as_mut_ptr();

            SEALING_KEY.mlock_kek(kek_ptr); //TODO Handle this bool

            let outcome = blake3::keyed_hash(&kek, plaintext.as_ref());
            SEALING_KEY.munlock_kek(kek_ptr); //TODO Handle this bool

            debug_assert_eq!(kek, [0u8; 32]);

            outcome
        }

        /// Hash some an array of bytes with Blake3 using a key to create a HMAC
        pub fn blake3_keyed_hash_with_array<T: Zeroize + AsRef<[u8]>>(
            plaintext_array: &[T],
        ) -> blake3::Hash {
            let mut kek = SEALING_KEY.kek();
            let kek_ptr = kek.as_mut_ptr();

            SEALING_KEY.mlock_kek(kek_ptr); //TODO Handle this bool

            let mut hasher = blake3::Hasher::new_keyed(&kek);
            plaintext_array.iter().for_each(|plaintext| {
                hasher.update(plaintext.as_ref());
            });

            let outcome = hasher.finalize();

            SEALING_KEY.munlock_kek(kek_ptr); //TODO Handle this bool

            debug_assert_eq!(kek, [0u8; 32]);

            outcome
        }

        /// Hash a predetermined content with Blake3 using a secret key to derive a key (HKDF)
        pub fn blake3_hkdf(plaintext: &str) -> [u8; blake3::OUT_LEN] {
            let mut kek = SEALING_KEY.kek();
            let kek_ptr = kek.as_mut_ptr();

            SEALING_KEY.mlock_kek(kek_ptr); //TODO Handle this bool

            let outcome = blake3::derive_key(plaintext, &kek);
            SEALING_KEY.munlock_kek(kek_ptr); //TODO Handle this bool

            debug_assert_eq!(kek, [0u8; 32]);

            outcome
        }
    }
}
