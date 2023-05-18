use crate::ZeroizeBytes;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const DEFAULT_VAULT_PAGES: usize = 4;
pub const DEFAULT_VAULT_PAGE_SIZE: usize = 4096_usize;

struct SealingKey<const N: usize, const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize>(
    [[u8; VAULT_PAGE_SIZE]; VAULT_PAGES],
);

impl<const N: usize, const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize> Zeroize
    for SealingKey<N, VAULT_PAGES, VAULT_PAGE_SIZE>
{
    fn zeroize(&mut self) {
        self.0 = [[0u8; VAULT_PAGE_SIZE]; VAULT_PAGES];
    }
}

impl<const N: usize, const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize> ZeroizeOnDrop
    for SealingKey<N, VAULT_PAGES, VAULT_PAGE_SIZE>
{
}

impl<const N: usize, const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize> Drop
    for SealingKey<N, VAULT_PAGES, VAULT_PAGE_SIZE>
{
    fn drop(&mut self) {
        self.zeroize()
    }
}

pub struct SealingKeyVault<const N: usize, const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize>(
    SealingKey<N, VAULT_PAGES, VAULT_PAGE_SIZE>,
);

impl<const N: usize, const VAULT_PAGES: usize, const VAULT_PAGE_SIZE: usize>
    SealingKeyVault<N, VAULT_PAGES, VAULT_PAGE_SIZE>
{
    pub fn new() -> Self {
        use nanorand::{ChaCha8, Rng};

        let mut pages = [[0u8; VAULT_PAGE_SIZE]; VAULT_PAGES];

        (0..VAULT_PAGES).for_each(|vault_page_index| {
            let mut chacha_rng = ChaCha8::new();
            let mut random_bytes = [0; VAULT_PAGE_SIZE];
            (0..VAULT_PAGE_SIZE).for_each(|index| {
                random_bytes[index] = chacha_rng.generate::<u8>();
            });

            pages[vault_page_index] = random_bytes;
        });

        let prekey = SealingKeyVault(SealingKey(pages));

        pages.copy_from_slice(&[[0u8; VAULT_PAGE_SIZE]; VAULT_PAGES]); //  TODO CHECK if this is necessary

        prekey
    }

    pub fn sealing_key(&self) -> ZeroizeBytes {
        let mut blake3_hasher = blake3::Hasher::new();

        self.0 .0.into_iter().for_each(|page| {
            blake3_hasher.update(&page);
        });

        let mut key = ZeroizeBytes::new_with_capacity(32);

        key.set(aead::bytes::BytesMut::from(
            blake3_hasher.finalize().as_bytes().as_slice(),
        ));

        key
    }
}
