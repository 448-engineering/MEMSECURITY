#![deny(unsafe_code)]
#![forbid(missing_docs)]
#![doc = include_str!("../README.md")]

mod errors;
pub use errors::*;

#[cfg(feature = "symm_asymm")]
mod cryptography_structures;
#[cfg(feature = "symm_asymm")]
pub use cryptography_structures::*;

#[cfg(feature = "encryption")]
mod encrypted_mem;
#[cfg(feature = "encryption")]
pub use encrypted_mem::*;

#[cfg(feature = "symm_asymm")]
mod zeroizable_arrays;
#[cfg(feature = "symm_asymm")]
pub use zeroizable_arrays::*;

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
#[cfg(feature = "ed25519")]
#[cfg(all(feature = "ascon", feature = "encryption"))]
pub use ascon_aead;
#[cfg(feature = "encryption")]
pub use blake3;
#[cfg(feature = "encryption")]
pub use bytes;
#[cfg(all(feature = "chacha", feature = "encryption"))]
pub use chacha20poly1305;
#[cfg(feature = "ed25519")]
pub use ed25519_dalek;
#[cfg(feature = "encryption")]
pub use memsec;
#[cfg(feature = "encryption")]
pub use once_cell;
#[cfg(feature = "random")]
pub use rand_chacha;
#[cfg(feature = "random")]
pub use rand_core;
#[cfg(feature = "uuid")]
pub use uuid;
#[cfg(feature = "x25519")]
pub use x25519_dalek;

pub use borsh;
pub use zeroize;
