#![deny(unsafe_code)]
#![forbid(missing_docs)]
#![doc = include_str!("../README.md")]

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
