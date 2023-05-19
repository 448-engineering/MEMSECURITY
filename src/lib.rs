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
