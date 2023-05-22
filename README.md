# MEMSECURITY

[![Rust](https://github.com/448-engineering/MEMSECURITY/actions/workflows/rust.yml/badge.svg?branch=master)](https://github.com/448-engineering/MEMSECURITY/actions/workflows/rust.yml)  ![crates.io](https://img.shields.io/crates/v/memsecurity.svg)[![Docs](https://docs.rs/memsecurity/badge.svg)](https://docs.rs/memsecurity)


Securely hold secrets in memory and protect them against cross-protection-boundary readout via microarchitectural, via attacks on physical layout, and via coldboot attacks.

The given type of encryption secures sensitive data, such as secret keys, by encrypting them in memory while they are not in use and decrypting them on demand. This method provides protection against various types of attacks, including cross-protection-boundary readout via microarchitectural flaws like Spectre or Meltdown, attacks on physical layout like Rowbleed, and coldboot attacks. The key insight is that these attacks are imperfect, meaning that the recovered data contains bitflips or the attack only provides a probability for any given bit. When applied to cryptographic keys, these kinds of imperfect attacks are enough to recover the actual key. However, this implementation derives a sealing key from a large area of memory called the "pre-key" using a key derivation function. Any single bitflip in the readout of the pre-key will avalanche through all the bits in the sealing key, rendering it unusable with no indication of where the error occurred.


This crate has not received an audit. Use at your own risk!!!

- The Arrays can be used without the need to import other crates for encryption by simple adding the crate with no extra features.
    ```toml
    [dependencies]
    memsecurity = "1.0.0"
    ```

- To enable crating of arrays with CSPRNG random bytes that can be zeroed out use the `random` feature
    ```toml
    [dependencies]
    memsecurity = { version = "1.0.0", features = ["random"] }
    ```

- To enable encryption of memory secrets, add this crate with the `encryption` feature. This feature automatically enables random bytes generation from the feature `random`.
    ```toml
    [dependencies]
    memsecurity = { version = "1.0.0", features = ["encryption"] }
    ```


#### EXAMPLE
```rust
use memsecurity::*;

fn main() {
    let mut foo = EncryptedMem::<32>::new();

    let plaintext_bytes = ZeroizeBytesArray::csprng();

    println!(" PLAINTEXT: {:?}", plaintext_bytes); //WARNING: THIS IS AN EXAMPLE, DO NOT PRINT SECRETS IN CODE

    foo.encrypt(&plaintext_bytes).unwrap();

    println!("CIPHERTEXT: {:?}", foo.ciphertext());
    println!("    XNONCE: {:?}", foo.xnonce());

    let decrypted = foo.decrypt().unwrap();

    println!(" DECRYPTED:{:?}", decrypted);
    assert_eq!(plaintext_bytes, decrypted);
}
```