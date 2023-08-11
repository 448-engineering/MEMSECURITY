#[cfg(all(feature = "encryption", feature = "symm_asymm"))]
use memsecurity::*;

#[cfg(all(feature = "encryption", feature = "symm_asymm"))]
fn main() {
    let mut foo = EncryptedMem::new();

    let plaintext_bytes = CsprngArray::<32>::gen();

    foo.encrypt(&plaintext_bytes).unwrap();

    let decrypted = foo.decrypt().unwrap();
    assert_eq!(
        plaintext_bytes.expose_borrowed(),
        decrypted.expose_borrowed()
    );
}

#[cfg(not(all(feature = "encryption", feature = "symm_asymm")))]
fn main() {
    println!(
        "RUN THIS EXAMPLE WITH `cargo run --example simple --features \"encryption symm_asymm\"`"
    );
}
