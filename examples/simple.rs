fn main() {
    foo()
}

#[cfg(all(feature = "encryption", feature = "ed25519"))]
fn foo() {
    use memsecurity::*;
    let mut foo = EncryptedMem::new();

    let plaintext_bytes = CsprngArray::<32>::gen();

    foo.encrypt(&plaintext_bytes).unwrap();

    let decrypted = foo.decrypt().unwrap();
    assert_eq!(
        plaintext_bytes.expose_borrowed(),
        decrypted.expose_borrowed()
    );

    {
        assert!(foo.sign(CsprngArray::<32>::gen()).is_ok());

        let plaintext_bytes = CsprngArray::<4>::gen();

        foo.encrypt(&plaintext_bytes).unwrap();

        assert!(foo.sign(CsprngArray::<32>::gen()).is_err());
    }
}

#[cfg(not(all(feature = "encryption", feature = "ed25519")))]
fn foo() {
    panic!("RUN THIS EXAMPLE WITH `cargo run --example simple --features \"encryption ed25519\"`")
}
