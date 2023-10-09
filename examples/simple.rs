#![allow(clippy::disallowed_names)]
fn main() {
    foo()
}

#[cfg(all(
    feature = "encryption",
    feature = "ed25519",
    feature = "x25519",
    feature = "uuid"
))]
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

    {
        let mut alice_kek = EncryptedMem::new();
        let alice_secret = CsprngArray::<32>::gen();
        alice_kek.encrypt(&alice_secret).unwrap();
        drop(alice_secret);
        let alice_public = alice_kek.x25519_public_key().unwrap();

        let mut bob_kek = EncryptedMem::new();
        let bob_secret = CsprngArray::<32>::gen();
        bob_kek.encrypt(&bob_secret).unwrap();
        drop(bob_secret);
        let bob_public = bob_kek.x25519_public_key().unwrap();

        let alice_shared_secret = alice_kek.x25519_dh(bob_public).unwrap();
        let bob_shared_secret = bob_kek.x25519_dh(alice_public).unwrap();

        assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes())
    }

    {
        use borsh::{to_vec, BorshDeserialize};

        let random = CsprngArray::<32>::gen();
        let random_bytes = to_vec(&random).unwrap();
        let deser_random = CsprngArray::<32>::try_from_slice(&random_bytes).unwrap();

        assert_eq!(random.expose_borrowed(), deser_random.expose_borrowed())
    }

    {
        let mut store = EncryptedMem::new();
        store.encrypt_uuid().unwrap();

        let decrypted = store.decrypt_uuid().unwrap();
        assert_eq!(decrypted.expose_borrowed().len(), 16usize);
    }
}

#[cfg(not(all(feature = "encryption", feature = "ed25519", feature = "x25519")))]
fn foo() {
    panic!("RUN THIS EXAMPLE WITH `cargo run --example simple --features \"encryption ed25519 x25519\"`")
}
