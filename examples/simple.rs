#[cfg(all(feature = "encryption", feature = "symm_asymm"))]
use memsecurity::*;

#[cfg(all(feature = "encryption", feature = "symm_asymm"))]
fn main() {
    let mut foo = EncryptedMem::<32>::new();

    let plaintext_bytes = CsprngArray::<32>::gen();

    println!(" PLAINTEXT: {:?}", plaintext_bytes); //SECURELY PRINTED TO CONSOLE USING DEBUG TRAIT
    println!(" PLAINTEXT: {:?}", plaintext_bytes); //SECURELY PRINTED TO CONSOLE USING DISPLAY TRAIT
    println!(" PLAINTEXT: {:?}", plaintext_bytes.expose()); //WARNING: THIS IS AN EXAMPLE, DO NOT PRINT SECRETS IN CODE

    let data = ZeroizeBytesArray::new_with_data(plaintext_bytes.expose());

    foo.encrypt(&data).unwrap();

    println!("CIPHERTEXT: {:?}", foo.ciphertext());
    println!("    XNONCE: {:?}", foo.xnonce());

    let decrypted = foo.decrypt().unwrap();

    println!(" DECRYPTED:{:?}", decrypted);
    assert_eq!(data, decrypted);
}

#[cfg(not(all(feature = "encryption", feature = "symm_asymm")))]
fn main() {
    println!("RUN THIS EXAMPLE WITH `cargo run --example simple --features encrypted`");
}
