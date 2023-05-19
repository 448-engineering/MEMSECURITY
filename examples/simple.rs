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
