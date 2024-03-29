use crate::{ToBlake3Hash, ZeroizeArray};

/// The 32 bytes of a Blake3 Hash
pub type Blake3Hash = ZeroizeArray<32>;
/// The 64 bytes of an ed25519 keypair
pub type Ed25519KeyPair = ZeroizeArray<64>;
/// The 32 bytes of an ed25519 keypair
pub type Ed25519PublicKey = ZeroizeArray<32>;
/// The 32 bytes of an ed25519 secret
pub type Ed25519SecretKey = ZeroizeArray<32>;
/// The 64 bytes of an X25519 keypair
pub type X25519StaticKeyPair = ZeroizeArray<64>;
/// The 32 bytes of an X25519 public key
pub type X25519PublicKey = ZeroizeArray<32>;
/// The 32 bytes of an X25519 static secret key
pub type X25519StaticSecretKey = ZeroizeArray<32>;
/// The 32 bytes of an X25519 ephemeral secret key
pub type X25519EphemeralSecretKey = ZeroizeArray<32>;
/// The 32 bytes of an X25519 reusable secret key
pub type X25519ReusableSecretKey = ZeroizeArray<32>;
/// The 32 bytes of an X25519 shared secret key from the outcome of a DH key exchange
pub type X25519SharedSecretKey = ZeroizeArray<32>;
/// The 32 bytes secret key
pub type Key32Byte = ZeroizeArray<32>;
/// The 16 bytes of a Poly1305 AEAD tag
pub type Poly1305Tag = ZeroizeArray<16>;
/// The  bytes of a Tai64N timestamp
pub type TaiTimestamp = ZeroizeArray<12>;

impl ToBlake3Hash for ZeroizeArray<8> {
    fn hash(&self) -> blake3::Hash {
        blake3::hash(self.expose_borrowed())
    }
}

impl ToBlake3Hash for ZeroizeArray<12> {
    fn hash(&self) -> blake3::Hash {
        blake3::hash(self.expose_borrowed())
    }
}

impl ToBlake3Hash for ZeroizeArray<16> {
    fn hash(&self) -> blake3::Hash {
        blake3::hash(self.expose_borrowed())
    }
}

impl ToBlake3Hash for ZeroizeArray<24> {
    fn hash(&self) -> blake3::Hash {
        blake3::hash(self.expose_borrowed())
    }
}

impl ToBlake3Hash for ZeroizeArray<32> {
    fn hash(&self) -> blake3::Hash {
        blake3::hash(self.expose_borrowed())
    }
}

impl ToBlake3Hash for ZeroizeArray<64> {
    fn hash(&self) -> blake3::Hash {
        blake3::hash(self.expose_borrowed())
    }
}

impl ToBlake3Hash for ZeroizeArray<96> {
    fn hash(&self) -> blake3::Hash {
        blake3::hash(self.expose_borrowed())
    }
}

impl ToBlake3Hash for ZeroizeArray<128> {
    fn hash(&self) -> blake3::Hash {
        blake3::hash(self.expose_borrowed())
    }
}
