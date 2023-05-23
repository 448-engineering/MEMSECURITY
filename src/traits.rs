/// This trait ensures that a type can be converted into a Blake3 Hash.
/// This can be useful especially for equality checks since [blake3::Hash]
/// already implements constant time equality checks
pub trait ToBlake3Hash {
    /// The outcome of hashing `Self` with `blake3::hash`
    fn hash(&self) -> blake3::Hash;
}
