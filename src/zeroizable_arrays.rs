use bytes::{BufMut, BytesMut};
use core::fmt;
#[cfg(feature = "random")]
use nanorand::{BufferedRng, ChaCha8, Rng};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// This a byte that is zeroed out when dropped from memory.
/// #### Structure
/// ```rust
/// pub struct ZeroizeByte(u8);
/// ```
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ZeroizeByte(u8);

impl ZeroizeByte {
    /// Initialize a ZeroizeByte with the value of specified by byte
    pub fn new(value: u8) -> Self {
        ZeroizeByte(value)
    }

    /// Initialize a new byte which is zeroed byte
    pub fn new_zeroed() -> Self {
        ZeroizeByte(0u8)
    }

    /// File the current array with new values specified by the method parameter `value: u8`
    pub fn set(&mut self, value: u8) -> &mut Self {
        self.0 = value;

        self
    }

    /// Expose the internal as an owned byte
    pub fn expose(&self) -> u8 {
        self.0
    }

    /// Expose the internal as an borrowed byte
    pub fn expose_borrowed(&self) -> &u8 {
        &self.0
    }

    /// Clone the array
    pub fn clone(&self) -> ZeroizeByte {
        Self(self.0)
    }

    /// Own this array
    pub fn own(self) -> Self {
        self
    }

    /// Generate some random byte and initialize an new `ZeroizeByte` in the process.
    #[cfg(feature = "random")]
    pub fn csprng() -> Self {
        let mut rng = ChaCha8::new();

        ZeroizeByte(rng.generate::<u8>())
    }
}

impl Zeroize for ZeroizeByte {
    fn zeroize(&mut self) {
        self.0 = 0;
    }
}

impl Drop for ZeroizeByte {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl ZeroizeOnDrop for ZeroizeByte {}

/// This is a array whose size is specified as a const generic `N` and can be zeroed out when dropped from memory.
/// This array is useful when specifying fixed size bytes like passwords which need to be zeroed out from memory before being dropped.
/// #### Structure
/// ```rust
/// pub struct ZeroizeArray<const N: usize>([u8; N]);
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ZeroizeArray<const N: usize>([u8; N]);

impl<const N: usize> fmt::Debug for ZeroizeArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ZeroizeArray<const N: usize>({:?})",
            &blake3::hash(&self.0)
        )
    }
}

impl<const N: usize> ZeroizeArray<N> {
    /// Initialize a ZeroizeArray with the value of specified by the array of bytes
    pub fn new(value: [u8; N]) -> Self {
        ZeroizeArray(value)
    }

    /// Initialize a new array which is zeroed bytes of len `N` as specified by the generic `const N: usize`
    pub fn new_zeroed() -> Self {
        ZeroizeArray([0u8; N])
    }

    /// File the current array with new values specified by the method parameter `value: [u8; N]`
    pub fn fill_from_slice(&mut self, value: [u8; N]) -> &mut Self {
        self.0.copy_from_slice(&value);

        self
    }

    /// Expose the internal as an owned array
    pub fn expose(&self) -> [u8; N] {
        self.0
    }

    /// Expose the internal as an borrowed array
    pub fn expose_borrowed(&self) -> &[u8; N] {
        &self.0
    }

    /// Clone the array
    pub fn clone(&self) -> ZeroizeArray<N> {
        Self(self.0)
    }

    /// Own this array
    pub fn own(self) -> Self {
        self
    }

    /// Insert a value at index specified in the array
    pub fn insert(&mut self, index: usize, value: u8) -> &mut Self {
        self.0[index] = value;

        self
    }

    /// Generate some random bytes and initialize an new `ZeroizeArray` in the process.
    #[cfg(feature = "random")]
    pub fn csprng() -> Self {
        let mut buffer = [0u8; N];
        let mut rng = BufferedRng::new(ChaCha8::new());
        rng.fill(&mut buffer);

        let csprng = ZeroizeArray(buffer);

        buffer.copy_from_slice(&[0u8; N]);

        csprng
    }
}

impl<const N: usize> Zeroize for ZeroizeArray<N> {
    fn zeroize(&mut self) {
        self.0[..].copy_from_slice(&[0u8; N]);
    }
}

impl<const N: usize> Drop for ZeroizeArray<N> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<const N: usize> ZeroizeOnDrop for ZeroizeArray<N> {}

/// This is an array of variable length bytes that can be zeroed out on drop.
/// #### Structure
///
/// ```rust
/// use chacha20poly1305::aead::bytes::BytesMut;
///
/// pub struct ZeroizeBytesArray<const N: usize>(BytesMut);
/// ```
///

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ZeroizeBytesArray<const N: usize>(BytesMut);

impl<const N: usize> ZeroizeBytesArray<N> {
    /// Initialize the array with an initial length of `N`
    pub fn new() -> Self {
        ZeroizeBytesArray(BytesMut::with_capacity(N))
    }

    /// Initialize the array and set the internal value of the array to the value specified by method argument
    pub fn new_with_data(value: [u8; N]) -> Self {
        let mut value_bytes = BytesMut::with_capacity(N);

        value_bytes.put(&value[..]);

        ZeroizeBytesArray(value_bytes)
    }

    /// Set the internal value of the array to the value specified by method argument
    pub fn set(mut self, value: [u8; N]) -> Self {
        self.0.put(&value[..]);

        self
    }

    /// Add the byte the internal value
    pub fn set_byte(&mut self, value: u8) -> &mut Self {
        self.0.put_u8(value);

        self
    }

    /// Set the internal value of the array to the value specified by method argument value which is a `BytesMut`
    pub fn set_bytes_mut(mut self, value: BytesMut) -> Self {
        self.0.put(&value[..]);

        self
    }

    /// Initialize the array with the length specified by the generic const `N` added to the value specified by the
    /// method argument `capacity:usize` (N + capacity)
    pub fn with_additional_capacity(capacity: usize) -> Self {
        ZeroizeBytesArray(BytesMut::with_capacity(N + capacity))
    }

    /// Expose the internal value of the array
    pub fn expose(&self) -> &BytesMut {
        &self.0
    }

    /// Clone the array
    pub fn clone(&self) -> ZeroizeBytesArray<N> {
        Self(self.0.clone())
    }

    /// Generate cryptographically secure random bytes and initialize the array with these bytes returning the array.
    #[cfg(feature = "random")]
    pub fn csprng() -> Self {
        let mut buffer = [0u8; N];
        let mut rng = BufferedRng::new(ChaCha8::new());
        rng.fill(&mut buffer);

        let mut bytes_buffer = BytesMut::with_capacity(N);

        bytes_buffer.put(&buffer[..]);

        buffer.copy_from_slice(&[0u8; N]);

        ZeroizeBytesArray(bytes_buffer)
    }
}

impl<const N: usize> fmt::Debug for ZeroizeBytesArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ZeroizeBytesArray<const N: usize>({:?})",
            &blake3::hash(&self.0)
        )
    }
}

impl<const N: usize> Zeroize for ZeroizeBytesArray<N> {
    fn zeroize(&mut self) {
        self.0.clear()
    }
}

impl<const N: usize> Drop for ZeroizeBytesArray<N> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<const N: usize> ZeroizeOnDrop for ZeroizeBytesArray<N> {}

/// Similar to `ZeroizeBytesArray` but this does not have a fixed size length.
/// This is more similar to using a `Vec` than an `array`
/// #### Structure
/// ```rust
/// use chacha20poly1305::aead::bytes::BytesMut;
///
/// pub struct ZeroizeBytes(BytesMut);
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ZeroizeBytes(BytesMut);

impl ZeroizeBytes {
    /// Create a new array with no allocation and no specified capacity
    pub fn new() -> Self {
        ZeroizeBytes(BytesMut::new())
    }

    /// Initialize the array and set the internal value of the array to the value specified by method argument
    pub fn new_with_data(value: &[u8]) -> Self {
        let mut value_bytes = BytesMut::new();
        value_bytes.put(&value[..]);

        ZeroizeBytes(value_bytes)
    }

    /// Set the internal value of the array to the value specified by method argument value which is a `BytesMut`
    pub fn set_bytes_mut(&mut self, value: BytesMut) -> &mut Self {
        self.0.put(&value[..]);

        self
    }

    /// Sets the internal value to the new value
    pub fn set(&mut self, value: &[u8]) -> &mut Self {
        let mut container = BytesMut::new();
        container.put(value);
        self.0 = container;

        self
    }

    /// Add the byte the internal value
    pub fn set_byte(&mut self, value: u8) -> &mut Self {
        self.0.put_u8(value);

        self
    }

    /// Initializes the array with a specified capacity
    pub fn new_with_capacity(capacity: usize) -> Self {
        ZeroizeBytes(BytesMut::with_capacity(capacity))
    }

    /// Expose the internal value
    pub fn expose(&self) -> &BytesMut {
        &self.0
    }

    /// Clone the array
    pub fn clone(&self) -> ZeroizeBytes {
        Self(self.0.clone())
    }

    /// Generate some cryptographically secure random bytes and initialize the internal value of the array with these bytes
    /// returning the array.
    #[cfg(feature = "random")]
    pub fn csprng<const BUFFER_SIZE: usize>() -> Self {
        let mut buffer = [0u8; BUFFER_SIZE];
        let mut rng = BufferedRng::new(ChaCha8::new());
        rng.fill(&mut buffer);

        let mut bytes_buffer = BytesMut::with_capacity(BUFFER_SIZE);

        bytes_buffer.put(&buffer[..]);

        buffer.copy_from_slice(&[0u8; BUFFER_SIZE]);

        ZeroizeBytes(bytes_buffer)
    }
}

impl fmt::Debug for ZeroizeBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ZeroizeBytes({:?})", &blake3::hash(&self.0))
    }
}

impl Zeroize for ZeroizeBytes {
    fn zeroize(&mut self) {
        self.0.clear()
    }
}

impl Drop for ZeroizeBytes {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl ZeroizeOnDrop for ZeroizeBytes {}
