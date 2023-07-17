use crate::MemSecurityResult;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::ops::{Add, Sub};
use zeroize::Zeroize;

/// Generate Cryptographically secure random bytes of array size 8, 16, 24, 32 or 64
pub struct CsprngArraySimple;

impl CsprngArraySimple {
    /// Generate an array of random bytes with maximum array size of 8
    ///
    /// #### Usage
    /// ```rs
    /// let bytes = Csprng::gen_u8_byte();
    /// ```
    pub fn gen_u8_byte() -> u8 {
        CsprngArray::<1>::gen().0[0]
    }
    /// Generate an array of random bytes with maximum array size of 8
    ///
    /// #### Usage
    /// ```rs
    /// let bytes = Csprng::gen_u8();
    /// assert_eq!(bytes.len(), 8);
    /// ```
    pub fn gen_u8_array() -> CsprngArray<8> {
        CsprngArray::<8>::gen()
    }

    /// Generate an array of random bytes with maximum array size of 16
    ///
    /// #### Usage
    /// ```rs
    /// let bytes = CsprngArray::gen_16();
    /// assert_eq!(bytes.len(), 16);
    /// ```
    pub fn gen_u16_array() -> CsprngArray<16> {
        CsprngArray::<16>::gen()
    }

    /// Generate an array of random bytes with maximum array size of 24
    ///
    /// #### Usage
    /// ```rs
    /// let bytes = CsprngArray::gen_24();
    /// assert_eq!(bytes.len(), 24);
    /// ```
    pub fn gen_u24_array() -> CsprngArray<24> {
        CsprngArray::<24>::gen()
    }

    /// Generate an array of random bytes with maximum array size of 32
    ///
    /// #### Usage
    /// ```rs
    /// let bytes = CsprngArray::gen_32();
    /// assert_eq!(bytes.len(), 32);
    /// ```
    pub fn gen_u32_array() -> CsprngArray<32> {
        CsprngArray::<32>::gen()
    }

    /// Generate an array of random bytes with maximum array size of 64
    ///
    /// #### Usage
    /// ```rs
    /// let bytes = CsprngArray::gen_64();
    /// assert_eq!(bytes.len(), 64);
    /// ```
    pub fn gen_u64_array() -> CsprngArray<64> {
        CsprngArray::<64>::gen()
    }
}

/// Generate Cryptographically secure random bytes of different sizes based on generic usize `N`
/// #### Structure
/// ```rs
/// pub struct CsprngArray<const N: usize>([u8; N]);
/// ```
///
/// #### Example
/// ```rs
/// let bytes = CsprngArray::<32>::gen(); // Generates 32 random bytes
/// assert_eq!(bytes.len(), 32);
/// ```
pub struct CsprngArray<const N: usize>([u8; N]);

impl<const N: usize> CsprngArray<N> {
    /// Method to generate random cryptographically secure random bytes
    /// #### Example
    /// ```rs
    /// let bytes = CsprngArray::<64>::gen(); // Generates 64 random bytes
    /// assert_eq!(bytes.len(), 64);
    /// ```
    pub fn gen() -> Self {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut buffer = [0u8; N];
        rng.fill_bytes(&mut buffer);

        let outcome = CsprngArray(buffer);

        buffer.fill(0);

        outcome
    }

    /// Copies the contents of the buffer
    pub fn take(mut self, buffer: &mut [u8; N]) -> MemSecurityResult<()> {
        // FIXME implement
        let buffer_len = buffer.len();

        if buffer.len() != N {
            Err(crate::MemSecurityErr::InvalidArrayLength {
                const_n_len: N,
                buffer_len,
            })
        } else {
            buffer[0..N].copy_from_slice(&self.0);

            self.zeroize();

            Ok(())
        }
    }

    /// Copies the contents of the buffer
    pub fn take_zeroize_on_error(mut self, buffer: &mut [u8; N]) -> MemSecurityResult<()> {
        let buffer_len = buffer.len();

        if buffer.len() != N {
            self.zeroize();

            Err(crate::MemSecurityErr::InvalidArrayLength {
                const_n_len: N,
                buffer_len,
            })
        } else {
            buffer[0..N].copy_from_slice(&self.0);

            self.zeroize();

            Ok(())
        }
    }

    /// Clone the data. Be careful with this as it retains the secret in memory.
    /// It is recommended to call `Csprng::zeroize()` after consuming this in order to zeroize the memory
    pub fn expose(&self) -> [u8; N] {
        self.0
    }

    /// Get the inner value of the struct. This is only available in a debug build and
    /// is enforced by the flag `#[cfg(debug_assertions)]`
    #[cfg(debug_assertions)]
    pub fn dangerous_debug(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> Zeroize for CsprngArray<N> {
    fn zeroize(&mut self) {
        self.0.fill(0);

        assert_eq!(self.0, [0u8; N]); //Must panic if memory cannot be zeroized
    }
}

impl<const N: usize> core::fmt::Debug for CsprngArray<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CsprngArray(REDACTED)").finish()
    }
}

impl<const N: usize> core::fmt::Display for CsprngArray<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CsprngArray(REDACTED)").finish()
    }
}

impl<const N: usize> Drop for CsprngArray<N> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

/// Define maximum number a generic `T` can hold.
/// This is implemented for all integer and float primitive types
/// #### Example
/// ```rs
/// // The function with the enforced constraint
/// fn foo<T: MustBeInRange>(bar: T) {
///     // Use T as needed
///     println!("Input: {:?}", bar);
/// }
///
/// foo(42u64);
/// foo(0u64);
/// foo(std::u64::MAX);
/// ```
pub trait MinMaxNum: PartialOrd + Add + Sub + Copy {
    /// The minimum value that can be defined
    const MIN_VALUE: Self;
    /// The maximum value that can be defined
    const MAX_VALUE: Self;
}

impl MinMaxNum for u8 {
    const MIN_VALUE: u8 = core::u8::MIN;
    const MAX_VALUE: u8 = core::u8::MAX;
}

impl MinMaxNum for u16 {
    const MIN_VALUE: u16 = core::u16::MIN;
    const MAX_VALUE: u16 = core::u16::MAX;
}

impl MinMaxNum for u32 {
    const MIN_VALUE: u32 = core::u32::MIN;
    const MAX_VALUE: u32 = core::u32::MAX;
}

impl MinMaxNum for u64 {
    const MIN_VALUE: u64 = core::u64::MIN;
    const MAX_VALUE: u64 = core::u64::MAX;
}

impl MinMaxNum for u128 {
    const MIN_VALUE: u128 = core::u128::MIN;
    const MAX_VALUE: u128 = core::u128::MAX;
}

impl MinMaxNum for f32 {
    const MIN_VALUE: f32 = core::f32::MIN;
    const MAX_VALUE: f32 = core::f32::MAX;
}

impl MinMaxNum for f64 {
    const MIN_VALUE: f64 = core::f64::MIN;
    const MAX_VALUE: f64 = core::f64::MAX;
}

impl MinMaxNum for i8 {
    const MIN_VALUE: i8 = core::i8::MIN;
    const MAX_VALUE: i8 = core::i8::MAX;
}

impl MinMaxNum for i16 {
    const MIN_VALUE: i16 = core::i16::MIN;
    const MAX_VALUE: i16 = core::i16::MAX;
}

impl MinMaxNum for i32 {
    const MIN_VALUE: i32 = core::i32::MIN;
    const MAX_VALUE: i32 = core::i32::MAX;
}

impl MinMaxNum for i64 {
    const MIN_VALUE: i64 = core::i64::MIN;
    const MAX_VALUE: i64 = core::i64::MAX;
}

impl MinMaxNum for i128 {
    const MIN_VALUE: i128 = core::i128::MIN;
    const MAX_VALUE: i128 = core::i128::MAX;
}
