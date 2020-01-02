//!
//! Definitions
//!
use iota_conversion::Trit;

/// Mam Sponge Definition
///
pub trait Sponge
where
    Self: Default + Clone,
{
    /// Error
    type Error;
    /// Sponge Absorb Input
    type AbsorbInput;
    /// Sponge Absorb Input
    type SqueezeInput;

    /// Sponge absorption
    ///
    fn absorb(&mut self, data: Self::AbsorbInput) -> Result<(), Self::Error>;

    /// Sponge squeezing
    ///
    fn squeeze(&mut self, data: Self::SqueezeInput) -> Vec<Trit>;

    /// Sponge Hashing
    ///
    /// * `plain_text` - Input data
    /// * `hash_len` -
    fn hash(&mut self, plain_text: &[Trit], hash_len: usize) -> Result<Vec<Trit>, Self::Error>;

    /// Sponge AE encryption
    ///
    /// * `plain_text` - Input data
    fn encr(&mut self, plain_text: &[Trit]) -> Vec<Trit>;

    /// Sponge AE decryption
    ///
    /// * `cipher_text` - Hash value
    ///
    /// Output:
    ///
    /// * `plain_text` - Input data
    fn decr(&mut self, cipher_text: &[Trit]) -> Vec<Trit>;

    ///
    /// Reset State
    ///
    fn reset(&mut self);
}

///
/// Transform Function
///
pub trait Transform {
    ///
    /// Transform
    ///
    /// * `state`
    ///
    fn transform(state: &mut [Trit]);
}
