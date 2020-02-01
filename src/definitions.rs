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
/// Spongos Interfaces
///
pub trait Spongos: Sponge
where
    Self: Default + Clone,
{
    /// Fork
    ///
    /// Create an equivalent instance
    fn fork(&self) -> Self;

    /// Commit
    ///
    /// Commit changes in the rate part
    fn commit(&mut self);
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

pub mod ss {
    //!
    //! Implementation of RFCs Signing Scheme
    //!
    //! https://github.com/iotaledger/bee-rfcs/pull/26
    //!

    ///
    /// Trait for Private Key Generator
    ///
    pub trait PrivateKeyGenerator<S> {
        /// Private Key
        type PrivateKey;
        /// Error
        type Error;

        /// Generate Private Key
        fn generate(&self, seed: &[i8], nonce: &[i8]) -> Result<Self::PrivateKey, Self::Error>;
    }

    ///
    /// Signature Scheme PrivateKey
    ///
    pub trait PrivateKey {
        /// PublicKey type
        type PublicKey;
        /// Signature Type
        type Signature;
        ///
        /// Generate Public Key
        ///
        fn generate_public_key(&self) -> Self::PublicKey;
        ///
        /// Sign
        ///
        fn sign(&self, message: &[i8]) -> Result<Self::Signature, String>;
    }

    ///
    /// Signature Scheme PublicKey
    ///
    pub trait PublicKey {
        /// Signature Type
        type Signature;
        ///
        /// Verify
        ///
        fn verify(&self, message: &[i8], signature: &Self::Signature) -> bool;
        ///
        /// To Bytes
        ///
        fn to_bytes(&self) -> &[i8];
        ///
        /// To Bytes
        ///
        fn form_bytes(bytes: &[i8]) -> Self;
    }

    ///
    /// Signature Scheme
    ///
    pub trait Signature {
        /// PublicKey Type
        type PublicKey;

        ///
        /// Recover Public Key
        ///
        fn recover_public_key(&self, message: &[i8]) -> Self::PublicKey;
        ///
        /// To Bytes
        ///
        fn to_bytes(&self) -> &[i8];
        ///
        /// To Bytes
        ///
        fn form_bytes(bytes: &[i8]) -> Self;
    }
}
