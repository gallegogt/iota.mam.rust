//! WOTS Layer
//!
//! The WOTS Layer supports Winternitz One-Time Signatures
//!

use crate::{
    constants::{mam_divs, mam_mods, trits_get3},
    definitions::{
        ss::{PrivateKey, PublicKey, Signature},
        Sponge,
    },
    prng::{Prng, PrngDestinationTryte},
};
use iota_conversion::Trit;
use std::marker::PhantomData;

/// Size of a WOTS public key
pub const MAM_WOTS_PUBLIC_KEY_SIZE: usize = 243;
/// Size of a WOTS private key part
pub const MAM_WOTS_PRIVATE_KEY_PART_SIZE: usize = 162;
/// Number of parts in a WOTS private key
pub const MAM_WOTS_PRIVATE_KEY_PART_COUNT: usize = 81;
/// Size of a WOTS private key
pub const MAM_WOTS_PRIVATE_KEY_SIZE: usize =
    (MAM_WOTS_PRIVATE_KEY_PART_SIZE * MAM_WOTS_PRIVATE_KEY_PART_COUNT);

/// Wots PrivateKey Generator
///
#[derive(Debug)]
pub struct WotsV1PrivateKeyGenerator<S> {
    _market: PhantomData<S>,
}

///
///
/// WOTS Private Key
///
#[derive(Clone)]
pub struct WotsPrivateKey<S> {
    /// Private Key
    state: Vec<Trit>,
    /// Market Data
    _sponge: PhantomData<S>,
}

///
///
/// WOTS Public Key
///
#[derive(Debug)]
pub struct WotsPublicKey<S> {
    /// Private Key
    state: Vec<Trit>,
    /// Market Data
    _sponge: PhantomData<S>,
}

///
///
/// WOTS Signature
///
#[derive(Debug)]
pub struct WotsSignature<S> {
    /// Private Key
    state: Vec<Trit>,
    /// Market Data
    _sponge: PhantomData<S>,
}

///
/// Trait for Wots Private Key Generator
///
pub trait WotsPrivateKeyGenerator<S> {
    /// Private Key
    type PrivateKey;
    /// Generate Private Key
    fn generate(seed: &[Trit], nonce: &[Trit]) -> Result<Self::PrivateKey, String>;
}

impl<S> WotsPrivateKeyGenerator<S> for WotsV1PrivateKeyGenerator<S> {
    type PrivateKey = WotsPrivateKey<S>;

    fn generate(seed: &[Trit], nonce: &[Trit]) -> Result<Self::PrivateKey, String> {
        let mut prng = Prng::new(seed);
        let state = prng.gen(
            PrngDestinationTryte::DstWotsKey,
            nonce,
            MAM_WOTS_PRIVATE_KEY_SIZE,
        )?;

        Ok(WotsPrivateKey {
            state: state,
            _sponge: PhantomData,
        })
    }
}

impl<S> PrivateKey for WotsPrivateKey<S>
where
    S: Default + Sponge<Error = String>,
{
    type PublicKey = WotsPublicKey<S>;
    type Signature = WotsSignature<S>;

    ///
    /// Generate Public Key
    ///
    fn generate_public_key(&self) -> Self::PublicKey {
        let mut spongos = S::default();
        let pk_tmp = self
            .state
            .chunks(MAM_WOTS_PRIVATE_KEY_PART_SIZE)
            .map(|chunk| {
                (0..26)
                    .map(|_| {
                        spongos
                            .hash(&chunk, MAM_WOTS_PRIVATE_KEY_PART_SIZE)
                            .unwrap()
                    })
                    .last()
                    .unwrap()
            })
            .flatten()
            .collect::<Vec<_>>();

        WotsPublicKey {
            state: spongos.hash(&pk_tmp, MAM_WOTS_PUBLIC_KEY_SIZE).unwrap(),
            _sponge: PhantomData,
        }
    }

    ///
    /// Sign
    ///
    fn sign(&self, message: &[i8]) -> Result<Self::Signature, String> {
        let mut signature = [0_i8; MAM_WOTS_PRIVATE_KEY_SIZE];
        signature.copy_from_slice(&self.state);
        let mut spongos = S::default();
        let mut t = 0;
        let mut idx = 0;

        for chunk in signature
            .chunks_mut(MAM_WOTS_PRIVATE_KEY_PART_SIZE)
            .take(77)
        {
            let offset_hash = idx * 3;
            let mut chk = vec![0; MAM_WOTS_PRIVATE_KEY_PART_SIZE];

            let mut h = trits_get3(&message[offset_hash..offset_hash + 3]);

            t += h as i32;
            h = h;

            for _ in -13..h {
                chk = spongos
                    .hash(&chunk, MAM_WOTS_PRIVATE_KEY_PART_SIZE)
                    .unwrap();
            }

            chunk.copy_from_slice(&chk);

            idx += 1;
        }

        t = -t;

        for chunk in signature
            .chunks_mut(MAM_WOTS_PRIVATE_KEY_PART_SIZE)
            .skip(77)
        {
            let mut chk = vec![0; MAM_WOTS_PRIVATE_KEY_PART_SIZE];
            let mut h = mam_mods(t, 19683, 27);
            t = mam_divs(t, 19683, 27);

            h = h;

            for _ in -13..h {
                chk = spongos
                    .hash(&chunk, MAM_WOTS_PRIVATE_KEY_PART_SIZE)
                    .unwrap();
            }

            chunk.copy_from_slice(&chk);
        }

        Ok(WotsSignature {
            state: signature.to_vec(),
            _sponge: PhantomData,
        })
    }
}

impl<S> Default for WotsPrivateKey<S> {
    fn default() -> Self {
        WotsPrivateKey {
            state: vec![0i8; MAM_WOTS_PRIVATE_KEY_SIZE],
            _sponge: PhantomData,
        }
    }
}

impl<S> PublicKey for WotsPublicKey<S>
where
    S: Default + Sponge<Error = String>,
{
    type Signature = WotsSignature<S>;

    ///
    /// Verify
    ///
    fn verify(&self, message: &[i8], signature: &Self::Signature) -> bool {
        let public_key = signature.recover_public_key(message);
        for (st_it, pk_it) in self.state.iter().zip(public_key.state.iter()) {
            if st_it != pk_it {
                return false;
            }
        }
        return true;
    }
    ///
    /// To Bytes
    ///
    fn to_bytes(&self) -> &[i8] {
        &self.state
    }
    ///
    /// To Bytes
    ///
    fn form_bytes(bytes: &[i8]) -> Self {
        WotsPublicKey {
            state: bytes.to_vec(),
            _sponge: PhantomData,
        }
    }
}

impl<S> Signature for WotsSignature<S>
where
    S: Default + Sponge<Error = String>,
{
    type PublicKey = WotsPublicKey<S>;

    ///
    /// Recover Public Key
    ///
    fn recover_public_key(&self, message: &[i8]) -> Self::PublicKey {
        let mut signature = [0_i8; MAM_WOTS_PRIVATE_KEY_SIZE];
        signature.copy_from_slice(&self.state);
        let mut spongos = S::default();

        let mut t = 0;
        let mut idx = 0;

        for chunk in signature
            .chunks_mut(MAM_WOTS_PRIVATE_KEY_PART_SIZE)
            .take(77)
        {
            let offset_hash = idx * 3;
            let mut chk = vec![0; MAM_WOTS_PRIVATE_KEY_PART_SIZE];

            let mut h = trits_get3(&message[offset_hash..offset_hash + 3]);

            t += h as i32;
            h = -h;

            for _ in -13..h {
                chk = spongos
                    .hash(&chunk, MAM_WOTS_PRIVATE_KEY_PART_SIZE)
                    .unwrap();
            }

            chunk.copy_from_slice(&chk);

            idx += 1;
        }

        t = -t;

        for chunk in signature
            .chunks_mut(MAM_WOTS_PRIVATE_KEY_PART_SIZE)
            .skip(77)
        {
            let mut chk = vec![0; MAM_WOTS_PRIVATE_KEY_PART_SIZE];
            let mut h = mam_mods(t, 19683, 27);
            t = mam_divs(t, 19683, 27);

            h = -h;

            for _ in -13..h {
                chk = spongos
                    .hash(&chunk, MAM_WOTS_PRIVATE_KEY_PART_SIZE)
                    .unwrap();
            }

            chunk.copy_from_slice(&chk);
        }

        WotsPublicKey {
            state: spongos.hash(&signature, MAM_WOTS_PUBLIC_KEY_SIZE).unwrap(),
            _sponge: PhantomData,
        }
    }
    ///
    /// To Bytes
    ///
    fn to_bytes(&self) -> &[i8] {
        &self.state
    }
    ///
    /// To Bytes
    ///
    fn form_bytes(bytes: &[i8]) -> Self {
        WotsSignature {
            state: bytes.to_vec(),
            _sponge: PhantomData,
        }
    }
}

#[cfg(test)]
mod should {
    use super::*;
    use crate::spongos::MamSpongos;
    use iota_conversion::Trinary;

    const SEED: &str =
        "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN";

    #[test]
    fn wots_test() {
        let seed_trits = SEED.trits();
        let nonce = [0; 18];
        let private_key: WotsPrivateKey<MamSpongos> =
            WotsV1PrivateKeyGenerator::generate(&seed_trits, &nonce).unwrap();
        let public_key = private_key.generate_public_key();
        let signature = private_key.sign(&seed_trits).unwrap();
        let _rpk = signature.recover_public_key(&seed_trits);

        assert_eq!(public_key.verify(&seed_trits, &signature), true);
    }
}
