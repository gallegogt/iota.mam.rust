//! WOTS Layer
//!
//! The WOTS Layer supports Winternitz One-Time Signatures
//!

use crate::conversion::trits_from_value;
use crate::prng::{Prng, PrngDestinationTryte};
use crate::spongos::{ISpongos, Spongos};
use crate::{mam_divs, mam_mods, trits_get3};
use iota_conversion::Trit;
use std::fmt;

/// Size of a WOTS public key
const MAM_WOTS_PUBLIC_KEY_SIZE: usize = 243;
/// Size of a WOTS private key part
const MAM_WOTS_PRIVATE_KEY_PART_SIZE: usize = 162;
/// Number of parts in a WOTS private key
const MAM_WOTS_PRIVATE_KEY_PART_COUNT: usize = 81;
/// Size of a WOTS private key
const MAM_WOTS_PRIVATE_KEY_SIZE: usize =
    (MAM_WOTS_PRIVATE_KEY_PART_SIZE * MAM_WOTS_PRIVATE_KEY_PART_COUNT);
/// Size of a WOTS signed hash
const MAM_WOTS_HASH_SIZE: usize = 234;
/// Size of a WOTS signature
const MAM_WOTS_SIGNATURE_SIZE: usize = MAM_WOTS_PRIVATE_KEY_SIZE;

///
/// WOTS
///
#[derive(Clone)]
struct Wots {
    private_key: [Trit; MAM_WOTS_PRIVATE_KEY_SIZE],
}

impl Default for Wots {
    fn default() -> Self {
        Wots {
            private_key: [0i8; MAM_WOTS_PRIVATE_KEY_SIZE],
        }
    }
}

/// Interface for WOTS
pub trait IWots {
    /// Generates a WOTS private key with a nonce
    ///
    fn gen_sk(&mut self, prng: &mut Prng, nonce: &[Trit]) -> Result<(), String>;

    /// Generates a WOTS public key associated with a WOTS private key
    ///
    /// The Private key must have already been generated
    ///
    fn gen_pk(&self, pk: &mut [Trit; MAM_WOTS_PUBLIC_KEY_SIZE]) -> Result<(), String>;

    /// Generates a WOTS signature associated with a WOTS private key
    ///
    fn sign(
        &self,
        hash: &[Trit; MAM_WOTS_HASH_SIZE],
        signature: &mut [Trit; MAM_WOTS_PRIVATE_KEY_SIZE],
    ) -> Result<(), String>;

    /// Recover a presumed public key from a signature
    ///
    fn recover(
        &self,
        hash: &[Trit; MAM_WOTS_HASH_SIZE],
        signature: &[Trit; MAM_WOTS_PRIVATE_KEY_SIZE],
        public_key: &mut [Trit; MAM_WOTS_PUBLIC_KEY_SIZE],
    ) -> Result<(), String>;

    /// Resets a WOTS private key
    ///
    fn reset(&mut self);
}

impl IWots for Wots {
    /// Generates a WOTS private key with a nonce
    ///
    fn gen_sk(&mut self, prng: &mut Prng, nonce: &[Trit]) -> Result<(), String> {
        prng.gen(
            PrngDestinationTryte::DstWotsKey,
            nonce,
            &mut self.private_key,
        )
    }

    /// Generates a WOTS public key associated with a WOTS private key
    ///
    ///
    fn gen_pk(&self, pk: &mut [Trit; MAM_WOTS_PUBLIC_KEY_SIZE]) -> Result<(), String> {
        let mut pk_part = [0i8; MAM_WOTS_PRIVATE_KEY_PART_SIZE];
        let mut pk_tmp = [0i8; MAM_WOTS_PRIVATE_KEY_SIZE];

        // let mut spongos_part = Spongos::default();
        let mut spongos = Spongos::default();

        for (idx, chunk) in self
            .private_key
            .chunks(MAM_WOTS_PRIVATE_KEY_PART_SIZE)
            .enumerate()
        {
            for _ in 0..26 {
                spongos.hash(chunk.clone(), &mut pk_part);
            }

            let offset = idx * MAM_WOTS_PRIVATE_KEY_PART_SIZE;
            let length = offset + MAM_WOTS_PRIVATE_KEY_PART_SIZE;
            pk_tmp[offset..length].copy_from_slice(&pk_part);
        }

        spongos.hash(&pk_tmp, pk);

        Ok(())
    }

    /// Generates a WOTS signature associated with a WOTS private key
    ///
    fn sign(
        &self,
        hash: &[Trit; MAM_WOTS_HASH_SIZE],
        signature: &mut [Trit; MAM_WOTS_PRIVATE_KEY_SIZE],
    ) -> Result<(), String> {
        signature.copy_from_slice(&self.private_key);
        let mut spongos = Spongos::default();
        self.hash_sign_or_recover(&mut spongos, hash, signature, 0);
        Ok(())
    }

    /// Recover a presumed public key from a signature
    ///
    fn recover(
        &self,
        hash: &[Trit; MAM_WOTS_HASH_SIZE],
        signature: &[Trit; MAM_WOTS_PRIVATE_KEY_SIZE],
        public_key: &mut [Trit; MAM_WOTS_PUBLIC_KEY_SIZE],
    ) -> Result<(), String> {
        let mut sig_pks = [0; MAM_WOTS_PRIVATE_KEY_SIZE];
        sig_pks.copy_from_slice(signature);
        let mut spongos = Spongos::default();

        self.hash_sign_or_recover(&mut spongos, hash, &mut sig_pks, 1);
        spongos.hash(&sig_pks, public_key);
        Ok(())
    }

    /// Resets a WOTS private key
    ///
    fn reset(&mut self) {
        self.private_key = [0; MAM_WOTS_PRIVATE_KEY_SIZE];
    }
}

impl Wots {
    ///
    /// Build WOTS HASH Sign or Recover
    ///
    /// Arguments
    ///     spongos
    ///     hash: Hash trits
    ///     signature: Signature Trits
    ///     operation: 0 => WOTS_HASH_SIGN, 1 => WOTS_HASH_RECOVER
    ///
    fn hash_sign_or_recover(
        &self,
        spongos: &mut Spongos,
        hash: &[Trit],
        signature: &mut [Trit],
        operation: i8,
    ) {
        let mut t = 0;
        let mut idx = 0;

        for chunk in signature
            .chunks_mut(MAM_WOTS_PRIVATE_KEY_PART_SIZE)
            .take(77)
        {
            let offset_hash = idx * 3;
            let mut chk = [0; MAM_WOTS_PRIVATE_KEY_PART_SIZE];

            let mut h = trits_get3(&hash[offset_hash..offset_hash + 3]);

            t += h as i32;
            h = if operation == 0 { h } else { -h };

            for _ in -13..h {
                spongos.hash(&chunk, &mut chk);
            }

            chunk.copy_from_slice(&chk);

            idx += 1;
        }

        t = -t;

        for chunk in signature
            .chunks_mut(MAM_WOTS_PRIVATE_KEY_PART_SIZE)
            .skip(77)
        {
            let mut chk = [0; MAM_WOTS_PRIVATE_KEY_PART_SIZE];
            let mut h = mam_mods(t, 19683, 27);
            t = mam_divs(t, 19683, 27);

            h = if operation == 0 { h } else { -h };

            for _ in -13..h {
                spongos.hash(&chunk, &mut chk);
            }

            chunk.copy_from_slice(&chk);
        }
    }
}

impl fmt::Debug for Wots {
    /// Format
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "WOTS: [private_key: {:?}]", self.private_key.to_vec())
    }
}

mod should {
    use super::*;
    use crate::prng::{Prng, MAM_PRNG_SECRET_KEY_SIZE};

    #[test]
    fn wots_test() {
        let sk = [0; MAM_PRNG_SECRET_KEY_SIZE];
        let mut prng = Prng::new(&sk);
        let mut wots = Wots::default();

        let nonce = [0; 18];
        let mut pk = [0i8; MAM_WOTS_PUBLIC_KEY_SIZE];
        let mut recovered_pk = [0; MAM_WOTS_PUBLIC_KEY_SIZE];
        let mut hash = [0; MAM_WOTS_HASH_SIZE];
        let mut sign = [0; MAM_WOTS_SIGNATURE_SIZE];

        wots.reset();
        prng.gen(PrngDestinationTryte::DstWotsKey, &nonce, &mut hash)
            .unwrap();
        wots.gen_sk(&mut prng, &nonce).unwrap();
        wots.gen_pk(&mut pk).unwrap();

        wots.sign(&hash, &mut sign).unwrap();

        wots.recover(&hash, &sign, &mut recovered_pk).unwrap();

        assert_eq!(pk.to_vec(), recovered_pk.to_vec());
    }
}
