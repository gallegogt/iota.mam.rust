//! PRNG Layer
//!
//! The PRNG layer supports the generation of cryptographically strong pseudorandom numbers or,
//! more precisely, strings of trytes. The layer makes calls to the Sponge layer
//!

use crate::{
    definitions::Sponge,
    sponge::{MamSponge, SpongeCtrl},
};
use iota_conversion::Trit;
use std::fmt;

/// PRNG Secret Key Size
///
pub const MAM_PRNG_SECRET_KEY_SIZE: usize = 243;

/// PRNG Destination Tryte
///
pub enum PrngDestinationTryte {
    /// DstSecKey
    DstSecKey = 0,
    /// DstWotsKey
    DstWotsKey = 1,
    /// DstNtruKey
    DstNtruKey = 2,
}

impl PrngDestinationTryte {
    /// Return Trits
    pub fn trits(&self) -> [Trit; 3] {
        match *self {
            PrngDestinationTryte::DstSecKey => [0, 0, 0],
            PrngDestinationTryte::DstWotsKey => [1, 0, 0],
            PrngDestinationTryte::DstNtruKey => [-1, 1, 0],
        }
    }
}

/// PRNG Layer
///
#[derive(Clone)]
pub struct Prng {
    secret_key: [Trit; MAM_PRNG_SECRET_KEY_SIZE],
}

impl fmt::Debug for Prng {
    /// Format
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Prng: [secret_key: {:?}]", self.secret_key.to_vec())
    }
}

impl Prng {
    ///
    /// New instance
    ///
    pub fn new(secret_key: &[Trit]) -> Self {
        let mut sk = [0i8; MAM_PRNG_SECRET_KEY_SIZE];
        sk[0..MAM_PRNG_SECRET_KEY_SIZE].copy_from_slice(secret_key);
        Prng { secret_key: sk }
    }
    ///
    ///  Generate pseudoreandom numbers
    ///
    pub fn gen(
        &mut self,
        destination: PrngDestinationTryte,
        nonce: &[Trit],
        n: usize,
    ) -> Result<Vec<Trit>, String> {
        let mut spg = MamSponge::default();
        let data = [&self.secret_key, &destination.trits()[..], &nonce[..]].concat();
        spg.absorb((SpongeCtrl::Key, data))?;
        Ok(spg.squeeze((SpongeCtrl::Prn, n)))
    }
}

#[cfg(test)]
mod should {
    #[test]
    fn test_prng() {
        use super::{Prng, PrngDestinationTryte, MAM_PRNG_SECRET_KEY_SIZE};
        use iota_conversion::Trinary;
        const KEY_TRYTES: &str =
            "NOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLM";

        let k = KEY_TRYTES.trits();
        let n = [0i8; 18];
        let mut prng = Prng::new(&k);
        let y1 = prng
            .gen(
                PrngDestinationTryte::DstSecKey,
                &n,
                MAM_PRNG_SECRET_KEY_SIZE * 2 + 18,
            )
            .unwrap();
        let y2 = prng
            .gen(
                PrngDestinationTryte::DstWotsKey,
                &n,
                MAM_PRNG_SECRET_KEY_SIZE * 2 + 18,
            )
            .unwrap();

        assert_ne!(y1, y2)
    }
}
