//! PRNG Layer
//!
//! The PRNG layer supports the generation of cryptographically strong pseudorandom numbers or,
//! more precisely, strings of trytes. The layer makes calls to the Sponge layer
//!

use crate::sponge::{ISponge, Sponge, SpongeCtrl};
use iota_conversion::Trit;
use std::fmt;

/// PRNG Secret Key Size
///
pub const MAM_PRNG_SECRET_KEY_SIZE: usize = 243;

/// PRNG Destination Tryte
///
pub enum PrngDestinationTryte {
    DstSecKey = 0,
    DstWotsKey = 1,
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
        output: &mut [Trit],
    ) -> Result<(), String> {
        let mut spg = Sponge::default();
        let mut data: Vec<Trit> = vec![0; MAM_PRNG_SECRET_KEY_SIZE + 3 + nonce.len()];
        data[0..self.secret_key.len()].copy_from_slice(&self.secret_key);
        data[MAM_PRNG_SECRET_KEY_SIZE..MAM_PRNG_SECRET_KEY_SIZE + 3]
            .copy_from_slice(&destination.trits());
        data[3 + MAM_PRNG_SECRET_KEY_SIZE..].copy_from_slice(&nonce);

        spg.absorb(SpongeCtrl::Key, &data)?;
        spg.squeeze(SpongeCtrl::Prn, output)?;
        Ok(())
    }
}

mod should {
    #[test]
    fn test_prng() {
        use super::{Prng, PrngDestinationTryte, MAM_PRNG_SECRET_KEY_SIZE};
        use iota_conversion::Trinary;
        const KEY_TRYTES: &str =
            "NOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLM";

        let k = KEY_TRYTES.trits();
        let n = [0i8; 18];
        let mut y1 = vec![0i8; MAM_PRNG_SECRET_KEY_SIZE * 2 + 18];
        let mut y2 = vec![0i8; MAM_PRNG_SECRET_KEY_SIZE * 2 + 18];

        let mut prng = Prng::new(&k);
        prng.gen(PrngDestinationTryte::DstSecKey, &n, &mut y1)
            .unwrap();
        prng.gen(PrngDestinationTryte::DstWotsKey, &n, &mut y2)
            .unwrap();

        assert_ne!(y1, y2)
    }
}
