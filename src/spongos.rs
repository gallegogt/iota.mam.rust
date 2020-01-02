//! MamSpongos Layer
//!
use crate::{
    definitions::{Sponge, Spongos},
    sponge::{MamSponge, MAM_SPONGE_RATE},
};
use iota_conversion::Trit;

/// MamSpongos
#[derive(Debug, Clone)]
pub struct MamSpongos {
    /// Sponge
    sponge: MamSponge,
    /// Pos
    pos: usize,
}

impl Default for MamSpongos {
    /// Create Default instace of MamSpongos
    fn default() -> Self {
        MamSpongos {
            sponge: MamSponge::default(),
            pos: 0,
        }
    }
}

impl Sponge for MamSpongos {
    type Error = String;
    type AbsorbInput = Vec<Trit>;
    type SqueezeInput = usize;

    /// Absorb
    ///
    /// Proccess input data
    fn absorb(&mut self, trits: Self::AbsorbInput) -> Result<(), Self::Error> {
        for trit in trits.iter() {
            self.sponge.update_state_by_pos(self.pos, trit);
            self.update();
        }
        Ok(())
    }

    /// Squeeze
    ///
    /// Generate output data
    fn squeeze(&mut self, out_length: Self::SqueezeInput) -> Vec<Trit> {
        let mut squeezed: Vec<Trit> = vec![0_i8; out_length];

        for it in 0..out_length {
            squeezed[it] = self.sponge.take_state(self.pos);
            self.sponge.update_state_by_pos(self.pos, &0);
            self.update()
        }
        squeezed
    }

    /// Hash
    ///
    /// Hashing
    fn hash(&mut self, plain_text: &[Trit], hash_len: usize) -> Result<Vec<Trit>, Self::Error> {
        self.reset();
        self.absorb(plain_text.to_vec())?;
        Ok(self.squeeze(hash_len))
    }

    /// Encr
    ///
    /// Encrypt plaintext
    fn encr(&mut self, plain_text: &[Trit]) -> Vec<Trit> {
        let mut ciphertext = vec![0_i8; plain_text.len()];

        for idx in 0..plain_text.len() {
            ciphertext[idx] = match plain_text[idx] + self.sponge.take_state(self.pos) {
                2 => -1,
                -2 => 1,
                v => v,
            };
            self.sponge.update_state_by_pos(self.pos, &ciphertext[idx]);
            self.update();
        }

        ciphertext
    }

    /// Decr
    ///
    /// Decrypt ciphertext
    fn decr(&mut self, ciphertext: &[Trit]) -> Vec<Trit> {
        let mut plaintext = vec![0_i8; ciphertext.len()];

        for idx in 0..ciphertext.len() {
            plaintext[idx] = match ciphertext[idx] - self.sponge.take_state(self.pos) {
                2 => -1,
                -2 => 1,
                v => v,
            };

            self.sponge.update_state_by_pos(self.pos, &plaintext[idx]);
            self.update();
        }

        plaintext
    }

    fn reset(&mut self) {
        unimplemented!();
    }
}

impl Spongos for MamSpongos {
    /// Fork
    ///
    /// Create an equivalent instance
    fn fork(&self) -> Self {
        self.clone()
    }

    /// Commit
    ///
    /// Commit changes in the rate part
    fn commit(&mut self) {
        if self.pos != 0 {
            self.sponge.transform();
            self.pos = 0;
        }
    }
}

impl MamSpongos {
    /// Increment the pos and commit
    fn update(&mut self) {
        self.pos += 1;
        if self.pos == MAM_SPONGE_RATE {
            self.commit()
        }
    }

    /// Reset
    pub fn reset(&mut self) {
        self.sponge = MamSponge::default();
        self.pos = 0;
    }
}

#[cfg(test)]
mod should {
    use super::*;

    #[test]
    fn spongos_test_encr_decr() {
        const FIXED_SIZE: usize = 243;

        let x = vec![0; FIXED_SIZE];

        let mut spos = MamSpongos::default();
        spos.absorb(x.clone()).unwrap();
        spos.commit();
        let y = spos.squeeze(FIXED_SIZE);

        let mut spos1 = MamSpongos::default();
        spos1.absorb(x.clone()).unwrap();
        spos1.commit();
        let mut z = spos1.encr(&x);

        assert_eq!(y, z);

        spos.reset();
        spos.absorb(x.clone()).unwrap();
        spos.commit();
        z = spos.decr(&z.clone());

        assert_eq!(x, z);
    }
}
