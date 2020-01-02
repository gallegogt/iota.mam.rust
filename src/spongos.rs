//! Spongos Layer
//!
use crate::sponge::{MamSponge, MAM_SPONGE_RATE};
use iota_conversion::Trit;

/// Spongos
#[derive(Debug, Clone)]
pub struct Spongos {
    /// Sponge
    sponge: MamSponge,
    /// Pos
    pos: usize,
}

impl Default for Spongos {
    /// Create Default instace of Spongos
    fn default() -> Self {
        Spongos {
            sponge: MamSponge::default(),
            pos: 0,
        }
    }
}

///
/// Spongos Interfaces
///
pub trait ISpongos
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

    /// Absorb
    ///
    /// Proccess input data
    fn absorb(&mut self, trits: &[Trit]);

    /// Squeeze
    ///
    /// Generate output data
    fn squeeze(&mut self, squeezed: &mut [Trit]);

    /// Hash
    ///
    /// Hashing
    fn hash(&mut self, data: &[Trit], hash: &mut [Trit]);

    /// Encr
    ///
    /// Encrypt plaintext
    fn encr(&mut self, plaintext: &[Trit], ciphertext: &mut [Trit]) -> Result<(), String>;

    /// Decr
    ///
    /// Decrypt ciphertext
    fn decr(&mut self, ciphertext: &[Trit], plaintext: &mut [Trit]) -> Result<(), String>;
}

impl ISpongos for Spongos {
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

    /// Absorb
    ///
    /// Proccess input data
    fn absorb(&mut self, trits: &[Trit]) {
        for trit in trits.iter() {
            self.sponge.update_state_by_pos(self.pos, trit);
            self.update();
        }
    }

    /// Squeeze
    ///
    /// Generate output data
    fn squeeze(&mut self, squeezed: &mut [Trit]) {
        for it in 0..squeezed.len() {
            squeezed[it] = self.sponge.take_state(self.pos);
            self.sponge.update_state_by_pos(self.pos, &0);
            self.update()
        }
    }

    /// Hash
    ///
    /// Hashing
    fn hash(&mut self, data: &[Trit], hash: &mut [Trit]) {
        self.reset();
        self.absorb(data);
        self.squeeze(hash);
    }

    /// Encr
    ///
    /// Encrypt plaintext
    fn encr(&mut self, plaintext: &[Trit], ciphertext: &mut [Trit]) -> Result<(), String> {
        if plaintext.len() != ciphertext.len() {
            return Err(format!(
                "The Plain text and cipher text must be the same size"
            ));
        }

        for idx in 0..plaintext.len() {
            ciphertext[idx] = match plaintext[idx] + self.sponge.take_state(self.pos) {
                2 => -1,
                -2 => 1,
                v => v,
            };
            self.sponge.update_state_by_pos(self.pos, &ciphertext[idx]);
            self.update();
        }

        Ok(())
    }

    /// Decr
    ///
    /// Decrypt ciphertext
    fn decr(&mut self, ciphertext: &[Trit], plaintext: &mut [Trit]) -> Result<(), String> {
        if plaintext.len() != ciphertext.len() {
            return Err(format!(
                "The Plain text and cipher text must be the same size"
            ));
        }

        for idx in 0..ciphertext.len() {
            plaintext[idx] = match ciphertext[idx] - self.sponge.take_state(self.pos) {
                2 => -1,
                -2 => 1,
                v => v,
            };

            self.sponge.update_state_by_pos(self.pos, &plaintext[idx]);
            self.update();
        }

        Ok(())
    }
}

impl Spongos {
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

mod should {
    #[test]
    fn spongos_test_encr_decr() {
        use super::{ISpongos, Spongos};
        const FIXED_SIZE: usize = 243;

        let x = vec![0; FIXED_SIZE];
        let mut y = vec![0; FIXED_SIZE];
        let mut z = vec![0; FIXED_SIZE];

        let mut spos = Spongos::default();
        spos.absorb(&x);
        spos.commit();
        spos.squeeze(&mut y);

        let mut spos1 = Spongos::default();
        spos1.absorb(&x);
        spos1.commit();
        spos1.encr(&x, &mut z).unwrap();

        assert_eq!(y, z);

        spos.reset();
        spos.absorb(&x);
        spos.commit();
        spos.decr(&z.clone(), &mut z).unwrap();

        assert_eq!(x, z);
    }
}
