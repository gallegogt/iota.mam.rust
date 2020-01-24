//! MAM Sponge Layer

use crate::definitions::{Sponge, Transform};
use iota_conversion::Trit;
use std::fmt;
use troika::Ftroika;

/// Sponge state rate
pub const MAM_SPONGE_RATE: usize = 486;
/// Sponge state control
pub const MAM_SPONGE_CONTROL: usize = 6;
/// Sponge state capacity
pub const MAM_SPONGE_CAPACITY: usize = 237;
/// Sponge state width
pub const MAM_SPONGE_WIDTH: usize = (MAM_SPONGE_RATE + MAM_SPONGE_CONTROL + MAM_SPONGE_CAPACITY);

/// Sponge fixed key size
pub const MAM_SPONGE_KEY_SIZE: usize = 243;
/// Sponge fixed hash size
pub const MAM_SPONGE_HASH_SIZE: usize = 243;
/// Sponge fixed MAC size
pub const MAM_SPONGE_MAC_SIZE: usize = 243;

/// MAM Sponge CTRL
pub enum SpongeCtrl {
    /// Control trit DATA
    Data = 0,
    /// Control trit HASH
    Hash,
    /// Control trit KEY
    Key,
    /// Control trit PRN
    Prn,
    /// Control trit TEXT
    Text,
    /// Control trit MAC
    Mac,
}

impl SpongeCtrl {
    /// Get Control
    pub fn ctrl(&self) -> Trit {
        match *self {
            SpongeCtrl::Data => 0,
            SpongeCtrl::Hash => 0,
            SpongeCtrl::Key => 1,
            SpongeCtrl::Prn => 1,
            SpongeCtrl::Text => -1,
            SpongeCtrl::Mac => -1,
        }
    }
}

/// Sponge interface
#[derive(Clone)]
pub struct MamSponge {
    /// state
    pub state: [Trit; MAM_SPONGE_WIDTH],
}

impl Default for MamSponge {
    fn default() -> Self {
        MamSponge {
            state: [0; MAM_SPONGE_WIDTH],
        }
    }
}

impl fmt::Debug for MamSponge {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Sponge: [state: {:?}]", self.state.to_vec())
    }
}

///
/// Sponge Transform
///
pub struct SpongeTransform;

impl Transform for SpongeTransform {
    fn transform(state: &mut [Trit]) {
        let mut fstate = state.iter().map(|t| (*t + 1) as u8).collect::<Vec<u8>>();

        let mut ftroika = Ftroika::default();
        ftroika.absorb(&fstate);
        ftroika.squeeze(&mut fstate);

        fstate.iter().enumerate().for_each(|(idx, t)| {
            let v = *t as i8;
            state[idx] = v - 1;
        });
    }
}

impl MamSponge {
    /// Update State by Position
    pub fn update_state_by_pos(&mut self, pos: usize, trit_value: &Trit) {
        self.state[pos] = *trit_value;
    }

    /// Get state in pos
    pub fn take_state(&self, pos: usize) -> Trit {
        self.state[pos]
    }
    ///
    /// Transform State
    ///
    pub fn transform(&mut self) {
        SpongeTransform::transform(&mut self.state);
    }
}

impl Sponge for MamSponge {
    type Error = String;
    type AbsorbInput = (SpongeCtrl, Vec<Trit>);
    type SqueezeInput = (SpongeCtrl, usize);

    fn absorb(&mut self, absorb_info: Self::AbsorbInput) -> Result<(), Self::Error> {
        let c2 = absorb_info.0;
        let chk = match c2 {
            SpongeCtrl::Data => false,
            SpongeCtrl::Key => false,
            _ => true,
        };
        if chk {
            return Err(format!(
                "Control Trits must be MAM_SPONGE_CTL_DATA or MAM_SPONGE_CTL_KEY"
            ));
        }

        let r_data = if absorb_info.1.len() == 0 {
            [0i8].to_vec()
        } else {
            absorb_info.1
        };

        let n: usize = (r_data.len() as f32 / MAM_SPONGE_RATE as f32).ceil() as usize;
        r_data
            .chunks(MAM_SPONGE_RATE)
            .enumerate()
            .for_each(|(idx, chunk)| {
                let c0 = if chunk.len() == MAM_SPONGE_RATE { 1 } else { 0 };
                let c1 = if idx == (n - 1) { -1 } else { 1 };

                if self.state[MAM_SPONGE_RATE + 1] != 0 {
                    self.state[489..492].copy_from_slice(&[c0, c1, c2.ctrl()]);
                    SpongeTransform::transform(&mut self.state);
                }

                let mut padr = [0; MAM_SPONGE_RATE + 1];
                padr[..chunk.len()].copy_from_slice(&chunk);
                padr[chunk.len()] = 1;

                self.state[..487].copy_from_slice(&padr);
                self.state[487..489].copy_from_slice(&[c1, c2.ctrl()]);
            });

        Ok(())
    }

    fn squeeze(&mut self, data: Self::SqueezeInput) -> Vec<Trit> {
        let n: usize = (data.1 as f32 / MAM_SPONGE_RATE as f32).ceil() as usize;

        (0..data.1)
            .collect::<Vec<_>>()
            .chunks(MAM_SPONGE_RATE)
            .enumerate()
            .map(|(idx, c_data)| {
                let mut chunk = vec![0_i8; c_data.len()];

                let t0: Trit = -1;
                let t1: Trit = if idx == (n - 1) { -1 } else { 1 };

                self.state[489..492].copy_from_slice(&[t0, t1, data.0.ctrl()]);

                SpongeTransform::transform(&mut self.state);

                chunk.copy_from_slice(&self.state[..c_data.len()]);

                if chunk.len() == MAM_SPONGE_RATE {
                    self.state[..MAM_SPONGE_RATE].copy_from_slice(&[0; MAM_SPONGE_RATE]);
                } else {
                    let mut padr: [Trit; MAM_SPONGE_RATE] = [0; MAM_SPONGE_RATE];
                    padr[chunk.len() - 1] = 1;
                    self.state[..MAM_SPONGE_RATE].copy_from_slice(&padr);
                }
                self.state[MAM_SPONGE_RATE..489].copy_from_slice(&[t0, t1, data.0.ctrl()]);
                chunk
            })
            .collect::<Vec<_>>()
            .concat()
    }

    fn hash(&mut self, plain_text: &[Trit], hash_len: usize) -> Result<Vec<Trit>, Self::Error> {
        self.reset();
        self.absorb((SpongeCtrl::Data, plain_text.to_vec()))?;
        Ok(self.squeeze((SpongeCtrl::Hash, hash_len)))
    }

    fn encr(&mut self, plain_text: &[Trit]) -> Vec<Trit> {
        let mut cipher_text: Vec<Trit> = vec![0_i8; plain_text.len()];

        let n: usize = (plain_text.len() as f32 / MAM_SPONGE_RATE as f32).ceil() as usize;
        let mut it_pt = plain_text.chunks(MAM_SPONGE_RATE).enumerate();
        let mut it_ch = cipher_text.chunks_mut(MAM_SPONGE_RATE);

        loop {
            match it_pt.next() {
                Some((idx, chunk)) => {
                    let chunk_ch = it_ch.next().unwrap();
                    // control trit
                    let t0 = if chunk.len() == MAM_SPONGE_RATE { 1 } else { 0 };
                    let t1 = if idx == (n - 1) { -1 } else { 1 };
                    // Update State
                    self.state[489..492].copy_from_slice(&[t0, t1, -1]);
                    SpongeTransform::transform(&mut self.state);

                    for (it, value) in chunk
                        .iter()
                        .zip(self.state[..chunk.len()].iter())
                        .enumerate()
                    {
                        chunk_ch[it] = match value.0 + value.1 {
                            -2 => 1,
                            2 => -1,
                            v => v,
                        };
                    }

                    let mut padr = [0; MAM_SPONGE_RATE + 1];
                    padr[..chunk.len()].copy_from_slice(&chunk);
                    padr[chunk.len()] = 1;

                    self.state[..MAM_SPONGE_RATE + 1].copy_from_slice(&padr);
                    self.state[MAM_SPONGE_RATE + 1..MAM_SPONGE_RATE + 3].copy_from_slice(&[t1, -1]);
                }
                None => break,
            }
        }
        cipher_text
    }

    fn decr(&mut self, cipher_text: &[Trit]) -> Vec<Trit> {
        let mut plain_text: Vec<Trit> = vec![0_i8; cipher_text.len()];
        let n: usize = (cipher_text.len() as f32 / MAM_SPONGE_RATE as f32).ceil() as usize;
        let mut it_pt = plain_text.chunks_mut(MAM_SPONGE_RATE);
        let mut it_ch = cipher_text.chunks(MAM_SPONGE_RATE).enumerate();

        loop {
            match it_ch.next() {
                Some((idx, chunk)) => {
                    let chunk_pt = it_pt.next().unwrap();
                    let t0 = if chunk.len() == MAM_SPONGE_RATE { 1 } else { 0 };
                    let t1 = if idx == (n - 1) { -1 } else { 1 };
                    // Control
                    self.state[489..492].copy_from_slice(&[t0, t1, -1]);
                    SpongeTransform::transform(&mut self.state);

                    for (it, value) in chunk
                        .iter()
                        .zip(self.state[..chunk.len()].iter())
                        .enumerate()
                    {
                        chunk_pt[it] = match value.0 - value.1 {
                            -2 => 1,
                            2 => -1,
                            v => v,
                        };
                    }

                    let mut padr = [0; MAM_SPONGE_RATE + 1];
                    padr[..chunk_pt.len()].copy_from_slice(&chunk_pt);
                    padr[chunk_pt.len()] = 1;

                    self.state[..MAM_SPONGE_RATE + 1].copy_from_slice(&padr);
                    self.state[MAM_SPONGE_RATE + 1..MAM_SPONGE_RATE + 3].copy_from_slice(&[t1, -1]);
                }
                None => break,
            }
        }

        plain_text
    }

    fn reset(&mut self) {
        self.state = [0; MAM_SPONGE_WIDTH];
    }
}

#[cfg(test)]
mod should {
    use crate::{
        definitions::Sponge,
        sponge::{MamSponge, SpongeCtrl},
    };
    use iota_conversion::Trinary;
    const TRYTES: &str =
        "NOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLM";

    #[test]
    fn sponge_absorb_squeeze_data() {
        let mut layer = MamSponge::default();
        layer.absorb((SpongeCtrl::Key, TRYTES.trits())).unwrap();
        let prn_trits = layer.squeeze((SpongeCtrl::Prn, 81 * 3));
        assert!(TRYTES.trits().len() == prn_trits.len())
    }

    #[test]
    fn sponge_encr_decr_data() {
        let trits_size = [
            0, 1, 2, 3, 4, 5, 6, 242, 243, 244, 485, 486, 487, 972, 1110, 1111,
        ];

        let mut k = TRYTES.trits();
        let k_len = k.len();
        let mut sponge = MamSponge::default();
        sponge.absorb((SpongeCtrl::Key, k.clone())).unwrap();
        k = sponge.squeeze((SpongeCtrl::Prn, k_len));

        for st in trits_size.iter() {
            let x = vec![0_i8; *st];

            sponge.reset();
            sponge.absorb((SpongeCtrl::Key, k.clone())).unwrap();
            let y = sponge.encr(&x); // Y = E(X)

            sponge.reset();
            sponge.absorb((SpongeCtrl::Key, k.clone())).unwrap();
            let mut z = sponge.decr(&y); // Z = D(E(X))
            assert_eq!(x, z);

            sponge.reset();
            sponge.absorb((SpongeCtrl::Key, k.clone())).unwrap();
            z = sponge.encr(&z.clone()); // Z = E( Z = X )
            assert_eq!(y, z);

            sponge.reset();
            sponge.absorb((SpongeCtrl::Key, k.clone())).unwrap();
            z = sponge.decr(&z.clone()); //Z = D( Z = E ( X ))
            assert_eq!(x, z);
        }
    }
}
