//!
//! MAM Sponge Layer
//!

use iota_conversion::Trit;
use std::fmt;
use troika_rust::Ftroika;

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

///
/// MAM Sponge CTRL
///
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

///
/// Mam Sponge Definition
///
pub trait ISponge
where
    Self: Default + Clone,
{
    /// Sponge absorption
    ///
    /// Arguments
    ///      c2 Control trit encoding output data type
    ///      data Input data blocks
    ///
    fn absorb(&mut self, c2: SpongeCtrl, data: &[Trit]) -> Result<(), String>;

    /// Sponge squeezing
    ///
    /// Arguments
    ///     c2 Control trit encoding output data type
    ///     squeezed Output data
    ///
    fn squeeze(&mut self, c2: SpongeCtrl, squeezed: &mut [Trit]) -> Result<(), String>;

    /// Sponge Hashing
    ///
    /// Arguments
    ///     plain_text Input data
    ///     digest Hash value
    fn hash(&mut self, plain_text: &[Trit], digest: &mut [Trit]) -> Result<(), String>;

    /// Sponge AE encryption
    ///
    /// Arguments
    ///     plain_text Input data
    ///
    fn encr(&mut self, plain_text: &[Trit], cipher_text: &mut [Trit]) -> Result<(), String>;

    /// Sponge AE decryption
    ///
    /// Arguments
    ///     cipher_text Hash value
    ///     plain_text Input data
    ///
    fn decr(&mut self, cipher_text: &[Trit], plain_text: &mut [Trit]) -> Result<(), String>;
}

///
/// Sponge interface
///
#[derive(Clone)]
pub struct Sponge {
    /// state
    state: [Trit; MAM_SPONGE_WIDTH],
}

impl Default for Sponge {
    fn default() -> Self {
        Sponge {
            state: [0; MAM_SPONGE_WIDTH],
        }
    }
}

impl fmt::Debug for Sponge {
    /// Format
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Sponge: [state: {:?}]", self.state.to_vec())
    }
}

impl Sponge {
    /// Transform Function
    pub fn transform(&mut self) {
        let mut fstate: [u8; MAM_SPONGE_WIDTH] = [0; MAM_SPONGE_WIDTH];

        for (idx, t) in self.state.iter().enumerate() {
            fstate[idx] = (*t + 1) as u8;
        }

        let mut ftroika = Ftroika::default();
        ftroika.absorb(&fstate);
        ftroika.finalize();
        ftroika.squeeze(&mut fstate);

        for (idx, t) in fstate.iter().enumerate() {
            let v = *t as i8;
            self.state[idx] = v - 1;
        }
    }

    /// Reset State
    fn reset(&mut self) {
        self.state = [0; MAM_SPONGE_WIDTH];
    }

    /// Update State by Position
    pub fn update_state_by_pos(&mut self, pos: usize, trit_value: &Trit) {
        self.state[pos] = *trit_value;
    }

    /// Get state in pos
    pub fn take_state(&self, pos: usize) -> Trit {
        self.state[pos]
    }
}

impl ISponge for Sponge {
    /// Sponge absorption
    ///
    /// Arguments
    ///      c2 Control trit encoding output data type
    ///      data Input data blocks
    ///
    fn absorb(&mut self, c2: SpongeCtrl, data: &[Trit]) -> Result<(), String> {
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

        let mut r_data = data.clone();
        if data.is_empty() {
            r_data = &[0i8];
        }

        let n: usize = (r_data.len() as f32 / MAM_SPONGE_RATE as f32).ceil() as usize;
        for (idx, chunk) in r_data.chunks(MAM_SPONGE_RATE).enumerate() {
            let c0 = if chunk.len() == MAM_SPONGE_RATE { 1 } else { 0 };
            let c1 = if idx == (n - 1) { -1 } else { 1 };

            if self.state[MAM_SPONGE_RATE + 1] != 0 {
                self.state[489..492].copy_from_slice(&[c0, c1, c2.ctrl()]);
                self.transform();
            }

            let mut padr = [0; MAM_SPONGE_RATE + 1];
            padr[..chunk.len()].copy_from_slice(&chunk);
            padr[chunk.len()] = 1;

            self.state[..487].copy_from_slice(&padr);
            self.state[487..489].copy_from_slice(&[c1, c2.ctrl()]);
        }

        Ok(())
    }

    /// Sponge squeezing
    ///
    /// Arguments
    ///     c2 Control trit encoding output data type
    ///     squeezed Output data
    ///
    fn squeeze(&mut self, c2: SpongeCtrl, squeezed: &mut [Trit]) -> Result<(), String> {
        let n: usize = (squeezed.len() as f32 / MAM_SPONGE_RATE as f32).ceil() as usize;

        for (idx, chunk) in squeezed.chunks_mut(MAM_SPONGE_RATE).enumerate() {
            let t0: Trit = -1;
            let t1: Trit = if idx == (n - 1) { -1 } else { 1 };

            self.state[489..492].copy_from_slice(&[t0, t1, c2.ctrl()]);
            self.transform();
            chunk.copy_from_slice(&self.state[..chunk.len()]);

            if chunk.len() == MAM_SPONGE_RATE {
                self.state[..MAM_SPONGE_RATE].copy_from_slice(&[0; MAM_SPONGE_RATE]);
            } else {
                let mut padr: [Trit; MAM_SPONGE_RATE] = [0; MAM_SPONGE_RATE];
                padr[chunk.len() - 1] = 1;
                self.state[..MAM_SPONGE_RATE].copy_from_slice(&padr);
            }
            self.state[MAM_SPONGE_RATE..489].copy_from_slice(&[t0, t1, c2.ctrl()]);
        }
        Ok(())
    }

    /// Sponge Hashing
    ///
    /// Arguments
    ///     plain_text Input data
    ///     digest Hash value
    fn hash(&mut self, plain_text: &[Trit], digest: &mut [Trit]) -> Result<(), String> {
        self.reset();
        self.absorb(SpongeCtrl::Data, plain_text)?;
        self.squeeze(SpongeCtrl::Hash, digest)?;
        Ok(())
    }

    /// Sponge AE encryption
    ///
    /// Arguments
    ///     plain_text Input data
    ///     [out] cipher_text
    ///
    fn encr(&mut self, plain_text: &[Trit], cipher_text: &mut [Trit]) -> Result<(), String> {
        if cipher_text.len() != plain_text.len() {
            return Err("Cipher text and plain text must be the same length".to_string());
        }

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
                    self.transform();

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
        Ok(())
    }

    /// Sponge AE decryption
    ///
    /// Arguments
    ///     cipher_text Hash value
    ///     [out] plain_text data
    ///
    fn decr(&mut self, cipher_text: &[Trit], plain_text: &mut [Trit]) -> Result<(), String> {
        if cipher_text.len() != plain_text.len() {
            return Err("Cipher text and plain text must be the same length".to_string());
        }

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
                    self.transform();

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

        Ok(())
    }
}

mod should {
    use crate::sponge::{ISponge, Sponge, SpongeCtrl};
    use iota_conversion::Trinary;
    const TRYTES: &str =
        "NOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLM";

    #[test]
    fn absorb_squeeze_data() {
        let in_trits = TRYTES.trits();
        let mut prn_trits = vec![0; 81 * 3];
        let mut layer = Sponge::default();
        layer.absorb(SpongeCtrl::Key, &in_trits).unwrap();
        layer.squeeze(SpongeCtrl::Prn, &mut prn_trits).unwrap();
        assert!(in_trits.len() == prn_trits.len())
    }

    #[test]
    fn encr_decr_data() {
        let trits_size = [
            0, 1, 2, 3, 4, 5, 6, 242, 243, 244, 485, 486, 487, 972, 1110, 1111,
        ];

        let mut k = TRYTES.trits();
        let mut sponge = Sponge::default();
        sponge.absorb(SpongeCtrl::Key, &mut k).unwrap();
        sponge.squeeze(SpongeCtrl::Prn, &mut k).unwrap();

        for st in trits_size.iter() {
            let x = vec![0; *st];
            let mut y = vec![0; *st];
            let mut z = vec![0; *st];

            sponge.reset();
            sponge.absorb(SpongeCtrl::Key, &mut k).unwrap();
            sponge.encr(&x, &mut y).unwrap(); // Y = E(X)

            sponge.reset();
            sponge.absorb(SpongeCtrl::Key, &mut k).unwrap();
            sponge.decr(&y, &mut z).unwrap(); // Z = D(E(X))
            assert_eq!(x, z);

            sponge.reset();
            sponge.absorb(SpongeCtrl::Key, &mut k).unwrap();
            sponge.encr(&z.clone(), &mut z).unwrap(); // Z = E( Z = X )
            assert_eq!(y, z);

            sponge.reset();
            sponge.absorb(SpongeCtrl::Key, &mut k).unwrap();
            sponge.decr(&z.clone(), &mut z).unwrap(); //Z = D( Z = E ( X ))
            assert_eq!(x, z);
        }
    }

}
