//! Merkle Tree Signature Scheme
//!
//! Classic Implementation
//!

use crate::constants::Trit;
use crate::prng::Prng;
use crate::spongos::{ISpongos, Spongos};
use crate::wots::{MAM_WOTS_HASH_SIZE, MAM_WOTS_PUBLIC_KEY_SIZE, MAM_WOTS_SIGNATURE_SIZE};

/// MSS public key size
///
pub const MSS_PK_SIZE: usize = 243;

/// Trits needed to encode tree depth part of SKN.
///
pub const MSS_SKN_TREE_DEPTH_SIZE: usize = 4;

/// Trits needed to encode key number part of SKN.
///
pub const MSS_SKN_KEY_NUMBER_SIZE: usize = 14;

/// Trits needed to encode `skn`: tree depth and key number.
///
pub const MSS_SKN_SIZE: usize = MSS_SKN_TREE_DEPTH_SIZE + MSS_SKN_KEY_NUMBER_SIZE;

/// MSS signed hash value size.
///
pub const MSS_HASH_SIZE: usize = MAM_WOTS_HASH_SIZE;

/// Max Merkle-Tree height
///
pub const MSS_MAX_D: usize = 20;

/// Size of hash values stored in Merkle tree
///
pub const MSS_MT_HASH_SIZE: usize = MAM_WOTS_PUBLIC_KEY_SIZE;

///
/// Implementation of Merkle-Tree Signature Scheme (Classic)
///
/// MSS interface used to generate public key and sign.
///
pub struct Mss {
    /// Merkle tree height.
    ///
    height: i8,
    /// Current WOTS private key number.
    ///
    skn: i32,
    /// PRNG interface used to generate WOTS private keys.
    ///
    prng: Prng,
    /// Buffer storing complete Merkle-tree
    ///
    mt: Vec<Trit>,
    /// Nonce
    ///
    nonce: Vec<Trit>,
    /// Merkle Root
    ///
    root: [Trit; MSS_PK_SIZE],
}

impl Mss {
    /// MSS interface initialization
    ///
    pub fn new(prng: &Prng, height: usize, nonce: &[Trit]) -> Result<Self, ()> {
        if 0 <= height && height <= MSS_MAX_D {
            return Ok(Mss {
                height: height as i8,
                skn: 0,
                prng: prng.clone(),
                mt: Vec::new(),
                nonce: nonce.to_vec(),
                root: [0; MSS_PK_SIZE],
            });
        }
        Err(())
    }
    /// Generate MSS keys, stores current and next auth_path
    ///
    pub fn gen(&mut self) {
        let mut root = [0; MSS_PK_SIZE];
        let mut mt_height: i8 = 0;
        let mut n: i32 = 1 << self.height;

        let mut spongos = Spongos::default();

        for idx in 0..n {}
    }

    /// Private Functions
    ///
    ///
    ///  MSS authentication path size of height `d`
    ///
    fn apath_size(&self, d: usize) -> usize {
        MAM_WOTS_PUBLIC_KEY_SIZE * d
    }

    ///
    /// MSS signature size with a tree of height `d`
    ///
    fn sig_size(&self, d: usize) -> usize {
        MSS_SKN_SIZE + MAM_WOTS_SIGNATURE_SIZE + self.apath_size(d)
    }
}
