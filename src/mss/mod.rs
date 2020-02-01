//!
//! Merkle Signature Scheme
//!
//! Based on FMTSEQ => https://github.com/exaexa/codecrypt/blob/master/src/fmtseq.h
//!
mod internal;

use crate::{
    definitions::{
        ss::{PrivateKey, PrivateKeyGenerator, PublicKey, Signature},
        Sponge,
    },
    mss::internal::{InternalPrivateKey, TreeStackItem},
    wots::WotsSignature,
};
use iota_conversion::{long_value as trist_to_value, Trinary, Trit};
use std::{cell::RefCell, marker::PhantomData};

///
/// HASH LENGTH
///
const HASH_LEN: usize = 243;

/// MSS PrivateKey Generator
///
#[derive(Debug)]
pub struct MssPrivateKeyGenerator<S, G> {
    /// Subtree Height
    height: usize,
    /// Tree Level
    level: usize,
    /// Sponge
    _sponge: PhantomData<S>,
    _generator: PhantomData<G>,
}

///
///
/// MSS Private Key
///
#[derive(Clone)]
pub struct MssPrivateKey<S, G> {
    /// Intenal Implementation
    i_mt: RefCell<InternalPrivateKey<S, G>>,
    /// Public Key
    root: Vec<Trit>,
    /// Market Data
    _sponge: PhantomData<S>,
    _gen: PhantomData<G>,
}

///
///
/// MSS Public Key
///
#[derive(Debug, Clone)]
pub struct MssPublicKey<S> {
    /// Private Key
    pub state: Vec<Trit>,
    /// Height
    h: usize,
    /// Market Data
    _sponge: PhantomData<S>,
}

///
///
/// MSS Signature
///
#[derive(Debug)]
pub struct MssSignature<S> {
    /// Private Key
    state: Vec<Trit>,
    /// Market Data
    _sponge: PhantomData<S>,
}

impl<S, G> PrivateKeyGenerator<S> for MssPrivateKeyGenerator<S, G>
where
    S: Sponge<Error = String> + Default,
    G: Default + PrivateKeyGenerator<S, Error = String>,
    <G as PrivateKeyGenerator<S>>::PrivateKey: PrivateKey + Clone,
    <<G as PrivateKeyGenerator<S>>::PrivateKey as PrivateKey>::PublicKey: PublicKey,
{
    type PrivateKey = MssPrivateKey<S, G>;
    type Error = String;

    /// Generate Private Key
    ///
    /// Arguments:
    ///     `seed`: Secret Key
    ///     `nonce`: Nonce
    ///     `subtree_height`: SubTree Height
    ///     `level`: level count
    ///
    fn generate(&self, seed: &[Trit], nonce: &[Trit]) -> Result<Self::PrivateKey, String> {
        let mut spongos = S::default();
        let height = self.height * self.level;
        let mut i_mt = InternalPrivateKey::new(&seed, &nonce, self.height, self.level);

        let mut stk: Vec<TreeStackItem> = Vec::with_capacity(height + 1);
        let sigs: usize = 1 << height;

        i_mt.alloc_exist();
        let wots_kgen = G::default();

        for it in 0..sigs {
            let trits = (it as i64).trits_with_length(6);
            let wots_priv_key = wots_kgen
                .generate(&seed, &[&nonce[..], &trits[..]].concat())
                .unwrap();
            let pk = wots_priv_key.generate_public_key();

            stk.push(TreeStackItem::new(0, it, pk.to_bytes()));
            i_mt.store_exist(&stk[stk.len() - 1]);

            loop {
                if stk.len() < 2 {
                    break;
                }
                if stk[stk.len() - 1].level != stk[stk.len() - 2].level {
                    break;
                }

                let item1 = stk.pop().unwrap();
                let item2 = stk.pop().unwrap();

                let l = item1.level + 1;
                let p = item1.pos / 2;

                let hash = spongos
                    .hash(&[&item2.item[..], &item1.item[..]].concat(), HASH_LEN)
                    .unwrap();

                stk.push(TreeStackItem::new(l, p, &hash));
                i_mt.store_exist(&stk[stk.len() - 1]);
            }
        }

        i_mt.alloc_desired();
        Ok(MssPrivateKey::new(i_mt, stk[stk.len() - 1].item.clone()))
    }
}

impl<S, G> MssPrivateKeyGenerator<S, G>
where
    S: Sponge<Error = String> + Default,
    G: Default + PrivateKeyGenerator<S, Error = String>,
    <G as PrivateKeyGenerator<S>>::PrivateKey: PrivateKey + Clone,
    <<G as PrivateKeyGenerator<S>>::PrivateKey as PrivateKey>::PublicKey: PublicKey,
{
    ///
    /// Create MSS Private Key Generator
    ///
    /// The depth of this tree is (height x level) and the total messages that you can sign are _2 ^ (height x level)_
    ///
    /// Arguments
    ///     height Height of subtrees
    ///     level Level of Merkle Tree
    ///
    pub fn new(height: usize, level: usize) -> Self {
        MssPrivateKeyGenerator {
            height,
            level,
            _sponge: PhantomData,
            _generator: PhantomData,
        }
    }
    ///
    /// Create MSS Private Key Generator from Depth
    ///
    /// Arguments
    ///     depth Mss depth
    ///
    pub fn from_depth(depth: usize) -> Self {
        let h = (depth as f32).log2().floor();
        let level = (depth as f32 / h).round();
        Self::new(h as usize, level as usize)
    }
}

impl<S, G> PrivateKey for MssPrivateKey<S, G>
where
    S: Sponge<Error = String> + Default,
    G: Default + PrivateKeyGenerator<S, Error = String>,
    <G as PrivateKeyGenerator<S>>::PrivateKey: PrivateKey + Clone,
    <<G as PrivateKeyGenerator<S>>::PrivateKey as PrivateKey>::PublicKey: PublicKey,
    <<G as PrivateKeyGenerator<S>>::PrivateKey as PrivateKey>::Signature: Signature,
{
    type PublicKey = MssPublicKey<S>;
    type Signature = MssSignature<S>;
    ///
    /// Generate Public Key
    ///
    fn generate_public_key(&self) -> Self::PublicKey {
        MssPublicKey {
            state: self.root.to_vec(),
            h: self.i_mt.borrow().height * self.i_mt.borrow().level,
            _sponge: PhantomData,
        }
    }

    fn sign(&self, message: &[i8]) -> Result<Self::Signature, String> {
        let mut i_mt = self.i_mt.borrow_mut();
        let t_height = i_mt.height * i_mt.level;
        let mut signature_state = vec![0_i8; 18 + 13122 + HASH_LEN * t_height];

        if !i_mt.check_privkey() {
            return Err("Secret Key error".to_owned());
        }

        let wots_kgen = G::default();
        signature_state[0..18].copy_from_slice(&i_mt.skn());

        let trits = (i_mt.sigs_used as i64).trits_with_length(6);
        let wots_priv_key = wots_kgen
            .generate(&i_mt.seed, &[&i_mt.nonce[..], &trits[..]].concat())
            .unwrap();
        let signature = wots_priv_key.sign(message).unwrap();

        signature_state[18..(18 + 13122)].copy_from_slice(&signature.to_bytes());
        signature_state[(18 + 13122)..].copy_from_slice(&i_mt.apath()[..]);

        i_mt.update_private_key();

        Ok(MssSignature {
            state: signature_state,
            _sponge: PhantomData,
        })
    }
}

impl<S> PublicKey for MssPublicKey<S>
where
    S: Sponge<Error = String> + Default,
{
    type Signature = MssSignature<S>;
    ///
    /// Verify
    ///
    fn verify(&self, message: &[i8], signature: &Self::Signature) -> bool {
        let pk = signature.recover_public_key(message);
        self.state
            .iter()
            .zip(pk.to_bytes().iter())
            .all(|(st, pk)| st == pk)
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
        MssPublicKey {
            state: bytes.to_vec(),
            h: 0,
            _sponge: PhantomData,
        }
    }
}

impl<S> Default for MssPublicKey<S>
where
    S: Sponge<Error = String> + Default,
{
    fn default() -> Self {
        MssPublicKey {
            state: vec![0i8; 1],
            h: 0,
            _sponge: PhantomData,
        }
    }
}

impl<S> Signature for MssSignature<S>
where
    S: Sponge<Error = String> + Default,
{
    /// PublicKey Type
    type PublicKey = MssPublicKey<S>;

    ///
    /// Recover Public Key
    ///
    fn recover_public_key(&self, message: &[i8]) -> Self::PublicKey {
        if self.state.len() < 18 + 13122 {
            return Self::PublicKey::default();
        }
        let d = trist_to_value(&self.state[..4].to_vec());
        let mut skn = trist_to_value(&self.state[4..18].to_vec());

        if (d < 0)
            || (skn < 0)
            || (skn >= (1 << d))
            || (self.state.len() != (18 + 13122 + 243 * d) as usize)
        {
            return Self::PublicKey::default();
        }

        let wots: WotsSignature<S> = WotsSignature::form_bytes(&self.state[18..(18 + 13122)]);
        let mut t = wots.recover_public_key(message).to_bytes().to_vec();
        let mut p = self.state[(18 + 13122)..].to_vec();
        let mut spongos = S::default();

        for _ in 0..d {
            if skn % 2 == 0 {
                t = [&t, &p[..HASH_LEN]].concat();
            } else {
                t = [&p[..HASH_LEN], &t].concat();
            }
            t = spongos.hash(&t, HASH_LEN).unwrap();
            p = p[HASH_LEN..].to_vec();
            skn = ((skn / 2) as f32).floor() as i64;
        }

        return MssPublicKey {
            state: t,
            h: d as usize,
            _sponge: PhantomData,
        };
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
        MssSignature {
            state: bytes.to_vec(),
            _sponge: PhantomData,
        }
    }
}

impl<S, G> MssPrivateKey<S, G>
where
    S: Sponge<Error = String> + Default,
    G: Default + PrivateKeyGenerator<S, Error = String>,
    <G as PrivateKeyGenerator<S>>::PrivateKey: PrivateKey + Clone,
    <<G as PrivateKeyGenerator<S>>::PrivateKey as PrivateKey>::PublicKey: PublicKey,
{
    ///
    /// Initiate Mss PrivateKey
    ///
    pub fn new(mt: InternalPrivateKey<S, G>, root: Vec<Trit>) -> Self {
        MssPrivateKey {
            i_mt: RefCell::new(mt),
            root: root,
            _sponge: PhantomData,
            _gen: PhantomData,
        }
    }
}

#[cfg(test)]
mod should {
    use super::*;
    use crate::{spongos::MamSpongos, wots::WotsPrivateKeyGenerator};
    use iota_conversion::Trinary;

    const SEED: &str =
        "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN";

    #[test]
    fn generate_private_key() {
        let seed_trits = SEED.trits();
        let nonce = [0; 18];
        let mss_kg: MssPrivateKeyGenerator<MamSpongos, WotsPrivateKeyGenerator<MamSpongos>> =
            MssPrivateKeyGenerator::new(2, 2);
        let private_key = mss_kg.generate(&seed_trits, &nonce).unwrap();

        let pk = private_key.generate_public_key();

        assert!(pk.to_bytes().len() == 243);
    }

    #[test]
    fn sign_message() {
        let seed_trits = SEED.trits();
        let message = SEED.trits();
        let nonce = [0; 18];
        let mss_kg: MssPrivateKeyGenerator<MamSpongos, WotsPrivateKeyGenerator<MamSpongos>> =
            MssPrivateKeyGenerator::new(2, 2);
        let private_key = mss_kg.generate(&seed_trits, &nonce).unwrap();
        let signature = private_key.sign(&message).unwrap();

        assert_eq!(signature.to_bytes().len(), 18 + 13122 + 243 * 4);
    }

    #[test]
    fn generate_private_key_from_depth() {
        let seed_trits = SEED.trits();
        let message = SEED.trits();
        let nonce = [0; 18];
        let mss_kg: MssPrivateKeyGenerator<MamSpongos, WotsPrivateKeyGenerator<MamSpongos>> =
            MssPrivateKeyGenerator::from_depth(4);
        let private_key = mss_kg.generate(&seed_trits, &nonce).unwrap();
        let signature = private_key.sign(&message).unwrap();
        assert_eq!(signature.to_bytes().len(), 18 + 13122 + 243 * 4);
    }

    #[test]
    fn verify_message() {
        let seed_trits = SEED.trits();
        let message = SEED.trits();
        let nonce = [0; 18];
        let depth = 4;
        let mss_kg: MssPrivateKeyGenerator<MamSpongos, WotsPrivateKeyGenerator<MamSpongos>> =
            MssPrivateKeyGenerator::new(2, 2);
        let private_key = mss_kg.generate(&seed_trits, &nonce).unwrap();
        let sg = (1 << depth) - 1;

        let public_key = private_key.generate_public_key();

        for _ in 0..sg {
            let sig3 = private_key.sign(&message).unwrap();
            assert_eq!(public_key.verify(&message, &sig3), true);
        }
    }
}
