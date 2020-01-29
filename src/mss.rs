//!
//! Merkle Signature Scheme
//!
use crate::{
    definitions::{
        ss::{PrivateKey, PublicKey, Signature},
        Sponge,
    },
    wots::{WotsPrivateKeyGenerator, WotsSignature},
};
use iota_conversion::{long_value as trist_to_value, Trinary, Trit};
use std::marker::PhantomData;

///
/// HASH LENGTH
///
const HASH_LEN: usize = 243;

/// MSS PrivateKey Generator
///
#[derive(Debug)]
pub struct MssV1PrivateKeyGenerator<S, G> {
    _market: PhantomData<S>,
    generator: G,
}

///
///
/// MSS Private Key
///
#[derive(Clone)]
pub struct MssPrivateKey<S, G> {
    /// Nonce
    seed: Vec<Trit>,
    /// Nonce
    nonce: Vec<Trit>,
    /// Level count
    level: usize,
    /// SubTree Height
    height: usize,
    /// Sigs used
    sigs_used: usize,
    /// Exists Subtrees
    exist: Vec<Vec<Trit>>,
    /// Desired Subtrees
    desired: Vec<Vec<Trit>>,
    /// Desired Stack
    desired_stack: Vec<Vec<TreeStackItem>>,
    /// Desired progress
    desired_progress: Vec<usize>,
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

///
/// Tree Stack Item
///
#[derive(Debug, Clone)]
pub struct TreeStackItem {
    /// Level
    pub level: usize,
    /// Pos
    pub pos: usize,
    /// Hash
    pub item: Vec<Trit>,
}

impl Default for TreeStackItem {
    fn default() -> Self {
        TreeStackItem {
            level: 0,
            pos: 0,
            item: Vec::new(),
        }
    }
}

impl TreeStackItem {
    ///
    /// Create new TreeStackItem
    ///
    pub fn new(level: usize, pos: usize, item: &[Trit]) -> Self {
        TreeStackItem {
            level: level,
            pos: pos,
            item: item.to_vec(),
        }
    }
}

///
/// Trait for Mss Private Key Generator
///
pub trait MssPrivateKeyGenerator<S, G> {
    /// Private Key
    type PrivateKey;

    /// Generate Private Key
    ///
    /// Arguments:
    ///     `seed`: Secret Key
    ///     `nonce`: Nonce
    ///     `height`: subtree height
    ///     `level`: level
    ///
    fn generate(
        seed: &[Trit],
        nonce: &[Trit],
        height: usize,
        level: usize,
    ) -> Result<Self::PrivateKey, String>;
}

impl<S, G> MssPrivateKeyGenerator<S, G> for MssV1PrivateKeyGenerator<S, G>
where
    S: Sponge<Error = String> + Default,
    G: WotsPrivateKeyGenerator<S>,
    <G as WotsPrivateKeyGenerator<S>>::PrivateKey: PrivateKey + Clone,
    <<G as WotsPrivateKeyGenerator<S>>::PrivateKey as PrivateKey>::PublicKey: PublicKey,
{
    type PrivateKey = MssPrivateKey<S, G>;

    /// Generate Private Key
    ///
    /// Arguments:
    ///     `seed`: Secret Key
    ///     `nonce`: Nonce
    ///     `subtree_height`: SubTree Height
    ///     `level`: level count
    ///
    fn generate(
        seed: &[Trit],
        nonce: &[Trit],
        subtree_height: usize,
        level: usize,
    ) -> Result<Self::PrivateKey, String> {
        let mut spongos = S::default();
        let height = subtree_height * level;
        let mut mss_priv_key = MssPrivateKey::new(&seed, &nonce, subtree_height, level);

        let mut stk: Vec<TreeStackItem> = Vec::with_capacity(height + 1);
        let sigs: usize = 1 << height ;

        mss_priv_key.alloc_exist();

        for it in 0..sigs {
            let trits = (it as i64).trits_with_length(6);
            let wots_priv_key = G::generate(&seed, &[&nonce[..], &trits[..]].concat()).unwrap();
            let pk = wots_priv_key.generate_public_key();

            stk.push(TreeStackItem::new(0, it, pk.to_bytes()));
            mss_priv_key.store_exist(&stk[stk.len() - 1]);

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

                stk.push(TreeStackItem {
                    pos: p,
                    level: l,
                    item: hash,
                });
                mss_priv_key.store_exist(&stk[stk.len() - 1]);
            }
        }

        mss_priv_key.alloc_desired();
        mss_priv_key.root[..].copy_from_slice(&stk[stk.len() - 1].item);
        Ok(mss_priv_key)
    }
}

impl<S, G> PrivateKey for MssPrivateKey<S, G>
where
    S: Sponge<Error = String> + Default,
    G: WotsPrivateKeyGenerator<S>,
    <G as WotsPrivateKeyGenerator<S>>::PrivateKey: PrivateKey + Clone,
    <<G as WotsPrivateKeyGenerator<S>>::PrivateKey as PrivateKey>::PublicKey: PublicKey,
    <<G as WotsPrivateKeyGenerator<S>>::PrivateKey as PrivateKey>::Signature: Signature,
{
    type PublicKey = MssPublicKey<S>;
    type Signature = MssSignature<S>;
    ///
    /// Generate Public Key
    ///
    fn generate_public_key(&self) -> Self::PublicKey {
        MssPublicKey {
            state: self.root.to_vec(),
            h: self.height * self.level,
            _sponge: PhantomData,
        }
    }
    ///
    /// Sign
    ///
    fn sign_mut(&mut self, message: &[i8]) -> Result<Self::Signature, String> {
        let t_height = self.height * self.level;
        let mut signature_state = vec![0_i8; 18 + 13122 + HASH_LEN * t_height];

        if !self.check_privkey() {
            return Err("Secret Key error".to_owned());
        }

        signature_state[0..18].copy_from_slice(&self.skn());

        let trits = (self.sigs_used as i64).trits_with_length(6);
        let wots_priv_key =
            G::generate(&self.seed, &[&self.nonce[..], &trits[..]].concat()).unwrap();
        let signature = wots_priv_key.sign(message).unwrap();

        signature_state[18..(18 + 13122)].copy_from_slice(&signature.to_bytes());
        signature_state[(18 + 13122)..].copy_from_slice(&self.apath()[..]);

        self.update_private_key();

        Ok(MssSignature {
            state: signature_state,
            _sponge: PhantomData,
        })
    }

    fn sign(&self, _message: &[i8]) -> Result<Self::Signature, String> {
        unimplemented!()
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

        if d < 0 || skn < 0 || skn >= 2 ^ d || self.state.len() != (18 + 13122 + 243 * d) as usize {
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
    G: WotsPrivateKeyGenerator<S>,
    <G as WotsPrivateKeyGenerator<S>>::PrivateKey: PrivateKey + Clone,
    <<G as WotsPrivateKeyGenerator<S>>::PrivateKey as PrivateKey>::PublicKey: PublicKey,
{
    ///
    /// Initiate Mss PrivateKey
    ///
    pub fn new(seed: &[Trit], nonce: &[Trit], height: usize, level: usize) -> Self {
        MssPrivateKey {
            seed: seed.to_vec(),
            nonce: nonce.to_vec(),
            level: level,
            height: height,
            sigs_used: 0,
            exist: vec![Vec::new(); level],
            desired: vec![Vec::new(); level - 1],
            desired_stack: vec![Vec::new(); level - 1],
            desired_progress: vec![0; level - 1],
            root: vec![0_i8; HASH_LEN],
            _sponge: PhantomData,
            _gen: PhantomData,
        }
    }

    ///
    /// Alloc exist tree
    ///
    pub(crate) fn alloc_exist(&mut self) {
        let ts = (1 << (self.height + 1)) - 2;
        for it in 0..self.level {
            self.exist[it] = vec![0i8; ts * HASH_LEN];
        }
    }
    ///
    /// Alloc Desired
    ///
    pub(crate) fn alloc_desired(&mut self) {
        for it in 0..self.level - 1 {
            let ts = (1 << (self.height + 1)) - 2;
            self.desired[it] = vec![0i8; ts * HASH_LEN];
        }
    }
    ///
    /// Store Exits
    ///
    pub(crate) fn store_exist(&mut self, item: &TreeStackItem) {
        let level = item.level / self.height;
        if level >= self.level {
            // top node
            return;
        }
        let sublevel = self.height - (item.level % self.height);
        let sublev_width = 1 << sublevel;
        if item.pos >= sublev_width {
            // too far right
            return;
        }
        let pos = item.pos + sublev_width - 2;
        self.exist[level][(pos * HASH_LEN)..((pos + 1) * HASH_LEN)].copy_from_slice(&item.item);
    }

    ///
    /// Store Desired
    ///
    pub(crate) fn store_desired(&mut self, item: &TreeStackItem, did: usize) {
        if (item.level / self.height) != did {
            // too below or above
            return;
        }
        let depth = self.height - (item.level % self.height);
        if item.pos >= (1 << depth) {
            return;
        }
        let pos = item.pos + (1 << depth) - 2;
        self.desired[did][(pos * HASH_LEN)..((pos + 1) * HASH_LEN)].copy_from_slice(&item.item);
    }

    ///
    /// Check Private Key
    ///
    pub(crate) fn check_privkey(&self) -> bool {
        let ts: usize = (1 << (self.height + 1)) - 2;
        // exist tree count is always L
        if self.exist.len() != self.level {
            return false;
        }

        for it in 0..self.exist.len() {
            if self.exist[it].len() != ts * HASH_LEN {
                return false;
            }
        }

        // check desired stuff
        if (self.desired_stack.len() < self.desired.len())
            || (self.desired_progress.len() < self.desired.len())
        {
            return false;
        }

        for it in 0..self.desired.len() {
            if self.desired[it].len() != ts * HASH_LEN {
                return false;
            }
        }

        return true;
    }

    pub(crate) fn update_private_key(&mut self) {

        for it in 0..self.desired.len() {
            let d_h = (it + 1) * self.height;
            let d_leaves = 1 << d_h;
            if self.desired_progress[it] >= d_leaves {
                continue; //already done
            }
            // create the leaf
            let d_startpos = (1 + (self.sigs_used >> d_h)) << d_h;
            let leaf_id = d_startpos + self.desired_progress[it];

            let trits = (leaf_id as i64).trits_with_length(6);
            let wots_priv_key =
                G::generate(&self.seed, &[&self.nonce[..], &trits[..]].concat()).unwrap();
            let pk = wots_priv_key.generate_public_key();

            let item = TreeStackItem::new(0, self.desired_progress[it], pk.to_bytes());
            self.store_desired(&item, it);

            self.desired_stack[it].push(item.clone());

            self.desired_progress[it] += 1;
            let mut spongos = S::default();

            // stack squashing
            loop {
                if self.desired_stack[it].len() < 2 {
                    break;
                }
                if self.desired_stack[it][self.desired_stack[it].len() - 1].level
                    != self.desired_stack[it][self.desired_stack[it].len() - 2].level
                {
                    break;
                }

                let item1 = self.desired_stack[it].pop().unwrap();
                let item2 = self.desired_stack[it].pop().unwrap();
                let l = item1.level + 1;
                let p = item1.pos / 2;

                let hash = spongos
                    .hash(&[&item2.item[..], &item1.item[..]].concat(), HASH_LEN)
                    .unwrap();

                let s_item = TreeStackItem::new(l, p, &hash);
                self.desired_stack[it].push(s_item.clone());
                self.store_desired(&s_item, it);
            }
        }

        let next_sigs_used = self.sigs_used + 1;
        let subtree_changes = self.sigs_used ^ next_sigs_used;
        let one_subtree_mask = (1 << self.height) - 1;

        // go from the topmost subtree.
        for it in 0..self.level {
            let idx = self.level - it - 1;
            // ignore unused top levels
            if idx > self.desired.len() {
                continue;
            }
            // if nothing changed, do nothing
            // if (! ( (subtree_changes >> (priv.h * (1 + idx)))
		    //     & one_subtree_mask)) continue;
            if ((subtree_changes >> (self.height * (1 + idx))) & one_subtree_mask) == 0 {
                continue;
            }

            // move desired to exist
            self.exist[idx] = self.desired[idx].clone();
            self.desired_progress[idx] = 0;
            self.desired_stack[idx].clear();
            // if there aren't more desired subtrees on this level,
            // strip it off.
            let next_subtree_start = (1 + (next_sigs_used >> ((1 + idx) * self.height))) << ((1 + idx) * self.height);
            if next_subtree_start >= (1 << (self.height * self.level)) {
                self.desired.resize_with(idx, Default::default);
                self.desired_stack.resize_with(idx, Default::default);
                self.desired_progress.resize_with(idx, Default::default);
            }
        }
        self.sigs_used = next_sigs_used;
    }

    ///
    /// Retrieve the Authentication Path
    ///
    pub fn apath(&self) -> Vec<Trit> {
        let t_height = self.height * self.level;
        let mut pos = self.sigs_used;
        let mut p = vec![0i8; t_height * HASH_LEN];

        for it in 0..t_height {
            let exid = it / self.height;
            let exlev = self.height - (it % self.height);
            // flip the last bit of pos so it gets the neighbor
            let expos = (pos ^ 1) % (1 << exlev);
            let ep = expos + (1 << exlev) - 2;

            p[(it * HASH_LEN)..((it + 1) * HASH_LEN)]
                .copy_from_slice(&self.exist[exid][(ep * HASH_LEN)..((ep + 1) * HASH_LEN)]);
            pos >>= 1
        }
        p
    }

    ///
    /// SKN
    ///
    pub fn skn(&self) -> [i8; 18] {
        let mut encoded_skn = [0i8; 18];
        let t_height =  self.height * self.level;
        let t_depth = (t_height as i64).trits_with_length(4);
        let t_skn = (self.sigs_used as i64).trits_with_length(14);

        encoded_skn[..4].copy_from_slice(&t_depth[..]);
        encoded_skn[4..].copy_from_slice(&t_skn[..]);
        encoded_skn
    }

    ///
    /// Sigs Remaning
    ///
    pub fn sigs_remaining(&self) -> usize {
        (1 << (self.height * self.level)) - self.sigs_used
    }
}

#[cfg(test)]
mod should {
    use super::*;
    use crate::{spongos::MamSpongos, wots::WotsV1PrivateKeyGenerator};
    use iota_conversion::Trinary;

    const SEED: &str =
        "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN";

    #[test]
    fn generate_private_key() {
        let seed_trits = SEED.trits();
        let nonce = [0; 18];
        let private_key = MssV1PrivateKeyGenerator::<
            MamSpongos,
            WotsV1PrivateKeyGenerator<MamSpongos>,
        >::generate(&seed_trits, &nonce, 2, 2)
        .unwrap();

        let pk = private_key.generate_public_key();

        assert!(pk.to_bytes().len() == 243);
    }

    #[test]
    fn sign_message() {
        let seed_trits = SEED.trits();
        let message = SEED.trits();
        let nonce = [0; 18];
        let mut private_key = MssV1PrivateKeyGenerator::<
            MamSpongos,
            WotsV1PrivateKeyGenerator<MamSpongos>,
        >::generate(&seed_trits, &nonce, 2, 2)
        .unwrap();
        let signature = private_key.sign_mut(&message).unwrap();

        assert_eq!(signature.to_bytes().len(), 18 + 13122 + 243 * 4);
    }

    #[test]
    fn verify_message() {
        let seed_trits = SEED.trits();
        let message = SEED.trits();
        let nonce = [0; 18];
        let depth = 4;
        let mut private_key = MssV1PrivateKeyGenerator::<
            MamSpongos,
            WotsV1PrivateKeyGenerator<MamSpongos>,
        >::generate(&seed_trits, &nonce, 2, 2)
        .unwrap();
        let sg = (1 << depth) - 1;

        let public_key = private_key.generate_public_key();

        for k in 0..sg {
            println!("K --> {}/{}", k, sg);
            let sig3 = private_key.sign_mut(&message).unwrap();
            println!("R --> {}/{}", private_key.sigs_remaining(), sg);
            assert_eq!(public_key.verify(&message, &sig3), true);
        }
    }
}
