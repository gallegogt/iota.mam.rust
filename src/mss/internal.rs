//!
//! Merkle Signature Scheme
//!
//! Based on FMTSEQ => https://github.com/exaexa/codecrypt/blob/master/src/fmtseq.h
//!
use crate::definitions::{
    ss::{PrivateKey, PrivateKeyGenerator, PublicKey},
    Sponge,
};
use iota_conversion::{Trinary, Trit};
use std::marker::PhantomData;

///
/// HASH LENGTH
///
const HASH_LEN: usize = 243;

///
///
/// Internal Private Key
///
#[derive(Clone)]
pub struct InternalPrivateKey<S, G> {
    /// Nonce
    pub seed: Vec<Trit>,
    /// Nonce
    pub nonce: Vec<Trit>,
    /// Level count
    pub level: usize,
    /// SubTree Height
    pub height: usize,
    /// Sigs used
    pub sigs_used: usize,
    /// Exists Subtrees
    exist: Vec<Vec<Trit>>,
    /// Desired Subtrees
    desired: Vec<Vec<Trit>>,
    /// Desired Stack
    desired_stack: Vec<Vec<TreeStackItem>>,
    /// Desired progress
    desired_progress: Vec<usize>,
    /// Market Data
    _sponge: PhantomData<S>,
    _gen: PhantomData<G>,
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

impl<S, G> InternalPrivateKey<S, G>
where
    S: Sponge<Error = String> + Default,
    G: Default + PrivateKeyGenerator<S, Error = String>,
    <G as PrivateKeyGenerator<S>>::PrivateKey: PrivateKey + Clone,
    <<G as PrivateKeyGenerator<S>>::PrivateKey as PrivateKey>::PublicKey: PublicKey,
{
    ///
    /// Initiate Mss PrivateKey
    ///
    pub fn new(seed: &[Trit], nonce: &[Trit], height: usize, level: usize) -> Self {
        InternalPrivateKey {
            seed: seed.to_vec(),
            nonce: nonce.to_vec(),
            level: level,
            height: height,
            sigs_used: 0,
            exist: vec![Vec::new(); level],
            desired: vec![Vec::new(); level - 1],
            desired_stack: vec![Vec::new(); level - 1],
            desired_progress: vec![0; level - 1],
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
            let w_kg = G::default();
            let wots_priv_key = w_kg
                .generate(&self.seed, &[&self.nonce[..], &trits[..]].concat())
                .unwrap();
            let pk = wots_priv_key.generate_public_key();

            let item = TreeStackItem::new(0, self.desired_progress[it], pk.to_bytes());
            self.desired_stack[it].push(item.clone());

            self.store_desired(&item, it);

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
            if ((subtree_changes >> (self.height * (1 + idx))) & one_subtree_mask) == 0 {
                continue;
            }

            // move desired to exist
            self.exist[idx].copy_from_slice(&self.desired[idx]);
            self.desired_progress[idx] = 0;
            self.desired_stack[idx].clear();

            // if there aren't more desired subtrees on this level,
            // strip it off.
            let next_subtree_start =
                (1 + (next_sigs_used >> ((1 + idx) * self.height))) << ((1 + idx) * self.height);
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
        let t_height = self.height * self.level;
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
