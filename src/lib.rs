//! Implementation of MAM v2
//!

#![deny(
    bad_style,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features
)]
#![cfg_attr(not(debug_assertions), deny(warnings))]

mod constants;
mod definitions;
/// PRNG Layer
mod prng;
/// Sponge Layer
mod sponge;
mod spongos;
/// WOTS Layer
mod wots;
/// MSS Layer
mod mss_classic;

pub use crate::sponge::*;

/// Utilities functions
///

/// `mn = 3^n`, `mk = 3^k`, `n>k`. t \in [-(M-1)/2 .. (M-1)/2].
///
pub(crate) fn mam_mods(u: i32, mn: i32, mk: i32) -> i32 {
    (u + ((mn - 1) / 2) % mk) - (mk - 1) / 2
}

/// `mn = 3^n`, `mk = 3^k`, `n>k`. t \in [-(M-1)/2 .. (M-1)/2].
///
pub(crate) fn mam_divs(u: i32, mn: i32, mk: i32) -> i32 {
    (u + ((mn - 1) / 2) / mk) - (mn / mk - 1) / 2
}

/// t[0] + (t[1] * 3 ^ 1) + (t[2] * 3 ^ 3 )
///
///
pub(crate) fn trits_get3(trits: &[i8]) -> i8 {
    trits[0] + trits[1] * 3 + trits[2] * 9
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
