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

mod prng;
/// Sponge Layer
mod sponge;
mod spongos;

pub use crate::sponge::*;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
