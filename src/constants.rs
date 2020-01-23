//! Constants and utilities functions
//!
use iota_conversion::Trit;

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
pub(crate) fn trits_get3(trits: &[i8]) -> Trit {
    trits[0] + trits[1] * 3 + trits[2] * 9
}

