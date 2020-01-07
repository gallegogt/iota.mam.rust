//! Constants and utilities functions
//!
/// The minimum value a trit can have
pub const MIN_TRIT_VALUE: i8 = -1;
/// The maximum value a trit can have
pub const MAX_TRIT_VALUE: i8 = 1;
/// Base
pub const RADIX: i8 = 3;
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
pub(crate) fn trits_get3(trits: &[i8]) -> i8 {
    trits[0] + trits[1] * 3 + trits[2] * 9
}

///
/// Put 3 Trits
///
pub(crate) fn trits_put3(t: i8) -> [Trit; 3] {
    let mut rst = [0i8; 3];
    let mut tx: i32 = t as i32;

    rst[0] = mam_mods(tx, 3 * 3 * 3, 3) as i8;
    tx = mam_divs(tx, 3 * 3 * 3, 3);
    rst[1] = mam_mods(tx, 3 * 3, 3) as i8;
    tx = mam_divs(tx, 3 * 3, 3);
    rst[2] = tx as i8;

    rst
}

///
/// Put 9 Trits
///
pub(crate) fn trits_put9(t: i16) -> [Trit; 9] {
    let mut rst = [0i8; 9];
    let mut tx: i32 = t as i32;

    let t0 = mam_mods(tx, 27 * 27 * 27, 27) as i8;
    tx = mam_divs(tx, 27 * 27 * 27, 27);
    let t1 = mam_mods(tx, 27 * 27, 27) as i8;
    tx = mam_divs(tx, 27 * 27, 27);
    let t2 = tx as i8;

    rst[0..3].copy_from_slice(&trits_put3(t0));
    rst[3..6].copy_from_slice(&trits_put3(t1));
    rst[6..9].copy_from_slice(&trits_put3(t2));

    rst
}

///
/// Put 9 Trits
///
pub(crate) fn trits_put18(t: i32) -> [Trit; 18] {
    let mut rst = [0i8; 18];
    let mut tx: i32 = t;

    let t0 = mam_mods(tx, 19683 * 19683, 19683) as i16;
    tx = mam_divs(tx, 19683 * 19683, 19683);
    let t1 = tx as i16;

    rst[0..9].copy_from_slice(&trits_put9(t0));
    rst[9..18].copy_from_slice(&trits_put9(t1));

    rst
}
