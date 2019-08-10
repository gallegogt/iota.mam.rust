//! Convertions
//!
use std::f64;

/// The minimum value a trit can have
pub const MIN_TRIT_VALUE: i8 = -1;
/// The maximum value a trit can have
pub const MAX_TRIT_VALUE: i8 = 1;
/// Base
pub const RADIX: i8 = 3;

/// Trit
type Trit = i8;

///
/// Converts an integer value to trits
///
pub fn trits_from_value(value: i64) -> Vec<Trit> {
    let fvalue = value as f64 * 1.0;
    let log = f64::from(2_f64 * (1_f64.max(fvalue.abs()))).log(f64::consts::E);
    let capacity = 1_f64 + (log / 3_f64.log(f64::consts::E)).floor();
    let mut trits: Vec<Trit> = Vec::with_capacity(capacity as usize);
    trits.resize(capacity as usize, 0);

    let mut absolute_value = fvalue.abs();
    let mut it = 0;
    let radix = RADIX as f64;

    while absolute_value > 0.0 {
        let mut remainder = absolute_value % radix;
        absolute_value = f64::from(absolute_value / radix).floor();

        if remainder > (MAX_TRIT_VALUE as f64) {
            remainder = MIN_TRIT_VALUE as f64;
            absolute_value += 1_f64;
        }
        trits[it] = remainder as i8;
        it += 1;
    }
    if value < 0 {
        for idx in 0..trits.len() {
            trits[idx] = trits[idx] * -1;
        }
    }
    trits
}
