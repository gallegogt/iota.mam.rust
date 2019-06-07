use crate::constants::{MAX_TRIT_VALUE, MIN_TRIT_VALUE, RADIX, TRYTES_TRITS_LUT, TRYTE_ALPHABET};
use crate::converter::{ConverterErrorKind, ConverterResult};
use crate::types::Trit;
use std::f64;

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

///
/// Converts trits into an integer value
///
pub fn trits_to_value(value: &[i8]) -> i64 {
    let mut ret_value = 0;

    for it in value.iter().rev() {
        ret_value = ret_value * 3 + i64::from(*it)
    }

    ret_value
}

///
/// Convert Trytes to Trits
///
pub fn trytes_to_trits<'a>(trytes: &'a str) -> ConverterResult<Vec<Trit>> {
    let mut dest = Vec::with_capacity(trytes.len() * 3);
    dest.resize(trytes.len() * 3, 0);
    let alphabet = &TRYTE_ALPHABET;
    let mut it = 0;
    for ch in trytes.chars() {
        if let Some(index) = alphabet.iter().position(|c| c == &ch) {
            dest[it * 3] = TRYTES_TRITS_LUT[index][0];
            dest[it * 3 + 1] = TRYTES_TRITS_LUT[index][1];
            dest[it * 3 + 2] = TRYTES_TRITS_LUT[index][2];
        } else {
            return Err(ConverterErrorKind::InvalidTrytes);
        }
        it += 1;
    }

    Ok(dest)
}

///
/// Convert Trits to Trytes
///
pub fn trits_to_trytes<'a>(trits_value: &[i8]) -> ConverterResult<String> {
    if trits_value.len() % 3 != 0 {
        return Err(ConverterErrorKind::InvalidTrits);
    }
    let mut result = String::from("");

    for chunk in trits_value.chunks(3) {
        for idx in 0..TRYTE_ALPHABET.len() {
            if chunk == TRYTES_TRITS_LUT[idx] {
                result.push(TRYTE_ALPHABET[idx]);
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_trits_from_value() {
        let simple_value = 12;
        let v = trits_from_value(simple_value);
        let v3 = trits_from_value(9223372036854775295);

        assert_eq!(v, vec![0, 1, 1]);
        assert_eq!(
            v3,
            vec![
                1, 0, 0, 0, -1, 1, 1, 0, 1, 0, -1, 0, -1, 0, 1, 0, 1, 0, -1, 1, 1, -1, -1, 1, 0, 1,
                -1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, -1, 1, -1, 1
            ]
        );
    }

    #[test]
    fn check_trits_to_value() {
        let trits = vec![
            -1, 0, 0, 0, -1, 1, 1, 0, 1, 0, -1, 0, -1, 0, 1, 0, 1, 0, -1, 1, 1, -1, -1, 1, 0, 1,
            -1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, -1, 1, -1, 1,
        ];
        let v = trits_to_value(&trits);
        assert_eq!(9223372036854775295, v);
    }

    #[test]
    fn check_convert_trytes_to_trits() {
        let trytes = "CAFUCAAHVNSRK9XJTHWZBFRPRIR9";
        let result = vec![
            0, 1, 0, 1, 0, 0, 0, -1, 1, 0, 1, -1, 0, 1, 0, 1, 0, 0, 1, 0, 0, -1, 0, 1, 1, 1, -1,
            -1, -1, -1, 1, 0, -1, 0, 0, -1, -1, 1, 1, 0, 0, 0, 0, -1, 0, 1, 0, 1, -1, 1, -1, -1, 0,
            1, -1, -1, 0, -1, 0, 0, -1, 1, 0, 0, -1, 1, 0, 0, -1, 1, -1, -1, 0, 0, -1, 0, 0, 1, 0,
            0, -1, 0, 0, 0,
        ];
        let output = trytes_to_trits(trytes).unwrap();
        assert_eq!(output, result);
    }

    #[test]
    fn check_convert_trits_to_trytes() {
        let trytes = "CAFUCAAHVNSRK9XJTHWZBFRPRIR9".to_owned();
        let result = vec![
            0, 1, 0, 1, 0, 0, 0, -1, 1, 0, 1, -1, 0, 1, 0, 1, 0, 0, 1, 0, 0, -1, 0, 1, 1, 1, -1,
            -1, -1, -1, 1, 0, -1, 0, 0, -1, -1, 1, 1, 0, 0, 0, 0, -1, 0, 1, 0, 1, -1, 1, -1, -1, 0,
            1, -1, -1, 0, -1, 0, 0, -1, 1, 0, 0, -1, 1, 0, 0, -1, 1, -1, -1, 0, 0, -1, 0, 0, 1, 0,
            0, -1, 0, 0, 0,
        ];
        let output = trits_to_trytes(&result).unwrap();
        assert_eq!(output, trytes);
    }
}
