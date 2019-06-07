use crate::constants::TRYTE_ALPHABET;
use crate::converter::{ConverterErrorKind, ConverterResult};

///
/// Converts an ascii encoded string to trytes.
///
pub fn ascii_to_trytes<'a>(input: &'a str) -> ConverterResult<String> {
    let mut trytes = "".to_owned();

    if !input.is_ascii() {
        return Err(ConverterErrorKind::InvalidAsciiChars);
    }

    for ch in input.chars() {
        let dec = ch as usize;
        trytes.push(TRYTE_ALPHABET[dec % 27]);
        trytes.push(TRYTE_ALPHABET[(dec - (dec % 27)) / 27]);
    }

    Ok(trytes)
}

///
/// Converts trytes of _even_ length to an ascii string
///
pub fn trytes_to_ascii<'a>(trytes: &'a str) -> ConverterResult<String> {
    if !trytes.chars().all(|c| TRYTE_ALPHABET.contains(&c)) {
        return Err(ConverterErrorKind::InvalidTrytes);
    }

    if trytes.len() % 2 != 0 {
        return Err(ConverterErrorKind::InvalidOddLength);
    }

    let mut ascii = "".to_owned();
    let v_chars: Vec<char> = trytes.chars().collect();

    for chunk in v_chars.chunks(2) {
        let idx_c1: u8 = match chunk[0] {
            '9' => 0,
            v => (v as u8) - ('A' as u8) + 1,
        };
        let idx_c2: u8 = match chunk[1] {
            '9' => 0,
            v => (v as u8) - ('A' as u8) + 1,
        };
        ascii.push((idx_c1 + idx_c2 * 27) as char);
    }

    Ok(ascii)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_convert_ascii_to_trytes() {
        let ascii_value = "ASCII Message to Trytes";
        let trytes = "KBBCMBSBSBEAWBTCGDGDPCVCTCEAHDCDEACCFDMDHDTCGD";

        let output = ascii_to_trytes(ascii_value).unwrap();
        assert_eq!(output, trytes);
    }

    #[test]
    fn check_convert_trytes_to_ascii() {
        let ascii_value = "ASCII Message to Trytes, Hola Mundo; Hello World; .....";
        let trytes = "KBBCMBSBSBEAWBTCGDGDPCVCTCEAHDCDEACCFDMDHDTCGDQAEARBCD9DPCEAWBIDBDSCCDEBEARBTC9D9DCDEAFCCDFD9DSCEBEASASASASASA";

        let output = trytes_to_ascii(trytes).unwrap();
        assert_eq!(output, ascii_value);
    }
}
