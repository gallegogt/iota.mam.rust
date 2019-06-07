#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum ConverterErrorKind {
    /// Invalid trytes
    InvalidTrytes,
    /// Invalid trits
    InvalidTrits,
    /// Invalid trytes length. Expected trytes of even length.'
    InvalidOddLength,
    /// Invalid ascii charactes.
    InvalidAsciiChars,
}

pub type ConverterResult<T> = Result<T, ConverterErrorKind>;
