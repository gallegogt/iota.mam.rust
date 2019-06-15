use ffi;

pub const TRYTE_ALPHABET_LENGTH: usize = 27;

/// A char array holding all acceptable characters in the tryte
/// alphabet. Used because strings can't be cheaply indexed in rust.
pub const TRYTE_ALPHABET: [char; TRYTE_ALPHABET_LENGTH] = [
    '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
    'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
];
/// The number of trits in a byte
pub const TRITS_PER_BYTE: usize = 5;
/// The number of trits in a tryte
pub const TRITS_PER_TRYTE: usize = 3;
// Trytes to trits look up table
pub const TRYTES_TRITS_LUT: [[i8; TRITS_PER_TRYTE]; TRYTE_ALPHABET_LENGTH] = [
    [0, 0, 0],
    [1, 0, 0],
    [-1, 1, 0],
    [0, 1, 0],
    [1, 1, 0],
    [-1, -1, 1],
    [0, -1, 1],
    [1, -1, 1],
    [-1, 0, 1],
    [0, 0, 1],
    [1, 0, 1],
    [-1, 1, 1],
    [0, 1, 1],
    [1, 1, 1],
    [-1, -1, -1],
    [0, -1, -1],
    [1, -1, -1],
    [-1, 0, -1],
    [0, 0, -1],
    [1, 0, -1],
    [-1, 1, -1],
    [0, 1, -1],
    [1, 1, -1],
    [-1, -1, 0],
    [0, -1, 0],
    [1, -1, 0],
    [-1, 0, 0],
];

/// The minimum value a trit can have
pub const MIN_TRIT_VALUE: i8 = -1;
/// The maximum value a trit can have
pub const MAX_TRIT_VALUE: i8 = 1;
/// Base
pub const RADIX: i8 = 3;
/// The minimum value a tryte can have
pub const MIN_TRYTE_VALUE: i8 = -13;
/// The maximum value a tryte can have
pub const MAX_TRYTE_VALUE: i8 = 13;

// Channel Constants
pub const CHANNEL_ID_SIZE: usize = ffi::MAM_CHANNEL_ID_SIZE as usize;
pub const TRYTE_CHANNEL_ID_SIZE: usize = (ffi::MAM_CHANNEL_ID_SIZE as usize) / 3;
pub const CHANNEL_NAME_SIZE: usize = ffi::MAM_CHANNEL_NAME_SIZE as usize;
pub const CHANNEL_MSG_ORD_SIZE: usize = ffi::MAM_CHANNEL_MSG_ORD_SIZE as usize;

// Endpoint Constants
pub const ENDPOINT_ID_SIZE: usize = ffi::MAM_ENDPOINT_ID_SIZE as usize;
pub const TRYTE_ENDPOINT_ID_SIZE: usize = (ffi::MAM_ENDPOINT_ID_SIZE as usize) / 3;
pub const ENDPOINT_NAME_SIZE: usize = ffi::MAM_ENDPOINT_NAME_SIZE as usize;

// PRNG Constants
pub const PRNG_SECRET_KEY_SIZE: usize = ffi::MAM_PRNG_SECRET_KEY_SIZE as usize;
