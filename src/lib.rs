#[macro_use]
extern crate log;
extern crate libc;

extern crate iota_mam_sys as ffi;

pub type Tryte = ffi::tryte_t;

mod errors;
mod trits;
mod prng;
mod mss;
mod spongos;
mod endpoint;
mod channel;
mod psk;

pub use errors::*;
pub use trits::*;
pub use prng::*;
pub use mss::*;
pub use endpoint::*;
pub use spongos::*;
pub use channel::*;
pub use psk::*;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
