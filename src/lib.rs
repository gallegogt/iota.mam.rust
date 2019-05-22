#[macro_use]
extern crate log;
extern crate libc;

extern crate iota_mam_sys as ffi;

mod errors;
mod trits;
mod prng;
mod mss;
mod spongos;
mod endpoint;
mod channel;
mod psk;
mod api;
mod types;

pub use errors::*;
pub use trits::*;
pub use prng::*;
pub use mss::*;
pub use endpoint::*;
pub use spongos::*;
pub use channel::*;
pub use psk::*;
pub use api::*;
pub use types::*;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
