#[macro_use]
extern crate log;
extern crate libc;

extern crate iota_mam_sys as ffi;

mod channel;
mod endpoint;
mod errors;
mod mss;
mod prng;
mod spongos;
mod trits;
// mod message;
mod api;
mod constants;
mod psk;
mod types;
// mod ntru;
pub mod converter;

pub use channel::*;
pub use endpoint::*;
pub use errors::*;
pub use mss::*;
pub use prng::*;
pub use spongos::*;
pub use trits::*;
// pub use message::*;
pub use api::*;
pub use constants::*;
pub use psk::*;
pub use types::*;
// pub use ntru::*;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
