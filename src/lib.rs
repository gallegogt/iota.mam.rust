#[macro_use]
extern crate log;
extern crate libc;

extern crate iota_mam_sys as ffi;

mod api;
mod bundle;
mod channel;
mod constants;
pub mod converter;
mod endpoint;
mod errors;
mod mss;
mod ntru;
mod prng;
mod psk;
mod spongos;
mod trits;
mod types;

pub use channel::*;
pub use endpoint::*;
pub use errors::*;
pub use mss::*;
pub use prng::*;
pub use spongos::*;
pub use trits::*;
// pub use message::*;
pub use api::*;
pub use bundle::*;
pub use constants::*;
pub use ntru::*;
pub use psk::*;
pub use types::*;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
