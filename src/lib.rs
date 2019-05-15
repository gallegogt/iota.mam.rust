#[macro_use]
extern crate log;
extern crate libc;

extern crate iota_mam_sys as ffi;

mod errors;
mod trits;
mod prng;
mod mss;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
