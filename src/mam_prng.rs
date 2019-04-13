use ffi;
use std::mem;

use crate::trits::Trits;


#[derive(Clone)]
pub struct MamPrng {
    pub c_prng: Box<ffi::mam_prng_t>
}

impl MamPrng {
    ///
    /// PRNG initialization
    ///
    pub fn new(secret_key: Trits) -> Self {
        unsafe {
            let mut sf = Self {
                c_prng: Box::new(ffi::mam_prng_t{
                    secret_key: mem::uninitialized(),
                })
            };

            ffi::mam_prng_init(&mut *(sf.c_prng), secret_key.into_raw());

            sf
        }
    }

    // /**
    //  * PRNG output generation with a nonce
    //  *
    //  * @param prng A PRNG interface
    //  * @param destination A destination tryte
    //  * @param nonce The nonce
    //  * @param output Pseudorandom output trits
    //  */
    pub fn gen(&self, destination: u32, nonce: &Trits, output: &mut Trits) {
        unsafe {
            ffi::mam_prng_gen(&(*self.c_prng), destination, nonce.into_raw(), output.c_trits)
        }
    }

}

impl Drop for MamPrng {

    /// PRNG deinitialization
    fn drop(&mut self) {
        unsafe {
            ffi::mam_prng_destroy(&mut (*self.c_prng));
        }

    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_new_mam_prng() {
        let mut key = Trits::new(ffi::MAM_PRNG_KEY_SIZE as usize);
        key.set_zero();
        key.from_str("NOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLM");

        let mut nonce = Trits::new(18);
        nonce.set_zero();

        let mut y1 = Trits::new(243 * 2 + 18);
        y1.set_zero();

        let mut y2 = Trits::new(243 * 2 + 18);
        y2.set_zero();

        println!("{:?} \n {:?}", key.size(), key.to_str());
        let prng = MamPrng::new(key);
        prng.gen(0, &nonce, &mut y1);
        prng.gen(1, &nonce, &mut y2);

        println!("{:?} \n {:?}", y1.size(), y1.to_str());
        println!("{:?} \n {:?}", y2.size(), y2.to_str());

        assert_eq!(30, 30);
    }
}

