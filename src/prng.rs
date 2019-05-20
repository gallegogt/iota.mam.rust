use crate::errors::{MamError, MamResult};
use crate::trits::Trits;
use ffi;

///
/// Destination context encoded in one tryte
///
pub enum PrngDst {
    SecKey = 0,
    WotsKey = 1,
    NtruKey = 2,
}

///
/// MAM PRNG
///
#[derive(Clone)]
pub struct Prng {
    pub c_prng: ffi::mam_prng_t,
}

impl Prng {
    ///
    /// Initializes a PRNG with a secret key
    ///
    pub fn new(secret_key: Trits) -> Self {
        unsafe {
            let mut sf = Self {
                c_prng: ffi::mam_prng_t {
                    secret_key: [0; ffi::MAM_PRNG_SECRET_KEY_SIZE as usize],
                },
            };

            ffi::mam_prng_init(&mut sf.c_prng, secret_key.into_raw());
            sf
        }
    }

    ///
    /// Return the C raw info
    ///
    pub fn into_raw_mut(&mut self) -> &mut ffi::mam_prng_t {
        &mut self.c_prng
    }

    ///
    /// Return the C raw info
    ///
    pub fn into_raw(&self) -> ffi::mam_prng_t {
        self.c_prng
    }

    ///
    /// Safely resets a PRNG secret key
    ///
    pub fn reset(&mut self) {
        for i in self.c_prng.secret_key.iter_mut() {
            *i = 0;
        }
    }

    ///
    /// @brief Generates pseudo random trits with three nonces
    ///
    /// @param[in] prng A PRNG
    /// @param[in] destination A destination tryte
    /// @param[in] nonce1 The first nonce
    /// @param[in] nonce2 The second nonce
    /// @param[in] nonce3 The third nonce
    /// @param[out] output The pseudo random trits
    ///
    /// @return a status code
    ///
    pub fn gen3(
        &self,
        destination: PrngDst,
        nonce1: &Trits,
        nonce2: &Trits,
        nonce3: &Trits,
        output: &Trits,
    ) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_prng_gen3(
                &self.c_prng,
                destination as u32,
                nonce1.into_raw(),
                nonce2.into_raw(),
                nonce3.into_raw(),
                output.into_raw(),
            );

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }

            Ok(())
        }
    }

    ///
    /// Generates pseudo random trits with a nonce
    ///
    /// @param prng A PRNG interface
    /// @param destination A destination tryte
    /// @param nonce The nonce
    /// @param output Pseudorandom output trits
    ///
    pub fn gen(&self, destination: PrngDst, nonce: &Trits, output: &Trits) -> MamResult<()> {
        self.gen3(destination, nonce, &Trits::null(), &Trits::null(), output)
    }

    ///
    /// @brief Generates pseudo random trits with two nonces
    ///
    /// @param[in] prng A PRNG
    /// @param[in] destination A destination tryte
    /// @param[in] nonce1 The first nonce
    /// @param[in] nonce2 The second nonce
    /// @param[out] output The pseudo random trits
    ///
    /// @return a status code
    ///
    pub fn gen2(
        &self,
        destination: PrngDst,
        nonce1: &Trits,
        nonce2: &Trits,
        output: &Trits,
    ) -> MamResult<()> {
        self.gen3(destination, nonce1, nonce2, &Trits::null(), output)
    }

    ///
    /// Size of a serialized PRNG
    ///
    pub fn serialize_size() -> usize {
        ffi::MAM_PRNG_SECRET_KEY_SIZE as usize
    }

    ///
    ///  Serializes a PRNG into a trits buffer
    ///
    pub fn serialize(&self) -> Trits {
        unsafe {
            let mut buffer = Trits::new(Prng::serialize_size());
            buffer.set_zero();

            let mut from_rep = Trits::from((
                ffi::MAM_PRNG_SECRET_KEY_SIZE as usize,
                self.c_prng.secret_key.as_ptr(),
            ));

            ffi::pb3_encode_ntrytes(from_rep.into_raw(), buffer.into_raw_mut());

            from_rep.set_null();

            buffer.pickup_all()
        }
    }
    ///
    /// Deserializes a PRNG from a trits buffer
    ///
    /// @param[in] buffer The trits buffer
    ///
    pub fn deserialize(buffer: &mut Trits) -> MamResult<Prng> {
        unsafe {
            let c_prng = ffi::mam_prng_t {
                secret_key: [0; ffi::MAM_PRNG_SECRET_KEY_SIZE as usize],
            };

            let mut trits = Trits::from((
                ffi::MAM_PRNG_SECRET_KEY_SIZE as usize,
                c_prng.secret_key.as_ptr(),
            ));

            let rc = ffi::pb3_decode_ntrytes(trits.into_raw(), buffer.into_raw_mut());

            // TODO: Fix error of no alloc memory
            trits.set_null();

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }

            Ok(Prng { c_prng: c_prng })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn check_new_mam_prng() {
        let mut key = Trits::new(ffi::MAM_PRNG_SECRET_KEY_SIZE as usize);
        key.set_zero();
        key.from_str(
            "NOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLM",
        );
        let nonce = Trits::new(18);
        nonce.set_zero();
        let y2 = Trits::new(243 * 2 + 18);
        y2.set_zero();
        let y1 = Trits::new(243 * 2 + 18);
        y1.set_zero();
        let prng = Prng::new(key);

        match prng.gen(PrngDst::SecKey, &nonce, &y2) {
            Err(e) => {
                println!("{:?}", e.description());
            }
            Ok(_) => {}
        }

        match prng.gen(PrngDst::NtruKey, &nonce, &y1) {
            Err(e) => {
                println!("{:?}", e.description());
            }
            Ok(_) => {}
        }

        assert_ne!(y1, y2);
    }

    #[test]
    fn check_prng_serialization() {
        let mut key = Trits::new(ffi::MAM_PRNG_SECRET_KEY_SIZE as usize);
        key.set_zero();
        key.from_str(
            "NOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLM",
        );
        let prng1 = Prng::new(key);
        let mut trits = prng1.serialize();

        match Prng::deserialize(&mut trits) {
            Err(e) => {
                println!("Error {:?}", e);
                assert!(false);
            }

            Ok(prng2) => {
                // TODO: Fix error of no alloc memory
                trits.set_null();

                assert_eq!(
                    prng1.into_raw().secret_key.len(),
                    prng2.into_raw().secret_key.len()
                );
            }
        };
    }
}
