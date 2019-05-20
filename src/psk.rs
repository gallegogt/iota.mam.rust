use crate::errors::{MamError, MamResult};
use crate::prng::Prng;
use crate::trits::Trits;
use crate::Tryte;

use ffi;
use std::mem;

///
/// MAM Psk
///
#[derive(Clone)]
pub struct Psk {
    c_psk: ffi::mam_psk_t,
}

impl Psk {
    ///
    /// Generates a pre-shared key with an id and a nonce
    ///
    /// [in] prng A PRNG
    /// [in] id The pre-shared key id
    /// [in] nonce A trytes nonce
    /// [in] nonce_length Length of the trytes nonce
    ///
    pub fn gen(prng: &Prng, id: &Tryte, nonce: &Tryte, nonce_length: usize) -> MamResult<Psk> {
        unsafe {
            let mut pks: ffi::mam_psk_t = mem::uninitialized();
            let rc = ffi::mam_psk_gen(&mut pks, &prng.into_raw(), id, nonce, nonce_length);

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(Psk { c_psk: pks })
        }
    }

    ///
    /// Safely resets a pre-shared key by clearing its secret part
    ///
    pub fn reset(&mut self) {
        for i in self.c_psk.key.iter_mut() {
            *i = 0;
        }
    }

    ///
    /// Gets a pre-shared key id trits
    ///
    pub fn id(&self) -> Trits {
        Trits::from((ffi::MAM_PSK_ID_SIZE as usize, self.c_psk.id.as_ptr()))
    }

    ///
    /// Gets a pre-shared key trits
    ///
    pub fn key(&self) -> Trits {
        Trits::from((ffi::MAM_PSK_KEY_SIZE as usize, self.c_psk.key.as_ptr()))
    }
}

///
/// MAM Psk Set
///
#[derive(Clone)]
pub struct PskSet {
    c_psk_set: ffi::mam_psk_t_set_t,
}

impl PskSet {
    ///
    /// Gets the size of a serialized set of pre-shared keys
    ///
    pub fn serialized_size(&self) -> usize {
        unsafe { ffi::mam_psks_serialized_size(self.c_psk_set) }
    }

    ///
    /// Serializes a set of pre-shared keys into a trits buffer
    ///
    /// [out] trits The trits buffer to serialize into
    ///
    pub fn serialize(&self, trits: &mut Trits) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_psks_serialize(self.c_psk_set, &mut trits.c_trits);

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }

            Ok(())
        }
    }

    ///
    /// Serializes a set of pre-shared keys into a trits buffer
    ///
    /// [out] trits The trits buffer to serialize into
    ///
    pub fn deserialize(&self, buffer: &mut Trits) -> MamResult<PskSet> {
        unsafe {
            let mut psks: ffi::mam_psk_t_set_t = mem::uninitialized();
            let rc = ffi::mam_psks_deserialize(&mut buffer.c_trits, &mut psks);

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }

            Ok(PskSet { c_psk_set: psks })
        }
    }
}

impl Drop for PskSet {
    fn drop(&mut self) {
        unsafe {
            ffi::mam_psks_destroy(&mut self.c_psk_set);
        }
    }
}
