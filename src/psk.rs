use crate::errors::{MamError, MamResult};
use crate::trits::Trits;
use crate::Tryte;
use ffi;
use std::mem;
use std::ptr;

///
/// MAM Psk
///
#[derive(Clone)]
pub struct Psk {
    c_psk: ffi::mam_psk_t,
}

impl Psk {
    ///
    /// Create new instance for NtruSk, uninitialized
    ///
    pub fn new() -> Self {
        unsafe {
            Psk {
                c_psk: mem::uninitialized(),
            }
        }
    }

    ///
    /// Generates a pre-shared key with an id and a nonce
    ///
    /// [in] prng A PRNG
    /// [in] id The pre-shared key id
    /// [in] nonce A trytes nonce
    /// [in] nonce_length Length of the trytes nonce
    ///
    pub fn gen(
        prng: &ffi::mam_prng_t,
        id: &[Tryte],
        nonce: &[Tryte],
        nonce_length: usize,
    ) -> MamResult<Psk> {
        unsafe {
            let mut pks: ffi::mam_psk_t = mem::uninitialized();
            let rc = ffi::mam_psk_gen(&mut pks, prng, id.as_ptr(), nonce.as_ptr(), nonce_length);

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

    ///
    /// return C instance
    ///
    pub fn into_raw(&self) -> &ffi::mam_psk_t {
        &self.c_psk
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
    /// Initialize
    ///
    pub fn new() -> Self {
        PskSet {
            c_psk_set: ptr::null_mut(),
        }
    }
    ///
    /// Gets the size of a serialized set of pre-shared keys
    ///
    pub fn serialized_size(&self) -> usize {
        unsafe { ffi::mam_psks_serialized_size(self.c_psk_set) }
    }

    ///
    /// return C instance
    ///
    pub fn into_raw(&self) -> &ffi::mam_psk_t_set_t {
        &self.c_psk_set
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

    ///
    /// Add PKS
    ///
    pub fn add(&mut self, value: &Psk) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_psk_t_set_add(&mut self.c_psk_set, value.into_raw());

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }

            Ok(())
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
