use crate::constants::{MAM_NTRU_ID_SIZE, MAM_NTRU_PK_SIZE};
use crate::errors::{MamError, MamResult};
use crate::trits::Trits;
use ffi;
use std::mem;
use std::ptr;

///
/// NTRU Public Key
///
#[derive(Clone)]
pub struct NtruPk {
    c_inner: ffi::mam_ntru_pk_t,
}

impl NtruPk {
    ///
    /// Create new instance for NtruPk, uninitialized
    ///
    pub fn new() -> Self {
        unsafe {
            NtruPk {
                c_inner: mem::uninitialized(),
            }
        }
    }

    ///
    /// Gets a NTRU public key id trits
    ///
    /// @param ntru_pk The NTRU public key
    ///
    /// @return the NTRU public key id trits
    ///
    pub fn id(&self) -> Trits {
        Trits::from((MAM_NTRU_ID_SIZE, self.c_inner.key.as_ptr()))
    }

    ///
    /// Gets a NTRU public key trits
    ///
    /// @param ntru_pk The NTRU public key
    ///
    /// @return the NTRU public key trits
    ///
    pub fn key(&self) -> Trits {
        Trits::from((MAM_NTRU_PK_SIZE, self.c_inner.key.as_ptr()))
    }

    pub fn into_raw(&self) -> &ffi::mam_ntru_pk_t {
        &self.c_inner
    }
}

impl From<ffi::mam_ntru_pk_t> for NtruPk {
    fn from(value: ffi::mam_ntru_pk_t) -> NtruPk {
        NtruPk { c_inner: value }
    }
}

///
/// NTRU Secret Key
///
#[derive(Clone)]
pub struct NtruSk {
    c_ntru_sk: ffi::mam_ntru_sk_t,
}

impl NtruSk {
    ///
    /// Create new instance for NtruSk, uninitialized
    ///
    pub fn new() -> Self {
        unsafe {
            NtruSk {
                c_ntru_sk: mem::uninitialized(),
            }
        }
    }
    ///
    /// Safely resets a NTRU secret key by clearing its secret part
    ///
    /// @return a status code
    ///
    pub fn reset(&mut self) -> MamResult<()> {
        unsafe {
            let rc = ffi::ntru_sk_reset(&mut self.c_ntru_sk);

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(())
        }
    }

    ///
    /// Update current NTRU secret key
    ///
    /// @param prng A PRNG interface
    /// @param nonce A nonce
    ///
    pub fn update(&mut self, prng: &ffi::mam_prng_t, nonce: &Trits) {
        unsafe {
            ffi::ntru_sk_gen(&mut self.c_ntru_sk, prng, nonce.into_raw());
        }
    }

    ///
    /// Generates a NTRU secret key
    ///
    /// @param prng A PRNG interface
    /// @param nonce A nonce
    ///
    pub fn gen(prng: &ffi::mam_prng_t, nonce: &Trits) -> NtruSk {
        unsafe {
            let mut ntru_sk: ffi::mam_ntru_sk_s = mem::uninitialized();
            ffi::ntru_sk_gen(&mut ntru_sk, prng, nonce.into_raw());

            NtruSk { c_ntru_sk: ntru_sk }
        }
    }

    ///
    /// Return internal c structure mutable
    ///
    pub fn into_raw_mut(&mut self) -> &mut ffi::mam_ntru_sk_s {
        &mut self.c_ntru_sk
    }

    ///
    /// Return internal c structure
    ///
    pub fn into_raw(&self) -> &ffi::mam_ntru_sk_s {
        &self.c_ntru_sk
    }

    pub fn public_key(&self) -> NtruPk {
        NtruPk::from(self.c_ntru_sk.public_key.clone())
    }
}

///
/// NTRU Public Key Set
///
pub struct NtruPkSet {
    c_inner: ffi::mam_ntru_pk_t_set_t,
}

impl NtruPkSet {
    ///
    /// Initialize
    ///
    pub fn new() -> Self {
        NtruPkSet {
            c_inner: ptr::null_mut(),
        }
    }

    ///
    /// Add
    ///
    pub fn add(&mut self, value: &NtruPk) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_ntru_pk_t_set_add(&mut self.c_inner, value.into_raw());
            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(())
        }
    }
    ///
    /// Into Raw
    ///
    pub fn into_raw(&self) -> &ffi::mam_ntru_pk_t_set_t {
        &self.c_inner
    }
}

///
/// Release resources
///
impl Drop for NtruPkSet {
    fn drop(&mut self) {
        unsafe { ffi::mam_ntru_pk_t_set_free(&mut self.c_inner) }
    }
}
