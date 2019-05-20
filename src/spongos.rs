use crate::trits::Trits;
use ffi;
use std::mem;

///
/// MAM Spongos
///
#[derive(Clone)]
pub struct Spongos {
    c_spongos: ffi::mam_spongos_t,
}

impl Spongos {
    /**
     * Constructor
     */
    pub fn new() -> Self {
         unsafe {
            let mut spongos: ffi::mam_spongos_t = mem::uninitialized();
            ffi::mam_spongos_init(&mut spongos);

            Spongos {
                c_spongos: spongos,
            }
         }
    }

    ///
    /// Creates an equivalent spongos instance
    ///
    pub fn fork(&self, fork: &mut Spongos) {
        unsafe {
            ffi::mam_mam_spongos_fork(&self.c_spongos, &mut fork.c_spongos)
        }
    }

    ///
    /// Commits changes in the rate part
    ///
    pub fn commit(&mut self) {
        unsafe {
            ffi::mam_spongos_commit(&mut self.c_spongos)
        }
    }

    ///
    /// Processes input data
    ///
    pub fn absorb(&mut self, input: &Trits) {
        unsafe {
            ffi::mam_spongos_absorb(&mut self.c_spongos, input.into_raw())
        }
    }

    ///
    ///  Processes n inputs data
    ///
    pub fn absorbn(&mut self, n: usize, inputs: &mut Trits) {
        unsafe {
            ffi::mam_spongos_absorbn(&mut self.c_spongos, n, inputs.into_raw_mut())
        }
    }

    ///
    /// Generates output data
    ///
    pub fn squeeze(&mut self, output: &Trits) {
        unsafe {
            ffi::mam_spongos_squeeze(&mut self.c_spongos, output.into_raw())
        }
    }

    ///
    /// Generates output data and check for equality with given output
    ///
    pub fn squeeze_eq(&mut self, expected_output: &Trits) -> bool {
        unsafe {
            ffi::mam_spongos_squeeze_eq(&mut self.c_spongos, expected_output.into_raw())
        }
    }

    ///
    /// Hashes input data
    ///
    pub fn hash(&mut self, input: &Trits, output: &Trits) {
        unsafe {
            ffi::mam_spongos_hash(&mut self.c_spongos, input.into_raw(), output.into_raw())
        }
    }

    ///
    /// Hashes n input data
    ///
    pub fn hashn(&mut self,n: usize, input: &mut Trits, output: &mut Trits) {
        unsafe {
            ffi::mam_spongos_hashn(&mut self.c_spongos, n, input.into_raw_mut(), output.into_raw())
        }
    }

    ///
    /// Encrypts plaintext
    ///
    pub fn encr(&mut self, plaintext: &Trits, ciphertext: &mut Trits) {
        unsafe {
            ffi::mam_spongos_encr(&mut self.c_spongos, plaintext.into_raw(), ciphertext.into_raw())
        }
    }

    ///
    /// Decrypts ciphertext
    ///
    pub fn decr(&mut self, ciphertext: &Trits, plaintext: &mut Trits) {
        unsafe {
            ffi::mam_spongos_decr(&mut self.c_spongos, ciphertext.into_raw(), plaintext.into_raw())
        }
    }

    ///
    /// Copy spongos from src to dst
    ///
    pub fn copy(&mut self, dst: &mut Spongos) {
        unsafe {
            ffi::mam_spongos_copy(&mut self.c_spongos, &mut dst.c_spongos)
        }
    }

    ///
    /// C instance
    ///
    pub fn into_raw(&self) -> &ffi::mam_spongos_t {
        &self.c_spongos
    }

    ///
    /// Mut C instance
    ///
    pub fn into_raw_mut(&mut self) -> &mut ffi::mam_spongos_t {
        &mut self.c_spongos
    }
}
