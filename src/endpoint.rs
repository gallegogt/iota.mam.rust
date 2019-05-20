use crate::errors::{MamError, MamResult};
use crate::mss::MssMtHeight;
use crate::prng::Prng;
use crate::trits::Trits;
use ffi;
use std::mem;

///
/// MAM Endpoint
///
#[derive(Clone)]
pub struct Endpoint {
    c_endpoint: ffi::mam_endpoint_t,
}

impl Endpoint {
    ///
    /// Allocates memory for internal objects and generates MSS public key
    ///
    /// @param allocator A MAM allocator
    /// @param prng A shared PRNG interface used to generate WOTS private keys
    /// @param height MSS MT height
    /// @param channel_name The channel name
    /// @param endpoint_name The endpoint name
    /// @param endpoint The endpoint
    ///
    pub fn new(
        prng: &mut Prng,
        height: MssMtHeight,
        channel_name: Trits,
        endpoint_name: Trits,
    ) -> MamResult<Endpoint> {
        unsafe {
            let mut c_endpoint: ffi::mam_endpoint_t = mem::uninitialized();
            let rc = ffi::mam_endpoint_create(
                prng.into_raw_mut(),
                height,
                channel_name.into_raw(),
                endpoint_name.into_raw(),
                &mut c_endpoint,
            );

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }

            Ok(Self {
                c_endpoint: c_endpoint,
            })
        }
    }

    ///
    ///  Gets an endpoint's id
    ///
    pub fn id(&self) -> Trits {
        unsafe {
            Trits {
                c_trits: ffi::mam_endpoint_id(&self.c_endpoint),
            }
        }
    }

    ///
    /// Gets an endpoint channel's name
    ///
    pub fn channel_name(&self) -> Trits {
        unsafe {
            Trits {
                c_trits: ffi::mam_endpoint_channel_name(&self.c_endpoint),
            }
        }
    }

    ///
    ///  Gets an endpoint's name
    ///
    pub fn name(&self) -> Trits {
        unsafe {
            Trits {
                c_trits: ffi::mam_endpoint_name(&self.c_endpoint),
            }
        }
    }

    ///
    /// Returns the number of remaining secret keys (unused leaves on merkle tree)
    ///
    pub fn num_remaining_sks(&self) -> usize {
        unsafe { ffi::mam_endpoint_num_remaining_sks(&self.c_endpoint) }
    }
}

impl Drop for Endpoint {
    ///
    ///  Deallocates memory for internal objects
    ///
    fn drop(&mut self) {
        unsafe { ffi::mam_endpoint_destroy(&mut self.c_endpoint) }
    }
}
