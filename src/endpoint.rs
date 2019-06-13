use crate::constants::ENDPOINT_ID_SIZE;
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
    /// @param channel_name_size The channel name size
    /// @param channel_name The channel name
    /// @param endpoint_name The endpoint name
    /// @param endpoint The endpoint
    ///
    pub fn new(
        prng: &mut Prng,
        height: MssMtHeight,
        channel_name_size: Trits,
        channel_name: Trits,
        endpoint_name: Trits,
    ) -> MamResult<Endpoint> {
        unsafe {
            let mut c_endpoint: ffi::mam_endpoint_t = mem::uninitialized();
            let rc = ffi::mam_endpoint_create(
                prng.into_raw_mut(),
                height,
                channel_name_size.into_raw(),
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
        Trits::from((ENDPOINT_ID_SIZE, self.c_endpoint.mss.root.as_ptr()))
    }

    ///
    /// Gets an endpoint channel's name
    ///
    pub fn name(&self) -> Trits {
        Trits {
            c_trits: self.c_endpoint.name,
        }
    }
    ///
    /// Gets an endpoint's name size
    ///
    pub fn name_size(&self) -> Trits {
        Trits {
            c_trits: self.c_endpoint.name_size,
        }
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

impl From<ffi::mam_endpoint_t> for Endpoint {
    ///
    /// From
    ///
    fn from(s: ffi::mam_endpoint_t) -> Endpoint {
        Endpoint { c_endpoint: s }
    }
}
