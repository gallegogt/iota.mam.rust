use crate::errors::{MamError, MamResult};
use crate::mss::MssMtHeight;
use crate::prng::Prng;
use crate::trits::Trits;
use ffi;
use std::mem;

///
/// MAM Channel
///
#[derive(Clone)]
pub struct Channel {
    c_channel: ffi::mam_channel_t,
}

impl Channel {
    ///
    /// Constructor
    ///
    pub fn new(prng: &mut Prng, height: MssMtHeight, channel_name: Trits) -> MamResult<Channel> {
        unsafe {
            let mut c_channel: ffi::mam_channel_t = mem::uninitialized();
            let rc = ffi::mam_channel_create(
                prng.into_raw_mut(),
                height,
                channel_name.into_raw(),
                &mut c_channel,
            );

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }

            Ok(Self {
                c_channel: c_channel,
            })
        }
    }

    ///
    /// Gets a channel's id
    ///
    pub fn id(&mut self) -> Trits {
        unsafe {
            Trits {
                c_trits: ffi::mam_channel_id(&mut self.c_channel),
            }
        }
    }

    ///
    /// Gets a channel's name
    ///
    pub fn name(&mut self) -> Trits {
        unsafe {
            Trits {
                c_trits: ffi::mam_channel_name(&mut self.c_channel),
            }
        }
    }

    ///
    /// Gets a channel's msg_ord
    ///
    pub fn msg_ord(&mut self) -> Trits {
        unsafe {
            Trits {
                c_trits: ffi::mam_channel_msg_ord(&mut self.c_channel),
            }
        }
    }

    ///
    /// Returns the number of remaining secret keys (unused leaves on merkle tree)
    ///
    pub fn num_remaining_sks(&mut self) -> usize {
        unsafe { ffi::mam_channel_num_remaining_sks(&mut self.c_channel) }
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        unsafe { ffi::mam_channel_destroy(&mut self.c_channel) }
    }
}

impl From<ffi::mam_channel_t> for Channel {
    ///
    /// From
    ///
    fn from(s: ffi::mam_channel_t) -> Channel {
        Channel { c_channel: s }
    }
}
