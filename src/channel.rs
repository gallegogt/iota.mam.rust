use crate::constants::{CHANNEL_ID_SIZE, CHANNEL_MSG_ORD_SIZE};
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
        Trits::from((CHANNEL_ID_SIZE, self.c_channel.mss.root.as_ptr()))
    }

    ///
    /// Gets a channel's name
    ///
    pub fn name(&self) -> Trits {
        Trits {
            c_trits: self.c_channel.name,
        }
    }

    ///
    /// Gets a channel's name size
    ///
    pub fn name_size(&self) -> Trits {
        Trits {
            c_trits: self.c_channel.name_size,
        }
    }

    ///
    /// Gets a channel's msg_ord
    ///
    pub fn msg_ord(&mut self) -> Trits {
        Trits::from((CHANNEL_MSG_ORD_SIZE, self.c_channel.msg_ord.as_ptr()))
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
