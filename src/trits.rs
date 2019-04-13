use crate::errors::{MamError, MamResult};
use ::std::os::raw::c_char;
use ffi;
use std::convert::From;
use std::ffi::CStr;
use std::ffi::CString;
use std::mem;
use std::str::FromStr;

/// An MAM Trits
#[derive(Debug)]
pub struct Trits {
    pub c_trits: ffi::trits_t,
}

impl Trits {
    pub fn new(n: usize) -> Self {
        unsafe {
            Self {
                c_trits: ffi::trits_alloc(n),
            }
        }
    }

    /// Check `x.n` against zero.
    pub fn is_empty(&self) -> bool {
        unsafe { ffi::trits_is_empty(self.c_trits) }
    }

    ///
    /// Size of trits.
    ///
    pub fn size(&self) -> usize {
        unsafe { ffi::trits_size(self.c_trits) }
    }

    ///
    /// Minimum of the size of `x` and `s`.
    ///
    pub fn size_min(&self, s: usize) -> usize {
        unsafe { ffi::trits_size_min(self.c_trits, s) }
    }

    ///
    /// Take the first `n` trits from `x`
    ///
    pub fn take(&self, n: usize) -> Self {
        unsafe {
            Trits {
                c_trits: ffi::trits_take(self.c_trits, n),
            }
        }
    }

    ///
    /// Set zero trits
    ///
    pub fn set_zero(&mut self) {
        unsafe {
            libc::memset(
                self.c_trits.p.offset(self.c_trits.d as isize) as *mut libc::c_void,
                0,
                self.size(),
            );
        }
    }

    ///
    /// Fill the current Trits with the str
    ///
    pub fn from_str<'a>(&mut self, s: &'a str) {
        unsafe {
            ffi::trits_from_str(self.c_trits, CString::new(s).unwrap().as_ptr());
        }
    }

    ///
    ///Take at most `n` first trits from `x`
    ///
    pub fn take_min(&self, n: usize) -> Self {
        unsafe {
            Trits {
                c_trits: ffi::trits_take_min(self.c_trits, n),
            }
        }
    }

    ///
    ///  Drop the first `n` trits from `x`
    ///
    pub fn drop(&self, n: usize) -> Self {
        unsafe {
            Trits {
                c_trits: ffi::trits_drop(self.c_trits, n),
            }
        }
    }

    ///
    /// Return the C raw info
    ///
    pub fn into_raw(&self) -> ffi::trits_t {
        self.c_trits
    }

    ///
    ///  Drop the first `n` trits from `x`
    ///
    pub fn drop_min(&self, n: usize) -> Self {
        unsafe {
            Trits {
                c_trits: ffi::trits_drop_min(self.c_trits, n),
            }
        }
    }

    ///
    ///  Pickup `n` trits previously dropped from `x`.
    ///
    pub fn pickup(&self, n: usize) -> Self {
        unsafe {
            Trits {
                c_trits: ffi::trits_pickup(self.c_trits, n),
            }
        }
    }

    ///
    /// Pickup All
    ///
    pub fn pickup_all(&self) -> Self {
        unsafe {
            Trits {
                c_trits: ffi::trits_pickup_all(self.c_trits),
            }
        }
    }

    ///
    /// \brief Convert trytes to string.
    /// \note `trits_size(x)` must be multiple of 3.
    /// Size of `s` must be equal `trits_size(x)/3`
    ///
    pub fn to_str<'a>(&self) -> MamResult<String> {
        unsafe {
            let size = (self.size() / 3) as usize;

            // Alloc C memory
            let out: *mut c_char = libc::malloc(size * mem::size_of::<c_char>()) as *mut c_char;
            ffi::trits_to_str(self.c_trits, out);
            let result = CStr::from_ptr(out).to_str();

            match result {
                Ok(value) => {
                    let v = String::from_str(value).unwrap();

                    // Release memory created by libc::malloc
                    libc::free(out as *mut libc::c_void);

                    Ok(v)
                },
                Err(err) => Err(MamError::from(err)),
            }
        }
    }
}

impl<'a> From<&'a str> for Trits {
    ///
    /// Convert trytes from string.
    /// \note `trits_size(x)` must be multiple of 3.
    /// Size of `s` must be equal `trits_size(x)/3`.
    ///
    fn from(s: &'a str) -> Trits {
        let trits = Trits::new(3 * s.len());
        unsafe {
            ffi::trits_from_str(trits.c_trits, CString::new(s).unwrap().as_ptr());
        }
        trits
    }
}

impl Drop for Trits {
    fn drop(&mut self) {
        unsafe { ffi::trits_free(self.c_trits) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_size_of_trits() {
        let trits = Trits::from("NONCE9PK99");
        assert_eq!(30, trits.size());
    }

    #[test]
    fn can_create_trits_by_str() {
        let trits = Trits::from("NONCE9PK99");
        assert_eq!(trits.size(), 30);
    }

    #[test]
    fn convert_trits_to_str() {
        let trits = Trits::from("NONCE9PK99");
        assert_eq!("NONCE9PK99", trits.to_str().unwrap());
    }
}