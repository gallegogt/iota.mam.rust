use std::convert::From;
use std::error;
use std::ffi::CStr;
use std::fmt;
use std::io;
use std::str;
use std::str::Utf8Error;
// use std::os::raw::c_char;

use ffi;

// Gets the string associated with the error code from the C lib.
pub(crate) fn error_message<'a>(rc: ffi::retcode_t) -> String {
    unsafe {
        CStr::from_ptr(ffi::error_2_string(rc))
            .to_string_lossy()
            .to_string()
    }
}

/// An MAM Error
pub struct MamError {
    repr: ErrorRepr,
}

/// The possible error types
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum ErrorKind {
    /// General Failure
    General,
    /// Operation failed because of a type mismatch.
    TypeError,
    /// I/O Error
    IoError,
}

/// The internal representations of the error
#[derive(Debug)]
enum ErrorRepr {
    WithDescription(ErrorKind, i32, String),
    WithDescriptionAndDetail(ErrorKind, i32, &'static str, String),
    IoError(io::Error),
}

impl From<io::Error> for MamError {
    /// Create an MamError from an I/O error
    fn from(err: io::Error) -> MamError {
        MamError {
            repr: ErrorRepr::IoError(err),
        }
    }
}

impl From<Utf8Error> for MamError {
    /// Create an MamError from a UTF error
    fn from(_: Utf8Error) -> MamError {
        MamError {
            repr: ErrorRepr::WithDescription(ErrorKind::TypeError, -1, "Invalid UTF-8".to_owned()),
        }
    }
}

impl From<ffi::retcode_t> for MamError {
    /// Create an MamError from a ffi::retcode_t error
    fn from(rc: ffi::retcode_t) -> MamError {
        MamError {
            repr: ErrorRepr::WithDescription(ErrorKind::General, rc as i32, error_message(rc)),
        }
    }
}

impl From<(ErrorKind, &'static str)> for MamError {
    fn from((kind, desc): (ErrorKind, &'static str)) -> MamError {
        MamError {
            repr: ErrorRepr::WithDescription(kind, -1, desc.to_owned()),
        }
    }
}

impl From<(ErrorKind, ffi::retcode_t, &'static str)> for MamError {
    fn from((kind, err, desc): (ErrorKind, ffi::retcode_t, &'static str)) -> MamError {
        MamError {
            repr: ErrorRepr::WithDescription(kind, err as i32, desc.to_owned()),
        }
    }
}

impl From<(ErrorKind, &'static str, String)> for MamError {
    fn from((kind, desc, detail): (ErrorKind, &'static str, String)) -> MamError {
        MamError {
            repr: ErrorRepr::WithDescriptionAndDetail(kind, -1, desc, detail),
        }
    }
}

impl<S> From<(ErrorKind, i32, &'static str, S)> for MamError
where
    S: Into<String>,
{
    fn from((kind, err, desc, detail): (ErrorKind, i32, &'static str, S)) -> MamError {
        MamError {
            repr: ErrorRepr::WithDescriptionAndDetail(kind, err, desc, detail.into()),
        }
    }
}

/// MAM Errors implement the std::error::Error trait
impl error::Error for MamError {
    /// A short description of the error.
    /// This should not contain newlines or explicit formatting.
    fn description(&self) -> &str {
        match self.repr {
            ErrorRepr::WithDescription(_, _, ref desc) => desc.as_str(),
            ErrorRepr::WithDescriptionAndDetail(_, _, desc, _) => desc,
            ErrorRepr::IoError(ref err) => err.description(),
        }
    }

    /// The lower-level cause of the error, if any.
    fn cause(&self) -> Option<&error::Error> {
        match self.repr {
            ErrorRepr::IoError(ref err) => Some(err as &error::Error),
            _ => None,
        }
    }
}

impl fmt::Display for MamError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match &self.repr {
            ErrorRepr::WithDescription(_, _err, desc) => desc.fmt(f),
            ErrorRepr::WithDescriptionAndDetail(_, _, desc, ref detail) => {
                desc.fmt(f)?;
                f.write_str(": ")?;
                detail.fmt(f)
            }
            ErrorRepr::IoError(ref err) => err.fmt(f),
        }
    }
}

impl fmt::Debug for MamError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        fmt::Display::fmt(self, f)
    }
}

/// Generic result for the entire public API
pub type MamResult<T> = Result<T, MamError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_error_message_invocation() {
        let message = error_message(ffi::retcode_t_RC_ERROR);
        assert_eq!(message.len(), 5);
    }
}
