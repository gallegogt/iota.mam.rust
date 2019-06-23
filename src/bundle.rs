use ffi;
use std::ptr;

///
/// BundleTransaction
///
#[derive(Clone)]
pub struct BundleTransactions {
    c_bundle: *mut ffi::bundle_transactions_t,
}

impl BundleTransactions {
    ///
    /// Create new bundle transaction
    ///
    pub fn new() -> Self {
        unsafe {
            let mut bundle = ptr::null_mut();
            ffi::bundle_transactions_new(&mut bundle);

            BundleTransactions {
                c_bundle: bundle,
            }
        }
    }
    ///
    /// Into Raw Mut
    ///
    pub fn into_raw_mut(&mut self) -> *mut ffi::bundle_transactions_t {
        self.c_bundle
    }
}

impl Drop for BundleTransactions {
    fn drop(&mut self) {
        unsafe { ffi::bundle_transactions_free(&mut self.c_bundle) }
    }
}
