use ffi;
use std::ptr;

///
/// BundleTransaction
///
#[derive(Clone)]
pub struct BundleTransactions {
    pub c_bundle: ffi::bundle_transactions_t,
}

impl BundleTransactions {
    ///
    /// Create new bundle transaction
    ///
    pub fn new() -> Self {
        unsafe {
            let mut bundle = ptr::null_mut();
            ffi::bundle_transactions_new(&mut bundle);

            BundleTransactions { c_bundle: *bundle }
        }
    }

    ///
    /// Into Raw Mut
    ///
    pub fn into_raw_mut(&mut self) -> &mut ffi::bundle_transactions_t {
        &mut self.c_bundle
    }

    pub fn size(&self) -> u32 {
        self.c_bundle.i
    }
}

impl Drop for BundleTransactions {
    fn drop(&mut self) {
        println!("Drop for BundleTransactions");
        unsafe {
            let mut cb: *mut ffi::bundle_transactions_t = &mut self.c_bundle;
            ffi::bundle_transactions_free(&mut cb)
        }
    }
}
