use crate::errors::{MamError, MamResult};
use crate::prng::Prng;
use crate::spongos::Spongos;
use crate::trits::Trits;
use ffi;
use std::mem;

///
/// Leaves have height `0`,
/// root has height `D`; `0 <= d < D`; `D <=* 20
///
pub type MssMtHeight = ffi::mss_mt_height_t;
///
///  Index (skn) of leaf/node on the level of height `d`; 0 <= i <"
///  2^(D-d).
///
pub type MssMtIdx = ffi::mss_mt_idx_t;
///
/// MAM MSS
///
#[derive(Clone)]
pub struct Mss {
    c_mss: ffi::mam_mss_t,
}

impl Mss {
    ///
    /// Allocate memory for internal Merkle tree structure.
    ///
    /// @param prng [in] PRNG interface
    /// @param sponge [in] Sponge interface
    /// @param height [in] Merkle-tree height
    /// @param nonce1 [in] first nonce
    /// @param nonce2 [in] second nonce
    ///
    pub fn new(
        prng: &mut Prng,
        height: MssMtHeight,
        nonce1: Trits,
        nonce2: Trits,
        nonce3: Trits,
        nonce4: Trits,
    ) -> MamResult<Self> {
        unsafe {
            let mut c_mss: ffi::mam_mss_t = mem::uninitialized();
            let rc = ffi::mam_mss_create(&mut c_mss, height);

            if rc != ffi::retcode_t_RC_OK {
                ffi::mam_mss_destroy(&mut c_mss);
                return Err(MamError::from(rc));
            }

            ffi::mam_mss_init(
                &mut c_mss,
                prng.into_raw_mut(),
                height,
                nonce1.into_raw(),
                nonce2.into_raw(),
                nonce3.into_raw(),
                nonce4.into_raw(),
            );

            Ok(Mss { c_mss: c_mss })
        }
    }

    ///
    /// Generate MSS keys, stores current and next auth_path
    ///
    pub fn gen(&mut self) {
        unsafe { ffi::mam_mss_gen(&mut self.c_mss) }
    }

    ///
    /// Encodes mss height and current sk index
    ///
    /// trists_skn [out] encoded height and current private key number
    ///
    pub fn skn(&self, trists_skn: &Trits) {
        unsafe { ffi::mam_mss_skn(&self.c_mss, trists_skn.into_raw()) }
    }

    ///
    /// Gets the authentication path
    ///
    /// skn [in] number of WOTS instance (current pk index), in traversal mode
    ///     this parameter is not used because current authentication path is always
    ///     updated
    ///
    ///  path [out] authentication path
    ///
    pub fn auth_path(&mut self, skn: MssMtIdx, path: Trits) {
        unsafe { ffi::mam_mss_auth_path(&mut self.c_mss, skn, path.into_raw()) }
    }

    /// Signs a hash
    ///
    /// @param hash [in] the hash to sign on
    /// @param sig [out] the signature
    ///
    pub fn sign(&mut self, hash: &Trits, sig: &Trits) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_mss_sign(&mut self.c_mss, hash.into_raw(), sig.into_raw());
            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(())
        }
    }
    /// Signs a hash and advances skn
    ///
    /// @param hash [in] the hash to sign on
    /// @param sig [out] the signature
    ///
    pub fn sign_and_next(&mut self, hash: &Trits, sig: &Trits) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_mss_sign_and_next(&mut self.c_mss, hash.into_raw(), sig.into_raw());
            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(())
        }
    }

    /// Advances skn
    ///
    pub fn next(&mut self) -> bool {
        unsafe { ffi::mam_mss_next(&mut self.c_mss) }
    }

    ///
    /// Returns the number of remaining secret keys (unused leaves on merkle tree)
    ///
    pub fn remaining_sks(&self) -> usize {
        unsafe { ffi::mam_mss_num_remaining_sks(&self.c_mss) }
    }

    ///
    /// Verifies MSS signature.
    ///
    /// mt_spongos [in] Spongos interface to hash Merkle Tree
    /// hash [in] signed hash value
    /// sig [in] signature
    /// [in] public key (Merkle-tree root)
    ///
    pub fn verify(mt_spongos: &mut Spongos, hash: &Trits, sig: &Trits, pk: Trits) -> bool {
        unsafe {
            ffi::mam_mss_verify(
                mt_spongos.into_raw_mut(),
                hash.into_raw(),
                sig.into_raw(),
                pk.into_raw(),
            )
        }
    }

    ///
    /// returns The size of a serialized Merkle tree.
    ///
    pub fn serialized_size(&self) -> usize {
        unsafe { ffi::mam_mss_serialized_size(&self.c_mss) }
    }

    ///
    /// Serialize Merkle tree.
    ///
    pub fn serialize(&mut self, buffer: &mut Trits) {
        unsafe { ffi::mam_mss_serialize(&mut self.c_mss, buffer.into_raw_mut()) }
    }

    ///
    /// Deerialize Merkle tree.
    ///
    pub fn deserialize(buffer: &mut Trits, mss: &mut Mss) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_mss_deserialize(buffer.into_raw_mut(), mss.into_raw_mut());
            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(())
        }
    }
    ///
    /// Return the C raw info
    ///
    pub fn into_raw_mut(&mut self) -> &mut ffi::mam_mss_t {
        &mut self.c_mss
    }

    ///
    /// Return the C raw info
    ///
    pub fn into_raw(&self) -> ffi::mam_mss_t {
        self.c_mss
    }
}

impl Drop for Mss {
    fn drop(&mut self) {
        unsafe {
            ffi::mam_mss_destroy(&mut self.c_mss);
        }
    }
}
