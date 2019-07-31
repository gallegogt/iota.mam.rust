use crate::bundle::BundleTransactions;
use crate::constants::{CHANNEL_ID_TRYTE_SIZE, ENDPOINT_ID_TRYTE_SIZE};
use crate::converter::ascii_trytes_to_trytes;
use crate::errors::{MamError, MamResult};
use crate::ntru::{NtruPkSet, NtruSk};
use crate::psk::{Psk, PskSet};
use crate::trits::Trits;
use crate::types::{Trint18, Trit, Tryte};

use std::ffi::CString;

use ffi;
use std::mem;

///
/// MAM API
///
#[derive(Clone)]
pub struct Api {
    c_api: ffi::mam_api_t,
}

impl Api {
    ///
    /// Initialize an API
    ///
    /// mam_seed - The seed for PRNG initialization [in]
    ///
    pub fn new(mam_seed: &[Tryte]) -> MamResult<Self> {
        unsafe {
            let mut c_api: ffi::mam_api_t = mem::uninitialized();
            let rc = ffi::mam_api_init(&mut c_api, mam_seed.as_ptr());

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }

            Ok(Self { c_api: c_api })
        }
    }

    ///
    /// Add a trusted channel id into the api's trusted channels set
    ///
    /// pk A new public key [in]
    ///
    pub fn add_trusted_channel_pk(&mut self, pk: &[Tryte]) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_add_trusted_channel_pk(&mut self.c_api, pk.as_ptr());

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(())
        }
    }

    ///
    /// Add a trusted endpoint id into the api's trusted endpoints set
    ///
    /// pk - A new public key [in]
    ///
    pub fn add_trusted_endpoint_pk(&mut self, pk: &[Tryte]) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_add_trusted_endpoint_pk(&mut self.c_api, pk.as_ptr());

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(())
        }
    }

    ///
    /// Add a NTRU secret key to api's NTRU sks set
    ///
    /// ntru_sk - A new ntru public key (allows for both enc/dec) [in]
    ///
    pub fn add_ntru_sk(&mut self, ntru_sk: &NtruSk) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_add_ntru_sk(&mut self.c_api, ntru_sk.into_raw());

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(())
        }
    }

    ///
    /// Add a NTRU public key to api's NTRU pks set
    ///
    /// ntru_pk - A new ntru public key (allows for encryption only) [in]
    ///
    pub fn add_ntru_pk(&mut self, ntru_sk: &ffi::mam_ntru_pk_t) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_add_ntru_pk(&mut self.c_api, ntru_sk);

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(())
        }
    }

    ///
    /// Add a pre shared key to api's psks set
    ///
    /// psk - A new psk [in]
    ///
    pub fn add_psk(&mut self, psk: &Psk) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_add_psk(&mut self.c_api, psk.into_raw());

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(())
        }
    }

    ///
    /// Creates and adds a channel to the API
    ///
    /// height - The channel's MSS height [in]
    ///
    pub fn channel_create(&mut self, height: usize) -> MamResult<[Tryte; CHANNEL_ID_TRYTE_SIZE]> {
        unsafe {
            let mut channel_id: [Tryte; CHANNEL_ID_TRYTE_SIZE] = [57; CHANNEL_ID_TRYTE_SIZE];
            let rc = ffi::mam_api_channel_create(&mut self.c_api, height, channel_id.as_mut_ptr());
            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(channel_id)
        }
    }

    ///
    /// Returns the number of remaining secret keys of a channel
    ///
    /// api - The API
    /// channel_id - The channel id
    ///
    pub fn channel_remaining_sks(&mut self, channel_id: &[Tryte]) -> usize {
        unsafe { ffi::mam_api_channel_remaining_sks(&mut self.c_api, channel_id.as_ptr()) }
    }
    ///
    /// Returns the number of remaining secret keys of an endpoint
    ///
    /// api - The API
    /// channel_id - The associated channel id
    /// endpoint_id - The endpoint id
    ///
    pub fn endpoint_remaining_sks(&mut self, channel_id: &[Tryte], endpoint_id: &[Tryte]) -> usize {
        unsafe {
            ffi::mam_api_endpoint_remaining_sks(
                &mut self.c_api,
                channel_id.as_ptr(),
                endpoint_id.as_ptr(),
            )
        }
    }

    ///
    /// Creates and adds an endpoint to the API
    ///
    /// height - The endpoint's MSS height [in]
    /// channel_id - The associated channel id [in]
    ///
    pub fn create_endpoint(
        &mut self,
        height: usize,
        channel_id: &[Tryte],
    ) -> MamResult<[Tryte; ENDPOINT_ID_TRYTE_SIZE]> {
        unsafe {
            let mut endpoint_id: [Tryte; ENDPOINT_ID_TRYTE_SIZE] = [57; ENDPOINT_ID_TRYTE_SIZE];
            let rc = ffi::mam_api_endpoint_create(
                &mut self.c_api,
                height,
                channel_id.as_ptr(),
                endpoint_id.as_mut_ptr(),
            );
            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(endpoint_id)
        }
    }

    ///
    /// Creates a MAM tag that can be used in IOTA transactions
    ///
    /// tag - The tag [out]
    /// msg_id - The message ID [in]
    /// ord - The packet ord [in]
    ///
    pub fn write_tag(&self, tag: &mut [Trit], msg_id: &[Trit], ord: Trint18) {
        unsafe { ffi::mam_api_write_tag(tag.as_mut_ptr(), msg_id.as_ptr(), ord) }
    }

    ///
    /// Writes MAM header on a channel(keyloads (session keys) + potential packet)
    /// into a bundle
    ///
    /// ch_id - A known channel ID [in]
    /// psks - pre shared keys used for encrypting the session keys [in]
    /// ntru_pks - ntru public keys used for encrypting the session keys [in]
    /// bundle - The bundle that the packet will be written into [out]
    /// msg_id - The msg_id (hashed channel_name and message index within the
    ///     channel) embedded into transaction's tag (together with packet index to
    ///     allow Tangle lookup) [out]
    pub fn bundle_write_header_on_channel(
        &mut self,
        ch_id: &[Tryte],
        psks: &PskSet,
        ntru_pks: &NtruPkSet,
        bundle: &mut BundleTransactions,
        msg_id: &mut Trit,
    ) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_bundle_write_header_on_channel(
                &mut self.c_api,
                ch_id.as_ptr(),
                psks.into_raw(),
                ntru_pks.into_raw(),
                bundle.into_raw_mut(),
                msg_id,
            );

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(())
        }
    }

    ///
    /// Writes MAM header on an endpoint(keyloads (session keys) + potential packet)
    /// into a bundle
    ///
    /// ch_id - A known channel ID [in]
    /// ep_id - A known endpoint ID [in]
    /// psks - pre shared keys used for encrypting the session keys [in]
    /// ntru_pks - ntru public keys used for encrypting the session keys [in]
    /// msg_type_id - The message type [in]
    /// bundle - The bundle that the packet will be written into [out]
    /// msg_id - The msg_id (hashed channel_name and message index within the
    ///     channel) embedded into transaction's tag (together with packet index to
    ///     allow Tangle lookup) [out]
    pub fn bundle_write_header_on_endpoint(
        &mut self,
        ch_id: &[Tryte],
        ep_id: &[Tryte],
        psks: &PskSet,
        ntru_pks: &NtruPkSet,
        bundle: &mut BundleTransactions,
        msg_id: &mut [Trit],
    ) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_bundle_write_header_on_endpoint(
                &mut self.c_api,
                ch_id.as_ptr(),
                ep_id.as_ptr(),
                psks.into_raw(),
                ntru_pks.into_raw(),
                bundle.into_raw_mut(),
                msg_id.as_mut_ptr(),
            );

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(())
        }
    }

    ///
    /// Writes an announcement of a new channel (keyloads (session keys) +
    /// potential packet) into a bundle
    ///
    /// ch_id - A known channel ID [in]
    /// ch1_id - The new channel ID [in]
    /// psks - pre shared keys used for encrypting the session keys [in]
    /// ntru_pks - ntru public keys used for encrypting the session keys [in]
    /// bundle - The bundle that the packet will be written into [out]
    /// msg_id - The msg_id (hashed channel_name and message index within the
    ///     channel) embedded into transaction's tag (together with packet index to
    ///     allow Tangle lookup) [out]
    pub fn bundle_announce_channel(
        &mut self,
        ch_id: &[Tryte],
        ch1_id: &[Tryte],
        psks: &PskSet,
        ntru_pks: &NtruPkSet,
        bundle: &mut BundleTransactions,
        msg_id: &mut [Trit],
    ) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_bundle_announce_channel(
                &mut self.c_api,
                ch_id.as_ptr(),
                ch1_id.as_ptr(),
                psks.into_raw(),
                ntru_pks.into_raw(),
                bundle.into_raw_mut(),
                msg_id.as_mut_ptr(),
            );

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(())
        }
    }

    ///
    /// Writes an announcement of a new endpoint (keyloads (session keys) +
    /// potential packet) into a bundle
    ///
    /// ch_id - A known channel ID [in]
    /// ep1_id - The new channel ID [in]
    /// psks - pre shared keys used for encrypting the session keys [in]
    /// ntru_pks - ntru public keys used for encrypting the session keys [in]
    /// bundle - The bundle that the packet will be written into [out]
    /// msg_id - The msg_id (hashed channel_name and message index within the
    ///     channel) embedded into transaction's tag (together with packet index to
    ///     allow Tangle lookup) [out]
    pub fn bundle_announce_new_endpoint(
        &mut self,
        ch_id: &[Tryte],
        ep1_id: &[Tryte],
        psks: &PskSet,
        ntru_pks: &NtruPkSet,
        bundle: &mut BundleTransactions,
        msg_id: &mut [Trit],
    ) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_bundle_announce_endpoint(
                &mut self.c_api,
                ch_id.as_ptr(),
                ep1_id.as_ptr(),
                psks.into_raw(),
                ntru_pks.into_raw(),
                bundle.into_raw_mut(),
                msg_id.as_mut_ptr(),
            );

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(())
        }
    }

    ///
    /// Writes MAM packet into a bundle
    ///
    /// msg_id - The msg_id
    /// payload - payload to write into the packet [in]
    /// payload size - The payload size [in]
    /// is_last_packet - indicate whether or not this is the last packet [in]
    /// msg_type_id - The message type [in]
    /// bundle - The bundle that the packet will be written into [out]
    ///
    pub fn bundle_write_packet(
        &mut self,
        msg_id: &[Trit],
        payload: &[Tryte],
        payload_size: usize,
        checksum: &ffi::mam_msg_checksum_t,
        is_last_packet: bool,
        bundle: &mut ffi::bundle_transactions_t,
    ) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_bundle_write_packet(
                &mut self.c_api,
                msg_id.as_ptr(),
                payload.as_ptr(),
                payload_size,
                *checksum,
                is_last_packet,
                bundle,
            );

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(())
        }
    }

    ///
    /// Reads MAM's session key and potentially the first packet using NTRU secret key
    ///
    /// bundle - The bundle containing the MAM message
    ///packet_payload - First packet payload [out] (will be allocated if  packet is present)
    ///
    pub fn bundle_read(
        &mut self,
        bundle: &ffi::bundle_transactions_t,
        payload: &mut [Tryte],
        payload_size: &mut usize,
        is_last_packet: &mut bool,
    ) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_bundle_read(
                &mut self.c_api,
                bundle,
                &mut payload.as_mut_ptr(),
                payload_size,
                is_last_packet,
            );

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(())
        }
    }

    ///
    /// Gets the number of trits needed for an API serialization
    ///
    pub fn serialized_size(&mut self) -> usize {
        unsafe { ffi::mam_api_serialized_size(&mut self.c_api) }
    }

    ///
    /// Serializes an API struct into a buffer
    ///
    /// buffer - The buffer to serialize the api into [out]
    /// encr_key_trytes - The encryption key [in] (optional - can set null)
    /// encr_key_trytes_size - The encryption key size[in]
    ///
    pub fn serialize(
        &self,
        buffer: &mut [Trit],
        encr_key_trytes: &[Tryte],
        encr_key_trytes_size: usize,
    ) {
        unsafe {
            ffi::mam_api_serialize(
                &self.c_api,
                buffer.as_mut_ptr(),
                encr_key_trytes.as_ptr(),
                encr_key_trytes_size,
            )
        }
    }

    ///
    /// Deserializes a buffer into API struct
    ///
    /// buffer - The buffer to serialize the api into [in]
    /// buffer_size - The size of the buffer [in]
    /// encr_key_trytes - The encryption key [in] (optional - can set null)
    /// encr_key_trytes_size - The encryption key size[in]
    ///
    pub fn deserialize(
        buffer: &[Trit],
        buffer_size: usize,
        encr_key_trytes: &[Tryte],
        encr_key_trytes_size: usize,
    ) -> MamResult<Api> {
        unsafe {
            let mut c_api: ffi::mam_api_t = mem::uninitialized();
            let rc = ffi::mam_api_deserialize(
                buffer.as_ptr(),
                buffer_size,
                &mut c_api,
                encr_key_trytes.as_ptr(),
                encr_key_trytes_size,
            );

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }

            Ok(Api { c_api: c_api })
        }
    }

    ///
    /// Saves an API into a file
    ///
    /// filename - The file name where to serialize the API into [in]
    ///
    pub fn save<'a>(
        &self,
        filename: &'a str,
        encr_key_trytes: &[Tryte],
        encr_key_trytes_size: usize,
    ) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_save(
                &self.c_api,
                CString::new(filename).unwrap().as_ptr(),
                encr_key_trytes.as_ptr(),
                encr_key_trytes_size,
            );

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }

            Ok(())
        }
    }

    ///
    /// Loads an API into a file
    ///
    /// @param filename - The file name where the API is serialized [in]
    ///
    pub fn load<'a>(
        filename: &'a str,
        encr_key_trytes: &[Tryte],
        encr_key_trytes_size: usize,
    ) -> MamResult<Api> {
        unsafe {
            let mut c_api: ffi::mam_api_t = mem::uninitialized();
            let rc = ffi::mam_api_load(
                CString::new(filename).unwrap().as_ptr(),
                &mut c_api,
                encr_key_trytes.as_ptr(),
                encr_key_trytes_size,
            );

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }

            Ok(Api { c_api: c_api })
        }
    }

    ///
    ///
    ///
    pub fn into_raw_mut(&mut self) -> &mut ffi::mam_api_t {
        &mut self.c_api
    }

    ///
    /// Gen NTRU SK
    ///
    pub fn gen_ntru_sk(&self, nonce: Trits) -> NtruSk {
        NtruSk::gen(&self.c_api.prng, &nonce)
    }

    pub fn gen_pks<'a>(&self, id: &'a str, nonce: &'a str) -> MamResult<Psk> {
        let trytes_id = ascii_trytes_to_trytes(id);
        let trytes_nonce = ascii_trytes_to_trytes(nonce);

        Psk::gen(
            &self.c_api.prng,
            &trytes_id,
            &trytes_nonce,
            trytes_nonce.len(),
        )
    }
}

impl Drop for Api {
    fn drop(&mut self) {
        unsafe {
            ffi::mam_api_destroy(&mut self.c_api);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;
    use crate::converter::ascii_trytes_to_trytes;
    use crate::trits::*;
    use std::error::Error;

    const API_SEED: &'static str =
        "APISEEDAPISEEDAPISEEDAPISEEDAPISEEDAPISEEDAPISEEDAPISEEDAPISEEDAPISEEDAPISEEDAPI9";
    const TEST_NTRU_NONCE: &'static str = "NTRUBNONCE";
    const TEST_PRE_SHARED_KEY_A_STR: &'static str = "PSKIDAPSKIDAPSKIDAPSKIDAPSK";
    const TEST_PRE_SHARED_KEY_A_NONCE_STR: &'static str = "PSKANONCE";
    const TEST_PRE_SHARED_KEY_B_STR: &'static str = "PSKIDBPSKIDBPSKIDBPSKIDBPSK";
    const TEST_PRE_SHARED_KEY_B_NONCE_STR: &'static str = "PSKBNONCE";

    #[test]
    fn check_init_api() {
        let s: Vec<i8> = ascii_trytes_to_trytes(API_SEED);
        let api = Api::new(&s);

        match api {
            Ok(_) => assert_eq!(true, true),
            Err(e) => {
                println!("Error: {}", e);
                assert_eq!(false, true)
            }
        }
    }

    #[test]
    fn check_save_load_wrong_key() {
        let s: Vec<i8> = ascii_trytes_to_trytes(API_SEED);
        let api = Api::new(&s).unwrap();
        let eck_trytes =
            "NOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLM";
        let encryption_key_trytes = ascii_trytes_to_trytes(eck_trytes);

        let result = api.save(
            "mam-api.bin",
            &encryption_key_trytes,
            encryption_key_trytes.len(),
        );
        match result {
            Ok(_) => assert_eq!(true, true),
            Err(e) => {
                println!("Error: {}", e);
                assert_eq!(true, false)
            }
        }

        let dck_trytes =
            "MOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLMNOPQRSTUVWXYZ9ABCDEFGHIJKLM";
        let decryption_key_trytes = ascii_trytes_to_trytes(dck_trytes);

        let n_api = Api::load(
            "mam-api.bin",
            &decryption_key_trytes,
            encryption_key_trytes.len(),
        );
        match n_api {
            Ok(_) => assert_eq!(true, false),
            Err(e) => {
                println!("Error: {}", e);
                assert_eq!(true, true);
            }
        }
    }

    #[test]
    fn check_api_create_channels() {
        let s: Vec<i8> = ascii_trytes_to_trytes(API_SEED);
        let mut api = Api::new(&s).unwrap();
        let depth = 6;
        match api.channel_create(depth) {
            Ok(ref channel_id) => {
                let v = api.channel_remaining_sks(channel_id);
                assert_eq!(v, 64);

                match api.create_endpoint(depth, channel_id) {
                    Ok(_) => {
                        assert_eq!(true, true);
                    }
                    Err(e) => {
                        assert_eq!(true, false, "{}", e.description());
                    }
                }

                match api.create_endpoint(depth, channel_id) {
                    Ok(_) => {
                        assert_eq!(true, true);
                    }
                    Err(e) => {
                        assert_eq!(true, false, "{}", e.description());
                    }
                }
            }
            Err(e) => {
                println!("+++ Error => {}", e);
                assert!(true, false);
            }
        }
    }

    #[test]
    fn check_api_generic() {
        let s: Vec<i8> = ascii_trytes_to_trytes(API_SEED);
        let mut sender_api = Api::new(&s).unwrap();
        // Create Channel ID
        let depth = 6;
        let ch_id = sender_api.channel_create(depth).unwrap();
        let ch1_id = sender_api.channel_create(depth).unwrap();
        let ep_id = sender_api.create_endpoint(depth, &ch_id).unwrap();

        let mut msg_id: [Trit; MAM_MSG_ID_SIZE] = [0; MAM_MSG_ID_SIZE];
        let ntru_nonce = Trits::from(TEST_NTRU_NONCE);

        let ntru = sender_api.gen_ntru_sk(ntru_nonce);
        match sender_api.add_ntru_sk(&ntru) {
            Ok(_) => assert_eq!(true, true),
            Err(e) => {
                println!("{:?}", e);
                assert_eq!(true, false)
            }
        };
        let pska = sender_api
            .gen_pks(TEST_PRE_SHARED_KEY_A_STR, TEST_PRE_SHARED_KEY_A_NONCE_STR)
            .unwrap();
        let pskb = sender_api
            .gen_pks(TEST_PRE_SHARED_KEY_B_STR, TEST_PRE_SHARED_KEY_B_NONCE_STR)
            .unwrap();

        match sender_api.add_psk(&pskb) {
            Ok(_) => assert_eq!(true, true),
            Err(e) => {
                println!("{:?}", e);
                assert_eq!(true, false)
            }
        };

        for pubkey in 0..4 {
            for keyload in 0..3 {
                for checksum in 0..3 {
                    let mut bundle = BundleTransactions::new();
                    let mut pks_set = PskSet::new();
                    let mut ntru_pk_set = NtruPkSet::new();

                    if keyload == ffi::mam_msg_keyload_e_MAM_MSG_KEYLOAD_PSK {
                        pks_set.add(&pska).unwrap();
                        pks_set.add(&pskb).unwrap();
                    } else if keyload == ffi::mam_msg_keyload_e_MAM_MSG_KEYLOAD_NTRU {
                        ntru_pk_set.add(&ntru.public_key()).unwrap();
                    }

                    if pubkey == ffi::mam_msg_pubkey_e_MAM_MSG_PUBKEY_CHID {
                        println!(
                            "Pass bf bundle size {} pkset {}",
                            bundle.size(),
                            pks_set.size()
                        );
                        match sender_api.bundle_write_header_on_endpoint(
                            &ch_id,
                            &ep_id,
                            &pks_set,
                            &ntru_pk_set,
                            &mut bundle,
                            &mut msg_id,
                        ) {
                            Ok(_) => assert_eq!(true, true),
                            Err(e) => {
                                println!("Error: {:?}", e);
                                assert_eq!(true, false);
                            }
                        };
                        println!("Pass");
                    } else if pubkey == ffi::mam_msg_pubkey_e_MAM_MSG_PUBKEY_CHID1 {
                        let remaining_sks = sender_api.channel_remaining_sks(&ch_id);
                        sender_api
                            .bundle_announce_channel(
                                &ch_id,
                                &ch1_id,
                                &pks_set,
                                &ntru_pk_set,
                                &mut bundle,
                                &mut msg_id,
                            )
                            .unwrap();

                        assert_eq!(remaining_sks - 1, sender_api.channel_remaining_sks(&ch_id));

                        println!("Pass");
                    }
                }
            }
        }

        // ntru.gen(sender_api.into_raw_mut().prng, nonce: Trits)
    }
}
