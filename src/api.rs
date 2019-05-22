use crate::channel::Channel;
use crate::endpoint::Endpoint;
use crate::errors::{MamError, MamResult};
use crate::psk::{Psk, PskSet};
use crate::trits::Trits;
use crate::types::{Trint18, Trint9, Trit, Tryte};
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
    pub fn new(mam_seed: &Tryte) -> MamResult<Self> {
        unsafe {
            let mut c_api: ffi::mam_api_t = mem::uninitialized();
            let rc = ffi::mam_api_init(&mut c_api, mam_seed);

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
    pub fn add_trusted_channel_pk(&mut self, pk: &Tryte) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_add_trusted_channel_pk(&mut self.c_api, pk);

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
    pub fn add_trusted_endpoint_pk(&mut self, pk: &Tryte) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_add_trusted_endpoint_pk(&mut self.c_api, pk);

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
    pub fn add_ntru_sk(&mut self, ntru_sk: &ffi::mam_ntru_sk_t) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_add_ntru_sk(&mut self.c_api, ntru_sk);

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
    pub fn create_channel(&mut self, height: usize) -> MamResult<Tryte> {
        unsafe {
            let mut channel_id: Tryte = 0;
            let rc = ffi::mam_api_create_channel(&mut self.c_api, height, &mut channel_id);

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }

            Ok(channel_id)
        }
    }

    ///
    /// Gets a channel from its id
    ///
    /// channel_id - The channel id [in]
    ///
    /// return a pointer to the channel or NULL if not found
    ///
    pub fn get_channel(&mut self, channel_id: &Tryte) -> Channel {
        unsafe {
            let c_channel = ffi::mam_api_get_channel(&mut self.c_api, channel_id);

            Channel::from(*c_channel)
        }
    }

    ///
    /// Creates and adds an endpoint to the API
    ///
    /// height - The endpoint's MSS height [in]
    /// channel_id - The associated channel id [in]
    ///
    pub fn create_endpoint(&mut self, height: usize, channel_id: &Tryte) -> MamResult<Tryte> {
        unsafe {
            let mut endpoint_id: Tryte = 0;
            let rc =
                ffi::mam_api_create_endpoint(&mut self.c_api, height, channel_id, &mut endpoint_id);

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }
            Ok(endpoint_id)
        }
    }

    ///
    /// Gets an endpoint from its id
    ///
    /// channel_id - The associated channel id [in]
    /// endpoint_id - The endpoint id [in]
    ///
    /// return a pointer to the endpoint or NULL if not found
    ///
    pub fn get_endpoint(&mut self, channel_id: &Tryte, endpoint_id: &Tryte) -> Endpoint {
        unsafe {
            let c_endpoint = ffi::mam_api_get_endpoint(&mut self.c_api, channel_id, endpoint_id);

            Endpoint::from(*c_endpoint)
        }
    }

    ///
    /// Creates a MAM tag that can be used in IOTA transactions
    ///
    /// tag - The tag [out]
    /// msg_id - The message ID [in]
    /// ord - The packet ord [in]
    ///
    pub fn write_tag(&self, tag: &mut Trit, msg_id: &Trit, ord: Trint18) {
        unsafe { ffi::mam_api_write_tag(tag, msg_id, ord) }
    }

    ///
    /// Writes MAM header on a channel(keyloads (session keys) + potential packet)
    /// into a bundle
    ///
    /// ch_id - A known channel ID [in]
    /// psks - pre shared keys used for encrypting the session keys [in]
    /// ntru_pks - ntru public keys used for encrypting the session keys [in]
    /// msg_type_id - The message type [in]
    /// bundle - The bundle that the packet will be written into [out]
    /// msg_id - The msg_id (hashed channel_name and message index within the
    ///     channel) embedded into transaction's tag (together with packet index to
    ///     allow Tangle lookup) [out]
    pub fn bundle_write_header_on_channel(
        &mut self,
        ch_id: &Tryte,
        psks: &PskSet,
        ntru_pks: ffi::mam_ntru_pk_t_set_t,
        msg_type_id: Trint9,
        bundle: &mut ffi::bundle_transactions_t,
        msg_id: &mut Trit,
    ) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_bundle_write_header_on_channel(
                &mut self.c_api,
                ch_id,
                *psks.into_raw(),
                ntru_pks,
                msg_type_id,
                bundle,
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
        ch_id: &Tryte,
        ep_id: &Tryte,
        psks: &PskSet,
        ntru_pks: ffi::mam_ntru_pk_t_set_t,
        msg_type_id: Trint9,
        bundle: &mut ffi::bundle_transactions_t,
        msg_id: &mut Trit,
    ) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_bundle_write_header_on_endpoint(
                &mut self.c_api,
                ch_id,
                ep_id,
                *psks.into_raw(),
                ntru_pks,
                msg_type_id,
                bundle,
                msg_id,
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
    /// msg_type_id - The message type [in]
    /// bundle - The bundle that the packet will be written into [out]
    /// msg_id - The msg_id (hashed channel_name and message index within the
    ///     channel) embedded into transaction's tag (together with packet index to
    ///     allow Tangle lookup) [out]
    pub fn bundle_announce_new_channel(
        &mut self,
        ch_id: &Tryte,
        ch1_id: &Tryte,
        psks: &PskSet,
        ntru_pks: ffi::mam_ntru_pk_t_set_t,
        msg_type_id: Trint9,
        bundle: &mut ffi::bundle_transactions_t,
        msg_id: &mut Trit,
    ) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_bundle_announce_new_channel(
                &mut self.c_api,
                ch_id,
                ch1_id,
                *psks.into_raw(),
                ntru_pks,
                msg_type_id,
                bundle,
                msg_id,
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
    /// msg_type_id - The message type [in]
    /// bundle - The bundle that the packet will be written into [out]
    /// msg_id - The msg_id (hashed channel_name and message index within the
    ///     channel) embedded into transaction's tag (together with packet index to
    ///     allow Tangle lookup) [out]
    pub fn bundle_announce_new_endpoint(
        &mut self,
        ch_id: &Tryte,
        ep1_id: &Tryte,
        psks: &PskSet,
        ntru_pks: ffi::mam_ntru_pk_t_set_t,
        msg_type_id: Trint9,
        bundle: &mut ffi::bundle_transactions_t,
        msg_id: &mut Trit,
    ) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_bundle_announce_new_endpoint(
                &mut self.c_api,
                ch_id,
                ep1_id,
                *psks.into_raw(),
                ntru_pks,
                msg_type_id,
                bundle,
                msg_id,
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
        msg_id: &Trit,
        payload: &Tryte,
        payload_size: usize,
        checksum: &ffi::mam_msg_checksum_t,
        is_last_packet: bool,
        bundle: &mut ffi::bundle_transactions_t,
    ) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_bundle_write_packet(
                &mut self.c_api,
                msg_id,
                payload,
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
    /// packet_payload - First packet payload [out] (will be allocated if  packet is present)
    ///
    pub fn bundle_read(
        &mut self,
        msg_id: &Trit,
        payload: *mut *mut Tryte,
        payload_size: &mut usize,
        checksum: &ffi::mam_msg_checksum_t,
        is_last_packet: &mut bool,
        bundle: &ffi::bundle_transactions_t,
    ) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_bundle_read(
                &mut self.c_api,
                bundle,
                payload,
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
    ///
    pub fn serialize(&self, buffer: &mut Trits) {
        unsafe { ffi::mam_api_serialize(&self.c_api, buffer.into_raw_mut()) }
    }

    ///
    /// Deserializes a buffer into API struct
    ///
    /// buffer - The buffer to serialize the api into [out]
    ///
    pub fn deserialize(buffer: &mut Trits) -> MamResult<Api> {
        unsafe {
            let mut c_api: ffi::mam_api_t = mem::uninitialized();
            let rc = ffi::mam_api_deserialize(buffer.into_raw_mut(), &mut c_api);

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
    pub fn save<'a>(&self, filename: &'a str) -> MamResult<()> {
        unsafe {
            let rc = ffi::mam_api_save(&self.c_api, CString::new(filename).unwrap().as_ptr());

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
    pub fn load<'a>(filename: &'a str) -> MamResult<Api> {
        unsafe {
            let mut c_api: ffi::mam_api_t = mem::uninitialized();
            let rc = ffi::mam_api_load(CString::new(filename).unwrap().as_ptr(), &mut c_api);

            if rc != ffi::retcode_t_RC_OK {
                return Err(MamError::from(rc));
            }

            Ok(Api { c_api: c_api })
        }
    }
}

impl Drop for Api {
    fn drop(&mut self) {
        unsafe {
            ffi::mam_api_destroy(&mut self.c_api);
        }
    }
}
