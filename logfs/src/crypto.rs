use std::num::NonZeroU32;

use ring::{aead, hkdf};

use crate::{DataOffset, LogFsError, journal::NextEntryOffset};

#[derive(Clone)]
pub struct CryptoConfig {
    pub key: zeroize::Zeroizing<String>,
    pub salt: zeroize::Zeroizing<Vec<u8>>,
    pub iterations: NonZeroU32,
}

impl std::fmt::Debug for CryptoConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoConfig")
            .field("key", &"*****")
            .field("seed", &"*****")
            .field("iterations", &"*****")
            .finish()
    }
}

pub struct Crypto {
    key: aead::LessSafeKey,
    master_key: zeroize::Zeroizing<[u8; ring::digest::SHA256_OUTPUT_LEN]>,
}

pub(crate) struct V3Crypto {
    root_key: aead::LessSafeKey,
    entry_key: aead::LessSafeKey,
}

impl Crypto {
    pub const EXTRA_PAYLOAD_LEN: usize = 16;

    pub fn new(config: CryptoConfig) -> Self {
        // Derive a via pbkdf2 key derivation.
        let mut derived_key = [0u8; ring::digest::SHA256_OUTPUT_LEN];

        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA512,
            config.iterations,
            config.salt.as_slice(),
            config.key.as_bytes(),
            &mut derived_key,
        );

        // NOTE: this can only fail if the key has an invalid length, for
        // the chosen algorithm, so it can't actually happen without
        // a programming mistake (as in: wrong size of `derived_key`).
        // So .expect() can be used without worries.
        let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &derived_key)
            .expect("Internal error: invalid key");
        let aead_key = aead::LessSafeKey::new(unbound_key);

        Self {
            key: aead_key,
            master_key: zeroize::Zeroizing::new(derived_key),
        }
    }

    pub(crate) fn v3_crypto(&self, identity: [u8; 16]) -> V3Crypto {
        V3Crypto {
            root_key: self.derive_v3_key(identity, b"logfs/v3.1/root"),
            entry_key: self.derive_v3_key(identity, b"logfs/v3.1/entry"),
        }
    }

    fn derive_v3_key(&self, identity: [u8; 16], purpose: &'static [u8]) -> aead::LessSafeKey {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &identity);
        let prk = salt.extract(self.master_key.as_ref());
        let info = [purpose];
        let okm = prk
            .expand(&info, &aead::CHACHA20_POLY1305)
            .expect("internal error: invalid v3 HKDF output length");
        let mut derived = zeroize::Zeroizing::new([0u8; ring::digest::SHA256_OUTPUT_LEN]);
        okm.fill(derived.as_mut())
            .expect("internal error: invalid v3 HKDF output length");
        let key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, derived.as_ref())
            .expect("internal error: invalid v3 AEAD key length");
        aead::LessSafeKey::new(key)
    }

    /// Build the decryption nonce for a `JournalEntry` with the given
    /// sequence.
    /// Note that the nonce will have a suffix of 0u32.
    fn build_entry_nonce(sequence: u64) -> aead::Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..8].copy_from_slice(&sequence.to_le_bytes());
        aead::Nonce::assume_unique_for_key(nonce_bytes)
    }

    /// Build the decryption nonce for a chunk of the raw data of a given
    /// `JournalEntry`.
    /// The chunk index must start at 1!.
    fn build_data_nonce(sequence: u64, chunk_index: u32) -> Result<aead::Nonce, LogFsError> {
        // if chunk_index < 1 {
        //     return Err(LogFsError::new_internal(
        //         "Internal error: Invalid chunk index 0",
        //     ));
        // }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..8].copy_from_slice(&sequence.to_le_bytes());
        nonce_bytes[8..12].copy_from_slice(&chunk_index.to_le_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        Ok(nonce)
    }

    pub fn decrypt_entry<'a>(
        &self,
        sequence: u64,
        header_data: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<(&'a [u8], NextEntryOffset), LogFsError> {
        let nonce = Self::build_entry_nonce(sequence);
        let aad = aead::Aad::from(header_data);
        let data = self
            .key
            .open_in_place(nonce, aad, buffer)
            .map(|x| &*x)
            .map_err(|_| LogFsError::new_internal("Could not decrypt journal entry"))?;
        Ok((data, self.extra_payload_len() as usize))
    }

    /// Additional size that is added to encrypted data.
    pub fn extra_payload_len(&self) -> DataOffset {
        aead::CHACHA20_POLY1305.tag_len() as u64
    }

    pub fn encrypt_entry(
        &self,
        sequence: u64,
        header_data: &[u8],
        data: &mut Vec<u8>,
    ) -> Result<(), LogFsError> {
        let nonce = Self::build_entry_nonce(sequence);
        let aad = aead::Aad::from(header_data);
        self.key
            .seal_in_place_append_tag(nonce, aad, data)
            .map_err(|_| LogFsError::new_internal("Could not encrypt journal entry"))?;
        Ok(())
    }

    pub fn encrypt_data(
        &self,
        sequence: u64,
        chunk_index: u32,
        data: &mut Vec<u8>,
    ) -> Result<(), LogFsError> {
        self.encrypt_data_with_aad(sequence, chunk_index, &[], data)
    }

    pub(crate) fn encrypt_data_with_aad(
        &self,
        sequence: u64,
        chunk_index: u32,
        aad: &[u8],
        data: &mut Vec<u8>,
    ) -> Result<(), LogFsError> {
        let data_nonce = Self::build_data_nonce(sequence, chunk_index)?;
        let aad = aead::Aad::from(aad);
        self.key
            .seal_in_place_append_tag(data_nonce, aad, data)
            .map_err(|_| LogFsError::new_internal("Could not encrypt journal entry"))
    }

    pub fn decrypt_data_ref<'a>(
        &self,
        sequence: u64,
        chunk_index: u32,
        data: &'a mut [u8],
    ) -> Result<&'a [u8], LogFsError> {
        self.decrypt_data_ref_with_aad(sequence, chunk_index, &[], data)
    }

    pub(crate) fn decrypt_data_ref_with_aad<'a>(
        &self,
        sequence: u64,
        chunk_index: u32,
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a [u8], LogFsError> {
        let nonce = Self::build_data_nonce(sequence, chunk_index)?;
        let slice = self
            .key
            .open_in_place(nonce, aead::Aad::from(aad), data)
            .map_err(|_| LogFsError::new_internal("Could not decrypt data"))?;
        Ok(slice)
    }

    pub fn decrypt_data(
        &self,
        sequence: u64,
        chunk_index: u32,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, LogFsError> {
        self.decrypt_data_with_aad(sequence, chunk_index, &[], data)
    }

    pub(crate) fn decrypt_data_with_aad(
        &self,
        sequence: u64,
        chunk_index: u32,
        aad: &[u8],
        mut data: Vec<u8>,
    ) -> Result<Vec<u8>, LogFsError> {
        let full_length = data.len();
        self.decrypt_data_ref_with_aad(sequence, chunk_index, aad, data.as_mut_slice())?;
        // Need to truncate data to actual length without the tag.
        data.truncate(full_length - self.extra_payload_len() as usize);
        Ok(data)
    }

    pub(crate) fn encrypt_with_nonce(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        data: &mut Vec<u8>,
    ) -> Result<(), LogFsError> {
        self.key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                data,
            )
            .map_err(|_| LogFsError::new_internal("Could not encrypt v3 root"))
    }

    pub(crate) fn decrypt_with_nonce<'a>(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a [u8], LogFsError> {
        self.key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                data,
            )
            .map(|data| &*data)
            .map_err(|_| LogFsError::new_internal("Could not decrypt v3 root"))
    }
}

impl V3Crypto {
    pub(crate) fn encrypt_root(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        data: &mut Vec<u8>,
    ) -> Result<(), LogFsError> {
        self.root_key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                data,
            )
            .map_err(|_| LogFsError::new_internal("Could not encrypt v3 root"))
    }

    pub(crate) fn decrypt_root<'a>(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a [u8], LogFsError> {
        self.root_key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                data,
            )
            .map(|data| &*data)
            .map_err(|_| LogFsError::new_internal("Could not decrypt v3 root"))
    }

    pub(crate) fn encrypt_entry(
        &self,
        domain: u64,
        chunk: u32,
        aad: &[u8],
        data: &mut Vec<u8>,
    ) -> Result<(), LogFsError> {
        let nonce = Crypto::build_data_nonce(domain, chunk)?;
        self.entry_key
            .seal_in_place_append_tag(nonce, aead::Aad::from(aad), data)
            .map_err(|_| LogFsError::new_internal("Could not encrypt v3 entry"))
    }

    pub(crate) fn decrypt_entry_ref<'a>(
        &self,
        domain: u64,
        chunk: u32,
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Result<&'a [u8], LogFsError> {
        let nonce = Crypto::build_data_nonce(domain, chunk)?;
        self.entry_key
            .open_in_place(nonce, aead::Aad::from(aad), data)
            .map(|data| &*data)
            .map_err(|_| LogFsError::new_internal("Could not decrypt v3 entry"))
    }

    pub(crate) fn decrypt_entry(
        &self,
        domain: u64,
        chunk: u32,
        aad: &[u8],
        mut data: Vec<u8>,
    ) -> Result<Vec<u8>, LogFsError> {
        let full_length = data.len();
        self.decrypt_entry_ref(domain, chunk, aad, &mut data)?;
        data.truncate(full_length - Crypto::EXTRA_PAYLOAD_LEN);
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crypto() -> Crypto {
        Crypto::new(CryptoConfig {
            key: "password".to_owned().into(),
            salt: b"salt".to_vec().into(),
            iterations: NonZeroU32::new(1).unwrap(),
        })
    }

    #[test]
    fn v3_keys_are_separated_by_file_and_purpose() {
        let crypto = crypto();
        let first = crypto.v3_crypto([1; 16]);
        let second = crypto.v3_crypto([2; 16]);
        let mut nonce = [0; 12];
        nonce[..8].copy_from_slice(&7u64.to_le_bytes());
        nonce[8..].copy_from_slice(&2u32.to_le_bytes());
        let aad = b"authenticated framing";

        let mut first_entry = b"same plaintext".to_vec();
        first.encrypt_entry(7, 2, aad, &mut first_entry).unwrap();
        let mut second_entry = b"same plaintext".to_vec();
        second.encrypt_entry(7, 2, aad, &mut second_entry).unwrap();
        assert_ne!(first_entry, second_entry);

        let mut root = b"same plaintext".to_vec();
        first.encrypt_root(nonce, aad, &mut root).unwrap();
        assert_ne!(first_entry, root);
        assert!(second.decrypt_entry(7, 2, aad, first_entry).is_err());
    }
}
