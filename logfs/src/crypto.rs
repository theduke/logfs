use std::num::NonZeroU32;

use ring::aead;

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

        Self { key: aead_key }
    }

    /// Build the decryption nonce for a `JournalEntry` with the given
    /// sequence.
    /// Note that the nonce will have a suffix of 0u32.
    fn build_entry_nonce(sequence: u64) -> aead::Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..8].copy_from_slice(&sequence.to_le_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        nonce
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
        buffer: &'a mut Vec<u8>,
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
        let data_nonce = Self::build_data_nonce(sequence, chunk_index)?;
        let aad = aead::Aad::from(&[]);
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
        let nonce = Self::build_data_nonce(sequence, chunk_index)?;
        let slice = self
            .key
            .open_in_place(nonce, aead::Aad::from(&[]), data)
            .map_err(|_| LogFsError::new_internal("Could not decrypt data"))?;
        Ok(slice)
    }

    pub fn decrypt_data(
        &self,
        sequence: u64,
        chunk_index: u32,
        mut data: Vec<u8>,
    ) -> Result<Vec<u8>, LogFsError> {
        let full_length = data.len();
        let nonce = Self::build_data_nonce(sequence, chunk_index)?;
        self.key
            .open_in_place(nonce, aead::Aad::from(&[]), data.as_mut_slice())
            .map_err(|_| LogFsError::new_internal("Could not decrypt data"))?;
        // Need to truncate data to actual length without the tag.
        data.truncate(full_length - self.extra_payload_len() as usize);
        Ok(data)
    }
}
