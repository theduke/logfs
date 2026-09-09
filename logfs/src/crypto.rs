use std::num::NonZeroU32;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{AeadInOut, KeyInit},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ring::aead;
use sha2::Sha256;

use crate::{DataOffset, LogFsError, journal::NextEntryOffset};

#[derive(Clone)]
pub struct CryptoConfig {
    /// Password used by v3 Argon2id and the legacy-v2 compatibility reader.
    pub key: zeroize::Zeroizing<String>,
    /// Legacy-v2 PBKDF2 salt. V3 stores independent random salts in its roots.
    pub salt: zeroize::Zeroizing<Vec<u8>>,
    /// Legacy-v2 PBKDF2 iteration count. V3 uses the selected bounded profile.
    pub iterations: NonZeroU32,
    /// Named, bounded Argon2id profile used for v3 roots. This is supplied
    /// out-of-band and is also authenticated inside each root.
    pub profile: CryptoProfile,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CryptoProfile {
    /// 64 MiB, three passes, one lane.
    #[default]
    Standard,
    /// 8 MiB, three passes, one lane for memory-constrained deployments.
    LowMemory,
}

impl CryptoProfile {
    fn params(self) -> Params {
        let memory_kib = match self {
            Self::Standard => 64 * 1024,
            Self::LowMemory => 8 * 1024,
        };
        Params::new(memory_kib, 3, 1, Some(32))
            .expect("internal error: fixed Argon2id profile is invalid")
    }
}

impl std::fmt::Debug for CryptoConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoConfig")
            .field("key", &"*****")
            .field("salt", &"*****")
            .field("iterations", &"*****")
            .field("profile", &self.profile)
            .finish()
    }
}

pub struct Crypto {
    legacy_key: std::sync::OnceLock<aead::LessSafeKey>,
    legacy_salt: zeroize::Zeroizing<Vec<u8>>,
    legacy_iterations: NonZeroU32,
    password: zeroize::Zeroizing<String>,
    profile: CryptoProfile,
}

#[derive(Clone)]
pub(crate) struct V3Crypto {
    root_key: XChaCha20Poly1305,
    entry_key: XChaCha20Poly1305,
    checkpoint_key: XChaCha20Poly1305,
    history_key: zeroize::Zeroizing<[u8; 32]>,
}

#[derive(Clone)]
pub(crate) struct V3RootCrypto {
    keys: [XChaCha20Poly1305; 2],
}

impl Crypto {
    pub const EXTRA_PAYLOAD_LEN: usize = 16;

    pub fn new(config: CryptoConfig) -> Self {
        Self {
            legacy_key: std::sync::OnceLock::new(),
            legacy_salt: config.salt,
            legacy_iterations: config.iterations,
            password: config.key,
            profile: config.profile,
        }
    }

    fn legacy_key(&self) -> &aead::LessSafeKey {
        self.legacy_key.get_or_init(|| {
            let mut derived_key = zeroize::Zeroizing::new([0u8; ring::digest::SHA256_OUTPUT_LEN]);
            ring::pbkdf2::derive(
                ring::pbkdf2::PBKDF2_HMAC_SHA512,
                self.legacy_iterations,
                self.legacy_salt.as_slice(),
                self.password.as_bytes(),
                derived_key.as_mut(),
            );
            let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, derived_key.as_ref())
                .expect("internal error: invalid legacy key length");
            aead::LessSafeKey::new(unbound_key)
        })
    }

    pub(crate) fn profile(&self) -> CryptoProfile {
        self.profile
    }

    fn v3_root_key(&self, salt: &[u8; 16], slot: u8) -> Result<XChaCha20Poly1305, LogFsError> {
        let mut password_key = zeroize::Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, self.profile.params())
            .hash_password_into(self.password.as_bytes(), salt, password_key.as_mut())
            .map_err(|_| LogFsError::new_internal("Could not derive v3 root key"))?;
        let hkdf = Hkdf::<Sha256>::new(Some(b"logfs/v3/root"), password_key.as_ref());
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        hkdf.expand(&[slot], key.as_mut())
            .map_err(|_| LogFsError::new_internal("Could not separate v3 root key"))?;
        Ok(XChaCha20Poly1305::new_from_slice(key.as_ref())
            .expect("internal error: invalid XChaCha key length"))
    }

    pub(crate) fn v3_root_crypto(&self, salts: &[[u8; 16]; 2]) -> Result<V3RootCrypto, LogFsError> {
        Ok(V3RootCrypto {
            keys: [
                self.v3_root_key(&salts[0], 0)?,
                self.v3_root_key(&salts[1], 1)?,
            ],
        })
    }

    pub(crate) fn decrypt_v3_root<'a>(
        &self,
        salt: &[u8; 16],
        slot: u8,
        nonce: [u8; 24],
        ciphertext: &'a mut Vec<u8>,
    ) -> Result<&'a [u8], LogFsError> {
        self.v3_root_key(salt, slot)?
            .decrypt_in_place(&XNonce::from(nonce), &[slot], ciphertext)
            .map_err(|_| LogFsError::new_internal("Could not authenticate v3 root"))?;
        Ok(ciphertext.as_slice())
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
            .legacy_key()
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
        self.legacy_key()
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
        self.legacy_key()
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
            .legacy_key()
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
}

impl V3Crypto {
    pub(crate) fn new(log_secret: &[u8; 32]) -> Self {
        fn expand(secret: &[u8; 32], context: &[u8]) -> zeroize::Zeroizing<[u8; 32]> {
            let hkdf = Hkdf::<Sha256>::new(Some(b"logfs/v3/log-secret"), secret);
            let mut key = zeroize::Zeroizing::new([0u8; 32]);
            hkdf.expand(context, key.as_mut())
                .expect("internal error: valid HKDF output length");
            key
        }
        let entry = expand(log_secret, b"entry");
        let root = expand(log_secret, b"root");
        let checkpoint = expand(log_secret, b"checkpoint");
        Self {
            root_key: XChaCha20Poly1305::new_from_slice(root.as_ref())
                .expect("internal error: invalid root key length"),
            entry_key: XChaCha20Poly1305::new_from_slice(entry.as_ref())
                .expect("internal error: invalid entry key length"),
            checkpoint_key: XChaCha20Poly1305::new_from_slice(checkpoint.as_ref())
                .expect("internal error: invalid checkpoint key length"),
            history_key: expand(log_secret, b"history"),
        }
    }

    fn encrypt_with(
        key: &XChaCha20Poly1305,
        nonce: [u8; 24],
        aad: &[u8],
        data: &mut Vec<u8>,
    ) -> Result<(), LogFsError> {
        key.encrypt_in_place(&XNonce::from(nonce), aad, data)
            .map_err(|_| LogFsError::new_internal("Could not encrypt v3 record"))
    }

    fn decrypt_with<'a>(
        key: &XChaCha20Poly1305,
        nonce: [u8; 24],
        aad: &[u8],
        data: &'a mut Vec<u8>,
    ) -> Result<&'a [u8], LogFsError> {
        key.decrypt_in_place(&XNonce::from(nonce), aad, data)
            .map_err(|_| LogFsError::new_internal("Could not authenticate v3 record"))?;
        Ok(data.as_slice())
    }

    pub(crate) fn encrypt_entry(
        &self,
        nonce: [u8; 24],
        aad: &[u8],
        data: &mut Vec<u8>,
    ) -> Result<(), LogFsError> {
        Self::encrypt_with(&self.entry_key, nonce, aad, data)
    }

    pub(crate) fn encrypt_root(
        &self,
        nonce: [u8; 24],
        aad: &[u8],
        data: &mut Vec<u8>,
    ) -> Result<(), LogFsError> {
        Self::encrypt_with(&self.root_key, nonce, aad, data)
    }

    pub(crate) fn decrypt_root<'a>(
        &self,
        nonce: [u8; 24],
        aad: &[u8],
        data: &'a mut Vec<u8>,
    ) -> Result<&'a [u8], LogFsError> {
        Self::decrypt_with(&self.root_key, nonce, aad, data)
    }

    pub(crate) fn decrypt_entry<'a>(
        &self,
        nonce: [u8; 24],
        aad: &[u8],
        data: &'a mut Vec<u8>,
    ) -> Result<&'a [u8], LogFsError> {
        Self::decrypt_with(&self.entry_key, nonce, aad, data)
    }

    /// A repair scan expects almost every candidate to fail authentication.
    /// Avoid allocating an error/backtrace for each byte position examined.
    pub(crate) fn authenticate_entry_candidate(
        &self,
        nonce: [u8; 24],
        aad: &[u8],
        data: &mut Vec<u8>,
    ) -> bool {
        self.entry_key
            .decrypt_in_place(&XNonce::from(nonce), aad, data)
            .is_ok()
    }

    pub(crate) fn encrypt_checkpoint(
        &self,
        nonce: [u8; 24],
        aad: &[u8],
        data: &mut Vec<u8>,
    ) -> Result<(), LogFsError> {
        Self::encrypt_with(&self.checkpoint_key, nonce, aad, data)
    }

    pub(crate) fn decrypt_checkpoint<'a>(
        &self,
        nonce: [u8; 24],
        aad: &[u8],
        data: &'a mut Vec<u8>,
    ) -> Result<&'a [u8], LogFsError> {
        Self::decrypt_with(&self.checkpoint_key, nonce, aad, data)
    }

    pub(crate) fn commit_history(&self, fields: &[&[u8]]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(self.history_key.as_ref())
            .expect("internal error: valid HMAC key length");
        for field in fields {
            mac.update(field);
        }
        mac.finalize().into_bytes().into()
    }
}

impl V3RootCrypto {
    pub(crate) fn encrypt(
        &self,
        slot: usize,
        nonce: [u8; 24],
        data: &mut Vec<u8>,
    ) -> Result<(), LogFsError> {
        self.keys[slot]
            .encrypt_in_place(&XNonce::from(nonce), &[slot as u8], data)
            .map_err(|_| LogFsError::new_internal("Could not encrypt v3 root"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v3_keys_are_separated_by_file_and_purpose() {
        let first = V3Crypto::new(&[1; 32]);
        let second = V3Crypto::new(&[2; 32]);
        let nonce = [7; 24];
        let aad = b"authenticated framing";

        let mut first_entry = b"same plaintext".to_vec();
        first.encrypt_entry(nonce, aad, &mut first_entry).unwrap();
        let mut second_entry = b"same plaintext".to_vec();
        second.encrypt_entry(nonce, aad, &mut second_entry).unwrap();
        assert_ne!(first_entry, second_entry);

        let mut checkpoint = b"same plaintext".to_vec();
        first
            .encrypt_checkpoint(nonce, aad, &mut checkpoint)
            .unwrap();
        assert_ne!(first_entry, checkpoint);
        assert!(second.decrypt_entry(nonce, aad, &mut first_entry).is_err());
    }
}
