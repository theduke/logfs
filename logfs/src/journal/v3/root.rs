//! V3 root envelopes and explicit strict-versus-salvage bootstrap policy.
use super::{data, format::*};
use crate::{LogFsError, crypto::Crypto};
use sha2::Digest;
use std::io::{Read, Seek, SeekFrom};

#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct V3RootPayload {
    pub(super) magic: [u8; 16],
    pub(super) version: u32,
    pub(super) profile: crate::CryptoProfile,
    pub(super) identity: [u8; 16],
    pub(super) slot: u8,
    pub(super) generation: u64,
    pub(super) block: data::Superblock,
    pub(super) log_secret: [u8; 32],
    pub(super) root_salts: [[u8; 16]; 2],
    pub(super) history: [u8; 32],
    pub(super) checkpoint_history: [u8; 32],
}

impl Drop for V3RootPayload {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.log_secret.zeroize();
    }
}

fn decode_root(
    raw: &[u8],
    index: usize,
    crypto: Option<&Crypto>,
    base_offset: u64,
    file_end: u64,
    salvage: bool,
) -> Result<IndexedSuperBlock, LogFsError> {
    let salt: [u8; 16] = raw[..V3_ROOT_SALT_LEN]
        .try_into()
        .map_err(|_| LogFsError::new_internal("Truncated v3 root salt"))?;
    let nonce: [u8; 24] = raw[V3_ROOT_SALT_LEN..V3_ROOT_OUTER_LEN]
        .try_into()
        .map_err(|_| LogFsError::new_internal("Truncated v3 root nonce"))?;
    let clear = zeroize::Zeroizing::new(if let Some(crypto) = crypto {
        let mut ciphertext = zeroize::Zeroizing::new(raw[V3_ROOT_OUTER_LEN..].to_vec());
        crypto
            .decrypt_v3_root(&salt, index as u8, nonce, &mut ciphertext)?
            .to_vec()
    } else {
        let clear_end = V3_ROOT_RECORD_LEN - V3_PLAIN_METADATA_CHECKSUM_LEN;
        let actual: [u8; 32] = sha2::Sha256::digest(&raw[..clear_end]).into();
        if actual != raw[clear_end..] {
            return Err(LogFsError::new_internal("V3 root checksum mismatch"));
        }
        raw[V3_ROOT_OUTER_LEN..clear_end].to_vec()
    });
    let (payload_bytes, bootstrap_secret) = if crypto.is_some() {
        let log_secret = zeroize::Zeroizing::new(
            <[u8; 32]>::try_from(&clear[..32])
                .map_err(|_| LogFsError::new_internal("Truncated v3 root secret"))?,
        );
        let inner_nonce: [u8; 24] = clear[32..56]
            .try_into()
            .map_err(|_| LogFsError::new_internal("Truncated v3 inner root nonce"))?;
        let inner_len = u32::from_le_bytes(
            clear[56..60]
                .try_into()
                .map_err(|_| LogFsError::new_internal("Truncated v3 inner root"))?,
        ) as usize;
        if inner_len == 0 || inner_len > clear.len().saturating_sub(60) {
            return Err(LogFsError::new_internal("Invalid v3 inner root length"));
        }
        let mut inner = zeroize::Zeroizing::new(clear[60..60 + inner_len].to_vec());
        crate::crypto::V3Crypto::new(&log_secret).decrypt_root(
            inner_nonce,
            &[index as u8],
            &mut inner,
        )?;
        (inner, Some(log_secret))
    } else {
        let payload_len = u32::from_le_bytes(
            clear[..4]
                .try_into()
                .map_err(|_| LogFsError::new_internal("Truncated v3 root payload"))?,
        ) as usize;
        if payload_len == 0 || payload_len > clear.len().saturating_sub(4) {
            return Err(LogFsError::new_internal("Invalid v3 root payload length"));
        }
        (
            zeroize::Zeroizing::new(clear[4..4 + payload_len].to_vec()),
            None,
        )
    };
    let payload: V3RootPayload = crate::encoding::deserialize(&payload_bytes)?;
    if payload.magic != V3_INNER_MAGIC
        || payload.version != 3
        || payload.block.format_version != data::LogFormatVersion::V3
        || payload.slot as usize != index
        || payload.generation % 2 != index as u64
        || payload.identity == [0; 16]
        || bootstrap_secret
            .as_ref()
            .is_some_and(|secret| **secret != payload.log_secret)
        || payload.root_salts[index] != salt
        || crypto.is_some_and(|crypto| payload.profile != crypto.profile())
    {
        return Err(LogFsError::new_internal("Invalid authenticated v3 root"));
    }
    let format = RootFormat::V3 {
        identity: payload.identity,
        generation: payload.generation,
        log_secret: zeroize::Zeroizing::new(payload.log_secret),
        root_salts: payload.root_salts,
        history: payload.history,
        checkpoint_history: payload.checkpoint_history,
    };
    super::read::validate_root(
        &payload.block,
        &format,
        base_offset,
        if salvage { u64::MAX } else { file_end },
    )?;

    Ok(IndexedSuperBlock {
        block: payload.block.clone(),
        index,
        format,
    })
}

pub(super) fn read_roots<R: Read + Seek>(
    reader: &mut R,
    base_offset: u64,
    file_end: u64,
    crypto: Option<&Crypto>,
    salvage: bool,
) -> Result<IndexedSuperBlock, LogFsError> {
    let mut parsed = Vec::new();
    for index in 0..V3_ROOT_COUNT as usize {
        let candidate = (|| {
            let absolute = base_offset
                .checked_add(index as u64 * V3_ROOT_SLOT_SIZE)
                .ok_or_else(|| LogFsError::new_internal("V3 root offset overflow"))?;
            if absolute
                .checked_add(V3_ROOT_SLOT_SIZE)
                .is_none_or(|end| end > file_end)
            {
                return Err(LogFsError::new_internal("Truncated v3 root slot"));
            }
            reader.seek(SeekFrom::Start(absolute))?;
            let mut raw = zeroize::Zeroizing::new(vec![0; V3_ROOT_RECORD_LEN]);
            reader.read_exact(&mut raw)?;
            decode_root(&raw, index, crypto, base_offset, file_end, salvage)
        })();
        match candidate {
            Ok(root) => parsed.push(root),
            Err(error) if salvage => {
                tracing::warn!(slot = index, %error, "Ignoring unusable v3 root during explicit salvage")
            }
            Err(error) => return Err(error),
        }
    }
    if parsed.len() == 2 {
        match (&parsed[0].format, &parsed[1].format) {
            (
                RootFormat::V3 {
                    identity: a,
                    log_secret: sa,
                    root_salts: ra,
                    generation: ga,
                    ..
                },
                RootFormat::V3 {
                    identity: b,
                    log_secret: sb,
                    root_salts: rb,
                    generation: gb,
                    ..
                },
            ) if a == b && sa.as_ref() == sb.as_ref() && ra == rb && ga.abs_diff(*gb) == 1 => {}
            _ => {
                return Err(LogFsError::new_internal(
                    "V3 root pair has inconsistent identity, salts, or generations",
                ));
            }
        }
    }
    if salvage {
        tracing::warn!(
            valid_roots = parsed.len(),
            "Explicit salvage authenticates individual records; latest committed state is uncertain"
        );
    }
    parsed
        .into_iter()
        .max_by_key(|root| match &root.format {
            RootFormat::V3 { generation, .. } => *generation,
            RootFormat::LegacyV2 => 0,
        })
        .ok_or_else(|| LogFsError::new_internal("Could not authenticate any v3 root for recovery"))
}

pub(super) fn encode_root(
    block: &IndexedSuperBlock,
    crypto: Option<&Crypto>,
    v3_crypto: Option<&crate::crypto::V3Crypto>,
    root_crypto: Option<&crate::crypto::V3RootCrypto>,
) -> Result<Vec<u8>, LogFsError> {
    use ring::rand::SecureRandom;
    let RootFormat::V3 {
        identity,
        generation,
        log_secret,
        root_salts,
        history,
        checkpoint_history,
    } = &block.format
    else {
        return Err(LogFsError::ReadOnly);
    };
    let payload = zeroize::Zeroizing::new(crate::encoding::serialize(&V3RootPayload {
        magic: V3_INNER_MAGIC,
        version: 3,
        profile: crypto.map(Crypto::profile).unwrap_or_default(),
        identity: *identity,
        slot: u8::try_from(block.index)
            .map_err(|_| LogFsError::new_internal("V3 root slot overflow"))?,
        generation: *generation,
        block: block.block.clone(),
        log_secret: **log_secret,
        root_salts: *root_salts,
        history: *history,
        checkpoint_history: *checkpoint_history,
    })?);
    let encrypted = crypto.is_some();
    let clear_len = if encrypted {
        V3_ROOT_CLEAR_LEN
    } else {
        V3_ROOT_RECORD_LEN - V3_ROOT_OUTER_LEN - V3_PLAIN_METADATA_CHECKSUM_LEN
    };
    let required_clear = if encrypted {
        60usize
            .checked_add(payload.len())
            .and_then(|length| length.checked_add(Crypto::EXTRA_PAYLOAD_LEN))
    } else {
        4usize.checked_add(payload.len())
    };
    if required_clear.is_none_or(|required| required > clear_len) {
        return Err(LogFsError::new_internal("V3 root payload is too large"));
    }
    let random = ring::rand::SystemRandom::new();
    let mut buffer = vec![0u8; V3_ROOT_RECORD_LEN];
    buffer[..V3_ROOT_SALT_LEN].copy_from_slice(&root_salts[block.index]);
    let mut nonce = [0u8; V3_NONCE_LEN];
    random
        .fill(&mut nonce)
        .map_err(|_| LogFsError::new_internal("Could not generate v3 root nonce"))?;
    buffer[V3_ROOT_SALT_LEN..V3_ROOT_OUTER_LEN].copy_from_slice(&nonce);
    let mut clear = zeroize::Zeroizing::new(vec![0u8; clear_len]);
    if !encrypted {
        random
            .fill(&mut clear)
            .map_err(|_| LogFsError::new_internal("Could not randomize v3 root padding"))?;
    }
    if encrypted {
        let mut inner_nonce = [0u8; 24];
        random
            .fill(&mut inner_nonce)
            .map_err(|_| LogFsError::new_internal("Could not generate separated v3 root nonce"))?;
        let mut inner = payload;
        v3_crypto
            .ok_or_else(|| LogFsError::new_internal("Missing v3 log-secret key"))?
            .encrypt_root(inner_nonce, &[block.index as u8], &mut inner)?;
        clear[..32].copy_from_slice(log_secret.as_ref());
        clear[32..56].copy_from_slice(&inner_nonce);
        clear[56..60].copy_from_slice(
            &u32::try_from(inner.len())
                .map_err(|_| LogFsError::new_internal("V3 inner root overflow"))?
                .to_le_bytes(),
        );
        clear[60..60 + inner.len()].copy_from_slice(&inner);
        root_crypto
            .ok_or_else(|| LogFsError::new_internal("Missing v3 root key"))?
            .encrypt(block.index, nonce, &mut clear)?;
        buffer[V3_ROOT_OUTER_LEN..].copy_from_slice(&clear);
    } else {
        clear[..4].copy_from_slice(
            &u32::try_from(payload.len())
                .map_err(|_| LogFsError::new_internal("V3 root payload overflow"))?
                .to_le_bytes(),
        );
        clear[4..4 + payload.len()].copy_from_slice(&payload);
        let clear_end = V3_ROOT_OUTER_LEN + clear.len();
        buffer[V3_ROOT_OUTER_LEN..clear_end].copy_from_slice(&clear);
        let hash: [u8; 32] = sha2::Sha256::digest(&buffer[..clear_end]).into();
        buffer[clear_end..].copy_from_slice(&hash);
    }
    Ok(buffer)
}
#[derive(Debug)]
pub(in crate::journal) struct IndexedSuperBlock {
    pub(in crate::journal) block: data::Superblock,
    pub(in crate::journal) index: usize,
    pub(in crate::journal) format: RootFormat,
}

#[derive(Clone)]
pub(in crate::journal) enum RootFormat {
    LegacyV2,
    V3 {
        identity: [u8; 16],
        generation: u64,
        log_secret: zeroize::Zeroizing<[u8; 32]>,
        root_salts: [[u8; 16]; 2],
        history: [u8; 32],
        checkpoint_history: [u8; 32],
    },
}

impl std::fmt::Debug for RootFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LegacyV2 => formatter.write_str("LegacyV2"),
            Self::V3 {
                identity,
                generation,
                history,
                checkpoint_history,
                ..
            } => formatter
                .debug_struct("V3")
                .field("identity", identity)
                .field("generation", generation)
                .field("log_secret", &"*****")
                .field("root_salts", &"*****")
                .field("history", history)
                .field("checkpoint_history", checkpoint_history)
                .finish(),
        }
    }
}

pub(super) fn v3_entry_start(_base_offset: u64) -> Result<u64, LogFsError> {
    Ok(V3_HEADER_SIZE)
}

impl RootFormat {
    pub(in crate::journal) fn entry_start(&self, base_offset: u64) -> Result<u64, LogFsError> {
        match self {
            Self::LegacyV2 => Ok(data::Superblock::HEADER_SIZE),
            Self::V3 { .. } => v3_entry_start(base_offset),
        }
    }

    pub(super) fn root_offset(&self, _base_offset: u64, index: usize) -> Result<u64, LogFsError> {
        let index = u64::try_from(index)
            .map_err(|_| LogFsError::new_internal("Root slot index overflow"))?;
        match self {
            Self::LegacyV2 => index
                .checked_mul(data::Superblock::SERIALIZED_LEN)
                .ok_or_else(|| LogFsError::new_internal("Root slot offset overflow")),
            Self::V3 { .. } => index
                .checked_mul(V3_ROOT_SLOT_SIZE)
                .ok_or_else(|| LogFsError::new_internal("Root slot offset overflow")),
        }
    }
}
