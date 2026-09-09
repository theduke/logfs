use std::{num::NonZeroU32, path::PathBuf};

use logfs::{
    ConfigBuilder, CryptoConfig, CryptoProfile, LogConfig, LogFormatVersion, LogOpenOptions,
};
use objstore::{ObjStoreError, Result};
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LogFsCryptoConfig {
    /// Encryption password. This may be populated after parsing a URL so the
    /// secret does not need to be embedded in it.
    #[serde(default)]
    pub key: Option<String>,
    /// Legacy-v2 PBKDF2 salt. V3 reads its random salts from the root slots.
    #[serde(default, with = "serde_bytes")]
    pub salt: Option<Vec<u8>>,
    /// Legacy-v2 PBKDF2 iteration count. V3 uses `profile` instead.
    #[serde(default)]
    pub iterations: Option<NonZeroU32>,
    /// Out-of-band Argon2id profile used for encrypted v3 roots.
    #[serde(default)]
    pub profile: CryptoProfile,
}

impl LogFsCryptoConfig {
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: Some(key.into()),
            ..Self::default()
        }
    }

    pub fn into_crypto(self) -> Option<CryptoConfig> {
        let key = self.key?;
        Some(CryptoConfig {
            key: Zeroizing::new(key),
            // The core compatibility config still has required legacy fields.
            // These placeholders are unreachable for explicitly selected v2;
            // v3 ignores them and reads independently generated salts on disk.
            salt: Zeroizing::new(self.salt.unwrap_or_default()),
            iterations: self.iterations.unwrap_or(NonZeroU32::MIN),
            profile: self.profile,
        })
    }
}

impl Default for LogFsCryptoConfig {
    fn default() -> Self {
        Self {
            key: None,
            salt: None,
            iterations: None,
            profile: CryptoProfile::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LogFsObjStoreConfig {
    pub path: PathBuf,
    /// Required on-disk log format. When omitted, LogFS auto-detects it.
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default)]
    pub allow_create: bool,
    #[serde(default)]
    pub raw_mode: bool,
    pub offset: Option<u64>,
    #[serde(default)]
    pub readonly: bool,
    pub default_chunk_size: Option<u32>,
    pub partial_index_write_interval: Option<u64>,
    pub full_index_write_interval: Option<u64>,
    pub crypto: Option<LogFsCryptoConfig>,
}

impl LogFsObjStoreConfig {
    pub const URI_SCHEME: &'static str = "logfs";

    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            version: None,
            allow_create: false,
            raw_mode: false,
            offset: None,
            readonly: false,
            default_chunk_size: None,
            partial_index_write_interval: None,
            full_index_write_interval: None,
            crypto: None,
        }
    }

    pub fn with_allow_create(mut self, allow: bool) -> Self {
        self.allow_create = allow;
        self
    }

    pub fn with_version(mut self, version: impl Into<Option<u32>>) -> Self {
        self.version = version.into();
        self
    }

    pub fn with_readonly(mut self, readonly: bool) -> Self {
        self.readonly = readonly;
        self
    }

    pub fn with_offset(mut self, offset: impl Into<Option<u64>>) -> Self {
        self.offset = offset.into();
        self
    }

    pub fn with_raw_mode(mut self, raw: bool) -> Self {
        self.raw_mode = raw;
        self
    }

    pub fn with_default_chunk_size(mut self, chunk_size: Option<u32>) -> Self {
        self.default_chunk_size = chunk_size;
        self
    }

    pub fn with_crypto(mut self, crypto: LogFsCryptoConfig) -> Self {
        self.crypto = Some(crypto);
        self
    }

    pub(crate) fn to_logfs_config(&self) -> LogConfig {
        let mut builder = ConfigBuilder::new(self.path.clone());
        if self.raw_mode {
            builder = builder.raw_mode();
        }
        builder = builder.offset(self.offset);
        if self.allow_create {
            builder = builder.allow_create();
        }
        if let Some(ref crypto) = self.crypto {
            if let Some(crypto) = crypto.clone().into_crypto() {
                builder = builder.crypto(crypto);
            }
        }
        if let Some(chunk_size) = self.default_chunk_size {
            builder = builder.default_chunk_size(chunk_size);
        }
        if let Some(full_interval) = self.full_index_write_interval {
            builder = builder.full_index_write_interval(full_interval);
        }
        let readonly = self.readonly || (self.requires_create_for_writes() && !self.allow_create);
        builder = builder.readonly(readonly);

        let mut config = builder.build();
        if let Some(partial_interval) = self.partial_index_write_interval {
            config.partial_index_write_interval = partial_interval;
        }
        config
    }

    pub(crate) fn to_logfs_open_options(&self) -> Result<LogOpenOptions> {
        if self.crypto.as_ref().is_some_and(|crypto| {
            crypto.key.is_none() && (crypto.salt.is_some() || crypto.iterations.is_some())
        }) {
            return Err(ObjStoreError::InvalidConfig {
                message: "crypto salt and iterations require a key".to_string(),
                source: None,
            });
        }
        if self.version == Some(2)
            && self.crypto.as_ref().is_some_and(|crypto| {
                crypto.key.is_some() && (crypto.salt.is_none() || crypto.iterations.is_none())
            })
        {
            return Err(ObjStoreError::InvalidConfig {
                message: "encrypted v2 requires salt and iterations".to_string(),
                source: None,
            });
        }
        let format_version = match self.version {
            None => None,
            Some(2) => Some(LogFormatVersion::V2),
            Some(3) => Some(LogFormatVersion::V3),
            Some(version) => {
                return Err(ObjStoreError::InvalidConfig {
                    message: format!("unsupported log format version '{version}': expected 2 or 3"),
                    source: None,
                });
            }
        };
        Ok(LogOpenOptions {
            format_version,
            ..LogOpenOptions::default()
        })
    }

    fn requires_create_for_writes(&self) -> bool {
        self.offset.is_some() || path_is_block_device(&self.path)
    }

    pub fn safe_uri(&self) -> Result<Url> {
        let path = if self.path.is_absolute() {
            self.path.clone()
        } else {
            std::env::current_dir()
                .map_err(|source| ObjStoreError::Io {
                    operation: objstore::Operation::Build,
                    source: Some(source.into()),
                })?
                .join(&self.path)
        };
        let file_url = Url::from_file_path(&path).map_err(|_| ObjStoreError::InvalidConfig {
            message: format!(
                "failed to construct file url from path '{}': path must be absolute",
                path.display()
            ),
            source: None,
        })?;
        let file_str = file_url.to_string();
        let safe_str = file_str
            .strip_prefix("file:")
            .map(|rest| format!("{}:{}", Self::URI_SCHEME, rest))
            .ok_or_else(|| ObjStoreError::InvalidConfig {
                message: "expected file:// URL for path".to_string(),
                source: None,
            })?;
        let mut url = Url::parse(&safe_str).map_err(|source| ObjStoreError::InvalidConfig {
            message: "failed to parse logfs safe URI".to_string(),
            source: Some(source.into()),
        })?;
        if self.version.is_some() || self.offset.is_some() || self.crypto.is_some() {
            let mut query = url.query_pairs_mut();
            if let Some(version) = self.version {
                query.append_pair("version", &version.to_string());
            }
            if let Some(offset) = self.offset {
                query.append_pair("offset", &offset.to_string());
            }
            if let Some(crypto) = &self.crypto {
                query.append_pair("profile", crypto_profile_name(crypto.profile));
            }
        }
        Ok(url)
    }

    pub fn from_url(url: &Url) -> Result<Self> {
        if url.scheme() != Self::URI_SCHEME {
            return Err(ObjStoreError::InvalidConfig {
                message: format!(
                    "invalid scheme: expected '{}', got '{}'",
                    Self::URI_SCHEME,
                    url.scheme()
                ),
                source: None,
            });
        }

        let prefix = format!("{}:", Self::URI_SCHEME);
        let file_str = url
            .as_str()
            .strip_prefix(&prefix)
            .map(|rest| format!("file:{rest}"))
            .ok_or_else(|| ObjStoreError::InvalidConfig {
                message: format!("invalid logfs url: expected '{prefix}' prefix"),
                source: None,
            })?;
        let file_url = Url::parse(&file_str).map_err(|source| ObjStoreError::InvalidConfig {
            message: "failed to parse translated file url".to_string(),
            source: Some(source.into()),
        })?;
        let path = file_url
            .to_file_path()
            .map_err(|_| ObjStoreError::InvalidConfig {
                message: format!("invalid path in logfs url: '{url}'"),
                source: None,
            })?;

        let mut config = Self::new(path);
        let mut crypto_key: Option<String> = None;
        let mut crypto_profile: Option<CryptoProfile> = None;
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "version" => {
                    config.version = Some(value.parse::<u32>().map_err(|source| {
                        ObjStoreError::InvalidConfig {
                            message: format!("invalid version '{value}': expected u32"),
                            source: Some(source.into()),
                        }
                    })?)
                }
                "create" => {
                    config.allow_create = value.is_empty() || parse_bool(&value)?;
                }
                "allow_create" => config.allow_create = parse_bool(&value)?,
                "readonly" => config.readonly = parse_bool(&value)?,
                "raw" | "raw_mode" => config.raw_mode = parse_bool(&value)?,
                "offset" => {
                    config.offset = Some(value.parse::<u64>().map_err(|source| {
                        ObjStoreError::InvalidConfig {
                            message: format!("invalid offset '{value}': expected u64"),
                            source: Some(source.into()),
                        }
                    })?)
                }
                "chunk_size" | "default_chunk_size" => {
                    config.default_chunk_size = Some(value.parse::<u32>().map_err(|source| {
                        ObjStoreError::InvalidConfig {
                            message: format!("invalid chunk size '{value}': expected u32"),
                            source: Some(source.into()),
                        }
                    })?)
                }
                "partial_index_interval" => {
                    config.partial_index_write_interval =
                        Some(value.parse::<u64>().map_err(|source| {
                            ObjStoreError::InvalidConfig {
                                message: format!(
                                    "invalid partial index interval '{value}': expected u64"
                                ),
                                source: Some(source.into()),
                            }
                        })?)
                }
                "full_index_interval" => {
                    config.full_index_write_interval =
                        Some(value.parse::<u64>().map_err(|source| {
                            ObjStoreError::InvalidConfig {
                                message: format!(
                                    "invalid full index interval '{value}': expected u64"
                                ),
                                source: Some(source.into()),
                            }
                        })?)
                }
                "key" => {
                    crypto_key = Some(value.to_string());
                }
                "profile" => {
                    crypto_profile = Some(parse_crypto_profile(&value)?);
                }
                other => {
                    return Err(ObjStoreError::InvalidConfig {
                        message: format!(
                            "unsupported logfs query parameter '{}': value '{}'",
                            other, value
                        ),
                        source: None,
                    });
                }
            }
        }

        if crypto_key.is_some() || crypto_profile.is_some() {
            config.crypto = Some(LogFsCryptoConfig {
                key: crypto_key,
                profile: crypto_profile.unwrap_or_default(),
                ..LogFsCryptoConfig::default()
            });
        }

        config.to_logfs_open_options()?;
        Ok(config)
    }
}

fn parse_crypto_profile(value: &str) -> Result<CryptoProfile> {
    match value {
        "standard" => Ok(CryptoProfile::Standard),
        "low-memory" | "low_memory" => Ok(CryptoProfile::LowMemory),
        _ => Err(ObjStoreError::InvalidConfig {
            message: format!(
                "invalid crypto profile '{value}': expected 'standard' or 'low-memory'"
            ),
            source: None,
        }),
    }
}

fn crypto_profile_name(profile: CryptoProfile) -> &'static str {
    match profile {
        CryptoProfile::Standard => "standard",
        CryptoProfile::LowMemory => "low-memory",
    }
}

fn parse_bool(value: &str) -> Result<bool> {
    match value {
        "1" | "true" | "on" | "yes" => Ok(true),
        "0" | "false" | "off" | "no" => Ok(false),
        other => Err(ObjStoreError::InvalidConfig {
            message: format!(
                "invalid bool value '{}': expected one of [true,false,1,0,on,off,yes,no]",
                other
            ),
            source: None,
        }),
    }
}

fn path_is_block_device(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt as _;

        std::fs::metadata(path).is_ok_and(|metadata| metadata.file_type().is_block_device())
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_selectors_round_trip() {
        let url = Url::parse("logfs:///tmp/archive.log?version=3&offset=4096").unwrap();
        let config = LogFsObjStoreConfig::from_url(&url).unwrap();

        assert_eq!(config.path, PathBuf::from("/tmp/archive.log"));
        assert_eq!(config.version, Some(3));
        assert_eq!(config.offset, Some(4096));
        assert_eq!(config.safe_uri().unwrap().as_str(), url.as_str());
    }

    #[test]
    fn uri_rejects_invalid_or_unsupported_versions() {
        let non_numeric = Url::parse("logfs:///tmp/archive.log?version=current").unwrap();
        assert!(LogFsObjStoreConfig::from_url(&non_numeric).is_err());

        let unsupported = Url::parse("logfs:///tmp/archive.log?version=1").unwrap();
        assert!(LogFsObjStoreConfig::from_url(&unsupported).is_err());
    }

    #[test]
    fn v3_crypto_url_uses_optional_key_and_profile() {
        let standard = LogFsObjStoreConfig::from_url(
            &Url::parse("logfs:///tmp/archive.log?version=3&key=secret").unwrap(),
        )
        .unwrap();
        assert_eq!(
            standard.safe_uri().unwrap().as_str(),
            "logfs:///tmp/archive.log?version=3&profile=standard"
        );
        let crypto = standard.crypto.unwrap();
        assert_eq!(crypto.key.as_deref(), Some("secret"));
        assert_eq!(crypto.salt, None);
        assert_eq!(crypto.iterations, None);
        assert_eq!(crypto.profile, CryptoProfile::Standard);

        let mut deferred = LogFsObjStoreConfig::from_url(
            &Url::parse("logfs:///tmp/archive.log?version=3&profile=low-memory").unwrap(),
        )
        .unwrap();
        assert_eq!(
            deferred.safe_uri().unwrap().as_str(),
            "logfs:///tmp/archive.log?version=3&profile=low-memory"
        );
        let crypto = deferred.crypto.as_mut().unwrap();
        assert_eq!(crypto.key, None);
        assert_eq!(crypto.profile, CryptoProfile::LowMemory);
        crypto.key = Some("injected-secret".to_string());

        let logfs_crypto = deferred.to_logfs_config().crypto.unwrap();
        assert_eq!(logfs_crypto.profile, CryptoProfile::LowMemory);
    }

    #[test]
    fn encrypted_v2_requires_programmatic_legacy_parameters() {
        let missing = Url::parse("logfs:///tmp/archive.log?version=2&key=secret").unwrap();
        assert!(LogFsObjStoreConfig::from_url(&missing).is_err());

        let mut config = LogFsObjStoreConfig::from_url(
            &Url::parse("logfs:///tmp/archive.log?version=2").unwrap(),
        )
        .unwrap();
        config.crypto = Some(LogFsCryptoConfig {
            key: Some("secret".to_string()),
            salt: Some(b"legacy-salt".to_vec()),
            iterations: NonZeroU32::new(100_000),
            profile: CryptoProfile::Standard,
        });
        assert!(config.to_logfs_open_options().is_ok());
    }

    #[test]
    fn url_rejects_noncanonical_crypto_parameters() {
        for query in [
            "crypto_key=secret",
            "crypto_profile=standard",
            "salt=c2FsdA==",
            "iterations=100000",
        ] {
            let url = Url::parse(&format!("logfs:///tmp/archive.log?{query}")).unwrap();
            assert!(LogFsObjStoreConfig::from_url(&url).is_err(), "{query}");
        }

        let invalid = Url::parse("logfs:///tmp/archive.log?profile=fast").unwrap();
        assert!(LogFsObjStoreConfig::from_url(&invalid).is_err());
    }

    #[test]
    fn offset_uri_is_readonly_without_create_flag() {
        let readonly = LogFsObjStoreConfig::from_url(
            &Url::parse("logfs:///tmp/archive.log?version=3&offset=4096").unwrap(),
        )
        .unwrap();
        assert!(readonly.to_logfs_config().readonly);

        let writable = LogFsObjStoreConfig::from_url(
            &Url::parse("logfs:///tmp/archive.log?version=3&offset=4096&create").unwrap(),
        )
        .unwrap();
        assert!(writable.allow_create);
        assert!(!writable.to_logfs_config().readonly);

        let explicitly_disabled = LogFsObjStoreConfig::from_url(
            &Url::parse("logfs:///tmp/archive.log?offset=4096&create=false").unwrap(),
        )
        .unwrap();
        assert!(explicitly_disabled.to_logfs_config().readonly);
    }
}
