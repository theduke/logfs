//! Implementation resource budgets. These are not v3 wire-format maxima.
use crate::LogFsError;

pub(super) const METADATA_PLAINTEXT_LIMIT: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(super) struct MetadataLimit {
    pub(super) plaintext: u64,
    name: &'static str,
}

impl MetadataLimit {
    /// Check before serialization/allocation, then add the authentication bytes.
    pub(super) fn encoded_len(self, plaintext: u64, padding: u64) -> Result<u64, LogFsError> {
        if plaintext > self.plaintext {
            return Err(LogFsError::new_internal(format!(
                "V3 {} plaintext length {plaintext} exceeds resource limit {}",
                self.name, self.plaintext
            )));
        }
        plaintext.checked_add(padding).ok_or_else(|| {
            LogFsError::new_internal(format!("V3 {} encoded length overflow", self.name))
        })
    }

    /// Validate an untrusted encoded length before allocating a read buffer.
    pub(super) fn check_encoded(self, encoded: u64, padding: u64) -> Result<(), LogFsError> {
        let plaintext = encoded.checked_sub(padding).ok_or_else(|| {
            LogFsError::new_internal(format!("Truncated v3 {} authentication data", self.name))
        })?;
        self.encoded_len(plaintext, padding)?;
        Ok(())
    }
}

pub(super) fn action() -> MetadataLimit {
    MetadataLimit {
        plaintext: budgets().0,
        name: "action",
    }
}

pub(super) fn checkpoint() -> MetadataLimit {
    MetadataLimit {
        plaintext: budgets().1,
        name: "checkpoint",
    }
}

fn budgets() -> (u64, u64) {
    #[cfg(test)]
    if let Some(limits) = TEST_LIMITS.get() {
        return limits;
    }
    (METADATA_PLAINTEXT_LIMIT, METADATA_PLAINTEXT_LIMIT)
}

#[cfg(test)]
thread_local! {
    static TEST_LIMITS: std::cell::Cell<Option<(u64, u64)>> = const { std::cell::Cell::new(None) };
}

/// Thread-local override exercises the actual I/O paths without 512 MiB fixtures.
#[cfg(test)]
pub(super) fn with_test_limits<T>(action: u64, checkpoint: u64, f: impl FnOnce() -> T) -> T {
    struct Reset(Option<(u64, u64)>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_LIMITS.set(self.0);
        }
    }
    let _reset = Reset(TEST_LIMITS.replace(Some((action, checkpoint))));
    f()
}
