//! Cleanup of credentials saved by older RealmHound versions.
//!
//! Production code can only delete credentials. Tokens used for API requests
//! are held in process memory and are never restored from this backend.

#[cfg(test)]
use std::fmt;

#[cfg(test)]
use chrono::{DateTime, Utc};
use thiserror::Error;

use super::AccountKey;

/// An in-memory representation of a legacy credential for cleanup fixtures.
///
/// The token is redacted in `Debug` output so it can never be logged.
#[derive(Clone)]
#[cfg(test)]
pub struct SavedCredential {
    token: String,
    captured_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
impl SavedCredential {
    /// Create a credential from a captured token and its capture time.
    pub fn new(token: impl Into<String>, captured_at: Option<DateTime<Utc>>) -> Self {
        Self {
            token: token.into(),
            captured_at,
        }
    }

    /// Borrow the token contents. Callers must never log the returned value.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Return when the token was captured, if known.
    pub fn captured_at(&self) -> Option<DateTime<Utc>> {
        self.captured_at
    }
}

#[cfg(test)]
impl fmt::Debug for SavedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SavedCredential")
            .field("token", &"<redacted>")
            .field("captured_at", &self.captured_at)
            .finish()
    }
}

#[cfg(test)]
impl PartialEq for SavedCredential {
    fn eq(&self, other: &Self) -> bool {
        self.token == other.token && self.captured_at == other.captured_at
    }
}

/// Errors returned by a [`CredentialStore`]. No variant carries token contents.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CredentialError {
    /// The credential backend is not available on this platform or session.
    /// Cleanup callers surface the failure and retry on the next launch.
    #[error("credential store is unavailable")]
    Unavailable,
    /// The target name was empty or otherwise rejected by the backend.
    #[error("credential target is invalid")]
    InvalidTarget,
    /// The stored credential payload could not be decoded.
    #[error("stored credential payload is malformed")]
    MalformedPayload,
    /// The backend reported a low-level failure, identified only by its code.
    #[error("credential store operation failed (code {code})")]
    Backend {
        /// Platform error code (never contains token contents).
        code: u32,
    },
}

/// Derive the deterministic credential target for an account key:
/// `RealmHound/account/<opaque AccountKey>`.
pub fn credential_target(account_key: AccountKey) -> String {
    format!("RealmHound/account/{account_key}")
}

/// Legacy credential cleanup. Missing credentials are not errors.
pub trait CredentialStore: Send + Sync {
    #[cfg(test)]
    /// Read the credential stored under `target`, or `None` when none exists.
    fn read(&self, _target: &str) -> Result<Option<SavedCredential>, CredentialError> {
        Err(CredentialError::Unavailable)
    }

    #[cfg(test)]
    /// Write (overwrite) the credential stored under `target`.
    fn write(&self, _target: &str, _credential: &SavedCredential) -> Result<(), CredentialError> {
        Err(CredentialError::Unavailable)
    }

    /// Delete the credential stored under `target`. Missing is not an error.
    fn delete(&self, target: &str) -> Result<(), CredentialError>;

    /// Remove all legacy account credentials, including orphaned account keys.
    fn purge_accounts(&self) -> Result<(), CredentialError>;
}

#[cfg(any(windows, test))]
fn is_account_target(target: &str) -> bool {
    target
        .strip_prefix("RealmHound/account/")
        .is_some_and(|key| key.parse::<AccountKey>().is_ok())
}

/// In-memory credential fixtures in tests; empty delete-only fallback otherwise.
///
/// Never touches the real Credential Manager, so tests stay hermetic.
#[derive(Debug, Default)]
pub struct InMemoryCredentialStore {
    #[cfg(test)]
    entries: std::sync::Mutex<std::collections::HashMap<String, SavedCredential>>,
}

impl InMemoryCredentialStore {
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl CredentialStore for InMemoryCredentialStore {
    #[cfg(test)]
    fn read(&self, target: &str) -> Result<Option<SavedCredential>, CredentialError> {
        if target.is_empty() {
            return Err(CredentialError::InvalidTarget);
        }
        let entries = self
            .entries
            .lock()
            .map_err(|_| CredentialError::Unavailable)?;
        Ok(entries.get(target).cloned())
    }

    #[cfg(test)]
    fn write(&self, target: &str, credential: &SavedCredential) -> Result<(), CredentialError> {
        if target.is_empty() {
            return Err(CredentialError::InvalidTarget);
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| CredentialError::Unavailable)?;
        entries.insert(target.to_string(), credential.clone());
        Ok(())
    }

    fn delete(&self, target: &str) -> Result<(), CredentialError> {
        if target.is_empty() {
            return Err(CredentialError::InvalidTarget);
        }
        #[cfg(test)]
        self.entries
            .lock()
            .map_err(|_| CredentialError::Unavailable)?
            .remove(target);
        Ok(())
    }

    fn purge_accounts(&self) -> Result<(), CredentialError> {
        #[cfg(test)]
        self.entries
            .lock()
            .map_err(|_| CredentialError::Unavailable)?
            .retain(|target, _| !is_account_target(target));
        Ok(())
    }
}

#[cfg(windows)]
pub use windows_impl::WindowsCredentialStore;

#[cfg(windows)]
mod windows_impl {
    use super::{is_account_target, CredentialError, CredentialStore};

    use windows_sys::Win32::Foundation::{GetLastError, ERROR_NOT_FOUND};
    use windows_sys::Win32::Security::Credentials::{
        CredDeleteW, CredEnumerateW, CredFree, CREDENTIALW, CRED_TYPE_GENERIC,
    };

    /// Delete-only Windows Credential Manager backend.
    #[derive(Debug, Default)]
    pub struct WindowsCredentialStore;

    impl WindowsCredentialStore {
        /// Create a Windows Credential Manager store.
        pub fn new() -> Self {
            Self
        }
    }

    fn to_wide_nul(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    impl CredentialStore for WindowsCredentialStore {
        fn purge_accounts(&self) -> Result<(), CredentialError> {
            let filter = to_wide_nul("RealmHound/account/*");
            let mut count = 0;
            let mut entries: *mut *mut CREDENTIALW = std::ptr::null_mut();
            // SAFETY: output pointers and the terminated filter remain valid.
            let ok = unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut entries) };
            if ok == 0 {
                let code = unsafe { GetLastError() };
                if code == ERROR_NOT_FOUND {
                    return Ok(());
                }
                return Err(CredentialError::Backend { code });
            }
            if entries.is_null() {
                return Err(CredentialError::MalformedPayload);
            }
            let mut result = Ok(());
            // SAFETY: the successful API call owns `count` entries and their
            // nul-terminated names until CredFree; credential blobs are not read.
            unsafe {
                for entry in std::slice::from_raw_parts(entries, count as usize) {
                    if entry.is_null() || (**entry).TargetName.is_null() {
                        result = Err(CredentialError::MalformedPayload);
                        continue;
                    }
                    if (**entry).Type != CRED_TYPE_GENERIC {
                        continue;
                    }
                    let name = (**entry).TargetName;
                    let mut length = 0;
                    while *name.add(length) != 0 {
                        length += 1;
                    }
                    let target = String::from_utf16_lossy(std::slice::from_raw_parts(name, length));
                    if is_account_target(&target) {
                        if let Err(error) = self.delete(&target) {
                            result = Err(error);
                        }
                    }
                }
                CredFree(entries.cast());
            }
            result
        }

        fn delete(&self, target: &str) -> Result<(), CredentialError> {
            if target.is_empty() {
                return Err(CredentialError::InvalidTarget);
            }
            let target_w = to_wide_nul(target);
            // SAFETY: `target_w` is a valid nul-terminated wide string.
            let ok = unsafe { CredDeleteW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0) };
            if ok == 0 {
                // SAFETY: querying the thread's last error code is always sound.
                let code = unsafe { GetLastError() };
                if code == ERROR_NOT_FOUND {
                    return Ok(());
                }
                return Err(CredentialError::Backend { code });
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purge_removes_account_credentials_including_orphans_only() {
        let store = InMemoryCredentialStore::new();
        let owned = credential_target(AccountKey::generate());
        let other = "OtherApp/account/secret";
        let unrelated = "RealmHound/account/not-an-account-key";
        for target in [&owned, other, unrelated] {
            store
                .write(target, &SavedCredential::new("synthetic-secret", None))
                .unwrap();
        }
        store.purge_accounts().unwrap();
        store.purge_accounts().unwrap();
        assert!(store.read(&owned).unwrap().is_none());
        assert!(store.read(other).unwrap().is_some());
        assert!(store.read(unrelated).unwrap().is_some());
    }

    #[test]
    fn target_is_deterministic_and_namespaced() {
        let key = AccountKey::generate();
        let target = credential_target(key);
        assert_eq!(target, format!("RealmHound/account/{key}"));
        assert_eq!(target, credential_target(key));
    }

    #[test]
    fn in_memory_read_overwrite_delete_round_trip() {
        let store = InMemoryCredentialStore::new();
        let target = credential_target(AccountKey::generate());
        assert_eq!(store.read(&target).unwrap(), None);

        let first = SavedCredential::new("token-one", Some(Utc::now()));
        store.write(&target, &first).unwrap();
        assert_eq!(store.read(&target).unwrap().unwrap().token(), "token-one");

        // Overwrite replaces the prior credential.
        let second = SavedCredential::new("token-two", None);
        store.write(&target, &second).unwrap();
        assert_eq!(store.read(&target).unwrap().unwrap().token(), "token-two");

        store.delete(&target).unwrap();
        assert_eq!(store.read(&target).unwrap(), None);
        // Deleting a missing credential is not an error.
        store.delete(&target).unwrap();
    }

    #[test]
    fn empty_target_is_rejected() {
        let store = InMemoryCredentialStore::new();
        let credential = SavedCredential::new("x", None);
        assert_eq!(store.read(""), Err(CredentialError::InvalidTarget));
        assert_eq!(
            store.write("", &credential),
            Err(CredentialError::InvalidTarget)
        );
        assert_eq!(store.delete(""), Err(CredentialError::InvalidTarget));
    }

    #[test]
    fn debug_redacts_token_contents() {
        let credential = SavedCredential::new("super-secret-token", None);
        let rendered = format!("{credential:?}");
        assert!(!rendered.contains("super-secret-token"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn errors_never_carry_token_contents() {
        // Typed, redacted errors: their Display never includes a token.
        for error in [
            CredentialError::Unavailable,
            CredentialError::InvalidTarget,
            CredentialError::MalformedPayload,
            CredentialError::Backend { code: 1168 },
        ] {
            let rendered = error.to_string();
            assert!(!rendered.contains("token"));
        }
    }
}
