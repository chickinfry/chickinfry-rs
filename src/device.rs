use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{ClientError, Persist, validate_origin};

#[path = "device/files.rs"]
mod files;

const VERSION: u32 = 1;
const MAX_BYTES: usize = 8 * 1024;
const MAX_ATTEMPTS: usize = 3;

pub(crate) fn error(code: &str) -> ClientError {
    ClientError::Protocol(format!("device_storage_{code}"))
}

pub(crate) fn validate_path(path: &Path) -> Result<(), ClientError> {
    if path.as_os_str().as_encoded_bytes().contains(&0) || !path.is_absolute() {
        return Err(error("unavailable"));
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Scope {
    pub app: String,
    pub origin: String,
    pub project: String,
}

impl Scope {
    fn bytes(&self) -> Result<Vec<u8>, ClientError> {
        if self.app.is_empty()
            || self.project.is_empty()
            || self.app.len() + self.project.len() + self.origin.len() > MAX_BYTES
            || validate_origin(&self.origin)? != self.origin
        {
            return Err(error("corrupt"));
        }
        serde_json::to_vec(self).map_err(|_| error("corrupt"))
    }

    pub(crate) fn path(&self, persist: Option<&Persist>) -> Result<Option<PathBuf>, ClientError> {
        match persist {
            Some(Persist::Disabled) => Ok(None),
            Some(Persist::Dir(path)) => {
                validate_path(path)?;
                Ok(Some(path.clone()))
            }
            None => {
                let base = files::state_home()?;
                let app = hex::encode(Sha256::digest(self.app.as_bytes()));
                #[cfg(target_os = "macos")]
                let path = base.join(app);
                #[cfg(not(target_os = "macos"))]
                let path = base.join("chickinfry").join(app);
                validate_path(&path)?;
                Ok(Some(path))
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Key {
    pub owner: String,
    pub kind: String,
}

#[derive(Clone, Default)]
pub(crate) struct Snapshot {
    pub generation: u64,
    pub records: BTreeMap<Key, Vec<u8>>,
    pub refreshing: BTreeSet<Key>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    scope: Scope,
    generation: u64,
    records: Vec<(Key, String)>,
    refreshing: BTreeSet<Key>,
}

impl Snapshot {
    fn encode(&self, scope: &Scope) -> Result<Vec<u8>, ClientError> {
        use base64::Engine;
        if self
            .records
            .keys()
            .filter(|key| key.kind == "attempt")
            .count()
            > MAX_ATTEMPTS
            || self.records.values().any(|value| value.len() > MAX_BYTES)
        {
            return Err(error("full"));
        }
        if self.records.keys().any(|key| {
            key.owner.is_empty()
                || key.owner.len() > 64
                || !key.owner.is_ascii()
                || !matches!(key.kind.as_str(), "session" | "attempt")
        }) || self
            .refreshing
            .iter()
            .any(|key| key.kind != "session" || !self.records.contains_key(key))
        {
            return Err(error("corrupt"));
        }
        let envelope = Envelope {
            version: VERSION,
            scope: scope.clone(),
            generation: self.generation,
            records: self
                .records
                .iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        base64::engine::general_purpose::STANDARD.encode(value),
                    )
                })
                .collect(),
            refreshing: self.refreshing.clone(),
        };
        let bytes = serde_json::to_vec(&envelope).map_err(|_| error("corrupt"))?;
        if bytes.len() > MAX_BYTES {
            return Err(error("full"));
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8], scope: &Scope, generation: u64) -> Result<Self, ClientError> {
        use base64::Engine;
        if bytes.len() > MAX_BYTES {
            return Err(error("corrupt"));
        }
        let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| error("corrupt"))?;
        if envelope.version > VERSION {
            return Err(error("version_unsupported"));
        }
        if generation == 0
            || envelope.version != VERSION
            || envelope.scope != *scope
            || envelope.generation != generation
        {
            return Err(error("corrupt"));
        }
        let count = envelope.records.len();
        let records = envelope
            .records
            .into_iter()
            .map(|(key, value)| {
                base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .map(|value| (key, value))
                    .map_err(|_| error("corrupt"))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        if records.len() != count {
            return Err(error("corrupt"));
        }
        let snapshot = Self {
            generation,
            records,
            refreshing: envelope.refreshing,
        };
        snapshot.encode(scope).map_err(|_| error("corrupt"))?;
        Ok(snapshot)
    }
}

struct Lock(File);

impl Drop for Lock {
    fn drop(&mut self) {
        // Inherited descriptors must not extend a completed transaction's lock.
        let _ = self.0.unlock();
    }
}

pub(crate) struct Device {
    root: PathBuf,
    pub(super) scope: Scope,
    name: String,
}

impl Device {
    pub(crate) fn open(root: &Path, scope: Scope) -> Result<Self, ClientError> {
        validate_path(root)?;
        let scope_key = scope.bytes()?;
        files::directory(root)?;
        let device = Self {
            root: root.into(),
            scope,
            name: hex::encode(Sha256::digest(scope_key)),
        };
        device.read()?;
        Ok(device)
    }

    fn path(&self, suffix: &str) -> PathBuf {
        self.root.join(format!("{}.{suffix}", self.name))
    }

    fn lock(&self) -> Result<Lock, ClientError> {
        files::check_directory(&self.root)?;
        let lock = files::open(&self.path("lock"), true)?.ok_or_else(|| error("unavailable"))?;
        lock.try_lock().map_err(|_| error("unavailable"))?;
        let lock = Lock(lock);
        files::check_file(&self.path("lock"))?;
        if std::fs::symlink_metadata(self.path("tmp")).is_ok() {
            files::check_file(&self.path("tmp"))?;
        }
        Ok(lock)
    }

    fn load(&self) -> Result<Snapshot, ClientError> {
        let path = self.path("json");
        let Some(file) = files::open(&path, false)? else {
            return Ok(Snapshot::default());
        };
        let mut bytes = Vec::new();
        file.take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(files::io_error)?;
        if bytes.len() > MAX_BYTES {
            return Err(error("corrupt"));
        }
        let header: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| error("corrupt"))?;
        if header
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|version| version > u64::from(VERSION))
        {
            return Err(error("version_unsupported"));
        }
        let generation = header
            .get("generation")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| error("corrupt"))?;
        Snapshot::decode(&bytes, &self.scope, generation)
    }

    pub(crate) fn read(&self) -> Result<Snapshot, ClientError> {
        let _lock = self.lock()?;
        self.load()
    }

    pub(crate) fn replace(&self, expected: u64, mut next: Snapshot) -> Result<bool, ClientError> {
        let _lock = self.lock()?;
        let current = self.load()?;
        #[cfg(test)]
        tests::pause_replace(&self.root);
        if current.generation != expected {
            return Ok(false);
        }
        next.generation = expected.checked_add(1).ok_or_else(|| error("full"))?;
        let bytes = next.encode(&self.scope)?;
        let path = self.path("json");
        if path.exists() {
            files::check_file(&path)?;
        }
        let temporary = self.path("tmp");
        // Only the lock owner can create or clean this scope's staging file.
        if std::fs::symlink_metadata(&temporary).is_ok() {
            files::check_file(&temporary)?;
            std::fs::remove_file(&temporary).map_err(files::io_error)?;
        }
        let mut file = files::create(&temporary)?;
        file.write_all(&bytes).map_err(files::io_error)?;
        file.sync_all().map_err(files::io_error)?;
        #[cfg(test)]
        tests::before_replace(&self.root);
        drop(file);
        std::fs::rename(&temporary, &path).map_err(files::io_error)?;
        files::sync_directory(&self.root)?;
        Ok(true)
    }

    pub(crate) fn clear(&self, expected: u64) -> Result<bool, ClientError> {
        // Keep the generation tombstone so late responses cannot recreate credentials.
        self.replace(expected, Snapshot::default())
    }

    pub(crate) fn claim_refresh(
        &self,
        expected: u64,
        key: &Key,
    ) -> Result<Option<Snapshot>, ClientError> {
        let mut state = self.read()?;
        if state.generation != expected
            || !state.records.contains_key(key)
            || !state.refreshing.insert(key.clone())
        {
            return Ok(None);
        }
        if !self.replace(expected, state.clone())? {
            return Ok(None);
        }
        state.generation += 1;
        Ok(Some(state))
    }
}

#[cfg(test)]
#[path = "device/store_tests.rs"]
mod tests;
