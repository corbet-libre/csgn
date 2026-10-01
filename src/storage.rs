//! Atomic persistence and fail-closed publication of signing state.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use crate::signer::Signer;
use crate::{KeyRing, Kind, SecretKey, SignError, SigningState};

/// Private recovery state and its monotonically increasing storage revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredState {
    /// Positive compare-and-swap revision. Never reused or reset.
    pub revision: i64,
    /// Exact recovery metadata; never publish it to verifiers.
    pub state: SigningState,
}

/// Minimal storage boundary for one fixed, authorized community namespace.
///
/// Implementations must atomically compare revisions and replace the entire state,
/// durably commit before success, and never log input. A missing expected revision
/// means create-only. Never delete/reset a live issuer's record. An error may mean
/// the commit outcome is unknown; [`PersistentSigner`] stops until reopened.
pub trait Store: Send + Sync {
    /// Load one issuer's current metadata; missing is not an error.
    fn load(
        &self,
        issuer: &str,
    ) -> impl Future<Output = Result<Option<StoredState>, StorageError>> + Send;

    /// Commit a replacement only if the current revision equals `expected`.
    /// Return the new positive revision. Stale writers must receive `Conflict`.
    fn compare_exchange(
        &self,
        expected: Option<i64>,
        state: &SigningState,
    ) -> impl Future<Output = Result<i64, StorageError>> + Send;
}

/// Volatile, atomic store for tests and ephemeral issuers.
///
/// Each constructor creates one isolated community scope. Clones share that scope.
/// This is a real in-memory implementation, not durable across process restarts.
#[derive(Clone, Default)]
pub struct MemoryStore(Arc<Mutex<BTreeMap<String, StoredState>>>);

impl Store for MemoryStore {
    async fn load(&self, issuer: &str) -> Result<Option<StoredState>, StorageError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| StorageError::Unavailable)?
            .get(issuer)
            .cloned())
    }

    async fn compare_exchange(
        &self,
        expected: Option<i64>,
        state: &SigningState,
    ) -> Result<i64, StorageError> {
        let mut rows = self.0.lock().map_err(|_| StorageError::Unavailable)?;
        let issuer = state.key_ring().issuer();
        if rows.get(issuer).map(|row| row.revision) != expected {
            return Err(StorageError::Conflict);
        }
        let revision = next_revision(expected)?;
        rows.insert(
            issuer.to_owned(),
            StoredState {
                revision,
                state: state.clone(),
            },
        );
        Ok(revision)
    }
}

pub(crate) fn next_revision(expected: Option<i64>) -> Result<i64, StorageError> {
    match expected {
        None => Ok(1),
        Some(value) if value > 0 => value.checked_add(1).ok_or(StorageError::InvalidState),
        Some(_) => Err(StorageError::InvalidState),
    }
}

/// Signing with commit-before-return ordering and revision fencing.
///
/// Errors or cancellation during persistence disable this instance. Reopen using
/// the store's active key ID and a key supplied by the platform secret store.
/// Validation errors leave the instance usable. No signed bytes or new ring are
/// exposed until the corresponding metadata has committed.
///
/// Run exactly one writer per issuer. Serialize issuance and ring publication in
/// that service. Revision fencing prevents stale writes, but cannot retract a
/// stale ring already read by another process or coordinate external publication.
pub struct PersistentSigner<S> {
    store: S,
    signer: Option<Signer>,
    revision: i64,
}

impl<S: Store> PersistentSigner<S> {
    /// Create an issuer only if it has never been stored in this namespace.
    pub async fn create(
        store: S,
        issuer: impl Into<String>,
        key: SecretKey,
        now: u64,
        max_validity: u64,
    ) -> Result<Self, StorageError> {
        let signer = Signer::new(issuer, key, now, max_validity).map_err(StorageError::Sign)?;
        let revision = store.compare_exchange(None, &signer.state()).await?;
        Ok(Self {
            store,
            signer: Some(signer),
            revision,
        })
    }

    /// Reload exact state and fence any writer with an older revision.
    /// The caller supplies the key matching the active public key in storage.
    pub async fn open(
        store: S,
        issuer: &str,
        key: SecretKey,
        now: u64,
    ) -> Result<Self, StorageError> {
        let saved = store.load(issuer).await?.ok_or(StorageError::Missing)?;
        if saved.revision <= 0 || saved.state.key_ring().issuer() != issuer {
            return Err(StorageError::InvalidState);
        }
        let signer = Signer::resume(saved.state, key, now).map_err(StorageError::Sign)?;
        let revision = store
            .compare_exchange(Some(saved.revision), &signer.state())
            .await?;
        Ok(Self {
            store,
            signer: Some(signer),
            revision,
        })
    }

    /// Sign and durably record the retention deadline before returning COSE bytes.
    pub async fn sign(
        &mut self,
        kind: Kind,
        payload: &[u8],
        now: u64,
        valid_until: u64,
    ) -> Result<Vec<u8>, StorageError> {
        self.update(|signer| signer.sign(kind, payload, now, valid_until))
            .await
    }

    /// Rotate and commit the new ring before making it visible.
    /// Provision the new key in the platform secret store before calling this.
    pub async fn rotate(&mut self, key: SecretKey, now: u64) -> Result<(), StorageError> {
        self.update(|signer| signer.rotate(key, now)).await
    }

    /// Commit removal of expired public keys; preserve key-ID tombstones.
    pub async fn prune(&mut self, now: u64) -> Result<(), StorageError> {
        self.update(|signer| signer.prune(now)).await
    }

    /// Endorse the next ring under the old active key, then commit ring and proof
    /// atomically before returning original COSE bytes. Provision the new key in
    /// the platform secret store first. Uncertain writes require reopen.
    pub async fn rotate_with_proof(
        &mut self,
        key: SecretKey,
        now: u64,
        valid_until: u64,
    ) -> Result<Vec<u8>, StorageError> {
        self.update(|signer| signer.rotate_with_proof(key, now, valid_until))
            .await
    }

    /// Endorse and commit expired-key removal. A no-op returns `None` and does
    /// not advance the public ring revision. Pending proofs block ring changes.
    pub async fn prune_with_proof(
        &mut self,
        now: u64,
        valid_until: u64,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.update(|signer| signer.prune_with_proof(now, valid_until))
            .await
    }

    /// Original durable proof awaiting consumer retention, including after reopen.
    pub fn pending_transition(&self) -> Result<Option<&[u8]>, StorageError> {
        Ok(self
            .signer
            .as_ref()
            .ok_or(StorageError::ReloadRequired)?
            .pending_transition())
    }

    /// Public ring-change sequence, independent of signing volume and CAS revisions.
    pub fn ring_revision(&self) -> Result<u64, StorageError> {
        Ok(self
            .signer
            .as_ref()
            .ok_or(StorageError::ReloadRequired)?
            .ring_revision())
    }

    /// Clear a matching pending proof only after the consumer durably retains it.
    /// The ring revision remains unchanged. An uncertain acknowledgement requires
    /// reopen; the returned pending state determines whether the commit happened.
    pub async fn acknowledge_transition(&mut self, revision: u64) -> Result<(), StorageError> {
        self.update(|signer| signer.acknowledge_transition(revision))
            .await
    }

    /// The last successfully committed public key ring, or `ReloadRequired`.
    pub fn key_ring(&self) -> Result<&KeyRing, StorageError> {
        Ok(self
            .signer
            .as_ref()
            .ok_or(StorageError::ReloadRequired)?
            .key_ring())
    }

    async fn update<T>(
        &mut self,
        apply: impl FnOnce(&mut Signer) -> Result<T, SignError>,
    ) -> Result<T, StorageError> {
        // Take before awaiting: dropping this future also drops the key and fences
        // this instance. Remote commit cancellation can have an unknown outcome.
        let mut signer = self.signer.take().ok_or(StorageError::ReloadRequired)?;
        let result = match apply(&mut signer) {
            Ok(result) => result,
            Err(error) => {
                self.signer = Some(signer);
                return Err(StorageError::Sign(error));
            }
        };
        self.revision = self
            .store
            .compare_exchange(Some(self.revision), &signer.state())
            .await?;
        self.signer = Some(signer);
        Ok(result)
    }
}

/// Persistence/publication failures. Messages deliberately exclude SQL and data.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StorageError {
    /// Another writer committed first, or create attempted to overwrite an issuer.
    Conflict,
    /// The requested issuer does not exist.
    Missing,
    /// Stored data or a revision is invalid.
    InvalidState,
    /// The database or synchronization primitive failed; outcome may be unknown.
    Unavailable,
    /// Reopen from current storage before attempting another operation.
    ReloadRequired,
    /// A signing validation error; no state was committed.
    Sign(SignError),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict => f.write_str("signing state revision conflict"),
            Self::Missing => f.write_str("signing state is missing"),
            Self::InvalidState => f.write_str("invalid signing state"),
            Self::Unavailable => f.write_str("signing storage unavailable; reload required"),
            Self::ReloadRequired => f.write_str("reload signing state before continuing"),
            Self::Sign(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for StorageError {}

#[cfg(test)]
#[path = "tests/storage.rs"]
mod tests;
