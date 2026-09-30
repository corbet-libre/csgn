//! The official libSQL client through crlt's community-scoped facade.

use crate::storage::next_revision;
use crate::{SigningState, StorageError, Store, StoredState};

/// Schema DDL to add to the service's ordered `crlt::Migration` history.
/// The service owns migration numbering and one database per community.
pub const SCHEMA: &str = "
CREATE TABLE csgn_state (
    community_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    state BLOB NOT NULL,
    PRIMARY KEY (community_id, issuer)
) WITHOUT ROWID;
";

const SELECT: &str = "SELECT revision, state FROM csgn_state WHERE issuer = ?1";
const INSERT: &str = "INSERT INTO csgn_state (issuer, revision, state) VALUES (?1, ?2, ?3)";
const UPDATE: &str =
    "UPDATE csgn_state SET revision = ?1, state = ?2 WHERE issuer = ?3 AND revision = ?4";

/// Persistent store bound to one `crlt::Community` capability.
///
/// Apply [`SCHEMA`] through `Db::migrate` before construction. No keys or payloads
/// are persisted. crlt injects `community_id` and enforces indexed query plans.
#[derive(Clone)]
pub struct LibsqlStore {
    community: crlt::Community,
}

impl LibsqlStore {
    /// Bind a caller-authorized, already migrated community capability.
    pub fn new(community: crlt::Community) -> Self {
        Self { community }
    }

    /// Check plans for every statement this adapter executes, without writing.
    pub async fn check_query_plans(&self) -> Result<(), StorageError> {
        self.community
            .explain(SELECT, ["issuer"])
            .await
            .map_err(unavailable)?
            .assert_indexed()
            .map_err(unavailable)?;
        self.community
            .explain(INSERT, crlt::params!["issuer", 1i64, Vec::<u8>::new()])
            .await
            .map_err(unavailable)?
            .assert_indexed()
            .map_err(unavailable)?;
        self.community
            .explain(
                UPDATE,
                crlt::params![2i64, Vec::<u8>::new(), "issuer", 1i64],
            )
            .await
            .map_err(unavailable)?
            .assert_indexed()
            .map_err(unavailable)?;
        Ok(())
    }
}

fn unavailable(_: crlt::Error) -> StorageError {
    StorageError::Unavailable
}

impl Store for LibsqlStore {
    async fn load(&self, issuer: &str) -> Result<Option<StoredState>, StorageError> {
        let rows = self
            .community
            .query(SELECT, [issuer])
            .await
            .map_err(unavailable)?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let revision = row.get_i64(0).map_err(|_| StorageError::InvalidState)?;
        let crlt::Value::Blob(bytes) = row.get_value(1).map_err(|_| StorageError::InvalidState)?
        else {
            return Err(StorageError::InvalidState);
        };
        let state = SigningState::from_cbor(bytes).map_err(|_| StorageError::InvalidState)?;
        if revision <= 0 || state.key_ring().issuer() != issuer {
            return Err(StorageError::InvalidState);
        }
        Ok(Some(StoredState { revision, state }))
    }

    async fn compare_exchange(
        &self,
        expected: Option<i64>,
        state: &SigningState,
    ) -> Result<i64, StorageError> {
        let revision = next_revision(expected)?;
        let issuer = state.key_ring().issuer();
        let mut tx = self.community.tx().await.map_err(unavailable)?;
        let rows = tx.query(SELECT, [issuer]).await.map_err(unavailable)?;
        let current = rows
            .first()
            .map(|row| row.get_i64(0))
            .transpose()
            .map_err(unavailable)?;
        if current != expected {
            tx.rollback().await.map_err(unavailable)?;
            return Err(StorageError::Conflict);
        }
        let count = if let Some(previous) = expected {
            tx.execute(
                UPDATE,
                crlt::params![revision, state.to_cbor(), issuer, previous],
            )
            .await
        } else {
            tx.execute(INSERT, crlt::params![issuer, revision, state.to_cbor()])
                .await
        }
        .map_err(unavailable)?;
        if count != 1 {
            tx.rollback().await.map_err(unavailable)?;
            return Err(StorageError::Conflict);
        }
        tx.commit().await.map_err(unavailable)?;
        Ok(revision)
    }
}
