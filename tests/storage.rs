//! Real storage round trips and publication ordering.
#![cfg(all(feature = "signer", not(target_arch = "wasm32")))]

use csgn::{Kind, MemoryStore, PersistentSigner, SecretKey, SignError, StorageError, Store};

fn key(byte: u8) -> SecretKey {
    SecretKey::from_seed(&mut [byte; 32])
}

async fn round_trip<S: Store + Clone>(store: S) {
    let mut signer = PersistentSigner::create(store.clone(), "cmty:test", key(1), 100, 1000)
        .await
        .unwrap();
    let mut messages = Vec::new();
    for (index, kind) in Kind::ALL.into_iter().enumerate() {
        let expiry = 200 + index as u64;
        messages.push((
            kind,
            signer
                .sign(kind, b"opaque payload", 101, expiry)
                .await
                .unwrap(),
        ));
    }
    let saved = store.load("cmty:test").await.unwrap().unwrap();
    let encoded = saved.state.to_cbor();
    assert!(!encoded.windows(14).any(|w| w == b"opaque payload"));
    assert_eq!(saved.state.key_ring().active().unwrap().signed_until(), 0);
    drop(signer);
    let mut signer = PersistentSigner::open(store.clone(), "cmty:test", key(1), 102)
        .await
        .unwrap();
    signer.rotate(key(2), 103).await.unwrap();
    drop(signer);
    let mut signer = PersistentSigner::open(store.clone(), "cmty:test", key(2), 104)
        .await
        .unwrap();
    let ring = signer.key_ring().unwrap().clone();
    assert_eq!(ring.keys().len(), 2);
    for (kind, message) in &messages {
        assert_eq!(
            ring.verify(message, *kind, 150).unwrap().payload(),
            b"opaque payload"
        );
    }
    signer.prune(203).await.unwrap();
    assert_eq!(signer.key_ring().unwrap().keys().len(), 2);
    signer.prune(204).await.unwrap();
    assert_eq!(signer.key_ring().unwrap().keys().len(), 2);
    signer.prune(86_400).await.unwrap();
    assert_eq!(signer.key_ring().unwrap().keys().len(), 1);
    assert_eq!(
        signer.rotate(key(1), 204).await,
        Err(StorageError::Sign(SignError::KeyReused))
    );
    assert!(
        signer
            .sign(Kind::Credential, b"still usable", 86_400, 86_500)
            .await
            .is_ok()
    );
    assert!(matches!(
        PersistentSigner::create(store.clone(), "cmty:test", key(3), 204, 1000).await,
        Err(StorageError::Conflict)
    ));
    assert!(matches!(
        PersistentSigner::open(store.clone(), "cmty:test", key(1), 205).await,
        Err(StorageError::Sign(SignError::KeyMismatch))
    ));
    assert!(matches!(
        PersistentSigner::open(store.clone(), "missing", key(1), 205).await,
        Err(StorageError::Missing)
    ));
    assert_eq!(store.load("missing").await.unwrap(), None);
}

async fn stale_writer<S: Store + Clone>(store: S) {
    let mut old = PersistentSigner::create(store.clone(), "cmty:race", key(1), 10, 100)
        .await
        .unwrap();
    let delivered = old
        .sign(Kind::Credential, b"already delivered", 10, 99)
        .await
        .unwrap();
    let delivered_ring = old.key_ring().unwrap().clone();
    let mut newer = PersistentSigner::open(store.clone(), "cmty:race", key(1), 11)
        .await
        .unwrap();
    newer.rotate(key(2), 12).await.unwrap();
    assert_eq!(
        old.sign(Kind::Credential, b"must not escape", 13, 100)
            .await,
        Err(StorageError::Conflict)
    );
    assert_eq!(old.key_ring(), Err(StorageError::ReloadRequired));
    // Fencing protects future writes, not external publication. This is why the
    // issuer service must serialize issuance and ring distribution in one writer.
    assert!(
        delivered_ring
            .verify(&delivered, Kind::Credential, 13)
            .is_ok()
    );
    assert_eq!(
        old.rotate(key(3), 14).await,
        Err(StorageError::ReloadRequired)
    );
    let saved = store.load("cmty:race").await.unwrap().unwrap();
    assert_eq!(
        saved.state.key_ring().active().unwrap().key_id(),
        key(2).key_id()
    );
}

#[tokio::test]
async fn memory_round_trip_and_conflict() {
    let store = MemoryStore::default();
    round_trip(store.clone()).await;
    stale_writer(store).await;
}

#[tokio::test]
async fn memory_scopes_are_isolated() {
    let a = MemoryStore::default();
    let b = MemoryStore::default();
    PersistentSigner::create(a.clone(), "same", key(1), 1, 100)
        .await
        .unwrap();
    assert_eq!(b.load("same").await.unwrap(), None);
    PersistentSigner::create(b.clone(), "same", key(2), 1, 100)
        .await
        .unwrap();
    assert_ne!(a.load("same").await.unwrap(), b.load("same").await.unwrap());
}

#[cfg(all(feature = "libsql", not(target_arch = "wasm32")))]
mod database {
    use super::*;
    use crlt::{Config, Db, Migration};
    use csgn::{LibsqlStore, SCHEMA};

    async fn migrate(db: &Db) {
        let migrations = [Migration::new(1, "signing", SCHEMA)];
        db.migrate(&migrations).await.unwrap();
        assert_eq!(db.migrate(&migrations).await.unwrap(), 0);
    }

    async fn local() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("file://{}", dir.path().join("signing.db").display());
        let db = Db::open(Config::new(url, "")).await.unwrap();
        migrate(&db).await;
        (dir, db)
    }

    #[tokio::test]
    async fn libsql_round_trip_and_conflict() {
        let (_dir, db) = local().await;
        let store = LibsqlStore::new(db.community("community-a").unwrap());
        store.check_query_plans().await.unwrap();
        round_trip(store.clone()).await;
        stale_writer(store).await;
    }

    #[tokio::test]
    async fn close_and_reopen_database_preserves_exact_retention() {
        let (dir, db) = local().await;
        let store = LibsqlStore::new(db.community("community-a").unwrap());
        let mut signer = PersistentSigner::create(store, "cmty", key(1), 10, 100)
            .await
            .unwrap();
        let message = signer
            .sign(Kind::Credential, b"member", 11, 90)
            .await
            .unwrap();
        drop(signer);
        drop(db);
        let url = format!("file://{}", dir.path().join("signing.db").display());
        let db = Db::open(Config::new(url, "")).await.unwrap();
        migrate(&db).await;
        let store = LibsqlStore::new(db.community("community-a").unwrap());
        let mut signer = PersistentSigner::open(store, "cmty", key(1), 12)
            .await
            .unwrap();
        signer.rotate(key(2), 13).await.unwrap();
        assert_eq!(signer.key_ring().unwrap().keys()[0].signed_until(), 86_400);
        assert!(
            signer
                .key_ring()
                .unwrap()
                .verify(&message, Kind::Credential, 89)
                .is_ok()
        );
        signer.prune(90).await.unwrap();
        assert_eq!(signer.key_ring().unwrap().keys().len(), 2);
        signer.prune(86_400).await.unwrap();
        assert_eq!(signer.key_ring().unwrap().keys().len(), 1);
    }

    #[tokio::test]
    async fn two_communities_cannot_read_or_update_each_other() {
        let (_dir, db) = local().await;
        let a = LibsqlStore::new(db.community("a").unwrap());
        let b = LibsqlStore::new(db.community("b").unwrap());
        let mut signer = PersistentSigner::create(a.clone(), "same-issuer", key(1), 10, 100)
            .await
            .unwrap();
        assert_eq!(b.load("same-issuer").await.unwrap(), None);
        PersistentSigner::create(b.clone(), "same-issuer", key(2), 10, 100)
            .await
            .unwrap();
        let before = b.load("same-issuer").await.unwrap();
        signer
            .sign(Kind::Credential, b"private to a", 11, 100)
            .await
            .unwrap();
        signer.rotate(key(3), 12).await.unwrap();
        assert_eq!(before, b.load("same-issuer").await.unwrap());
        a.check_query_plans().await.unwrap();
        b.check_query_plans().await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_creates_and_updates_have_one_winner() {
        let (_dir, db) = local().await;
        let store = LibsqlStore::new(db.community("race").unwrap());
        let (a, b) = tokio::join!(
            PersistentSigner::create(store.clone(), "cmty", key(1), 10, 100),
            PersistentSigner::create(store.clone(), "cmty", key(2), 10, 100)
        );
        assert_ne!(a.is_ok(), b.is_ok());
        let saved = store.load("cmty").await.unwrap().unwrap();
        let (a, b) = tokio::join!(
            store.compare_exchange(Some(saved.revision), &saved.state),
            store.compare_exchange(Some(saved.revision), &saved.state)
        );
        assert_ne!(a.is_ok(), b.is_ok());
        assert!(a == Err(StorageError::Conflict) || b == Err(StorageError::Conflict));
    }

    #[tokio::test]
    async fn corrupt_rows_are_rejected_without_exposing_data() {
        let (_dir, db) = local().await;
        let scope = db.community("corrupt").unwrap();
        let store = LibsqlStore::new(scope.clone());
        PersistentSigner::create(store.clone(), "cmty", key(1), 10, 100)
            .await
            .unwrap();
        scope
            .execute(
                "UPDATE csgn_state SET state = ?1 WHERE issuer = ?2",
                crlt::params![b"invalid state".to_vec(), "cmty"],
            )
            .await
            .unwrap();
        assert_eq!(store.load("cmty").await, Err(StorageError::InvalidState));
    }

    #[tokio::test]
    async fn failed_commit_never_returns_a_signature_or_mutated_ring() {
        let (_dir, db) = local().await;
        let scope = db.community("failure").unwrap();
        let store = LibsqlStore::new(scope.clone());
        let mut signer = PersistentSigner::create(store, "cmty", key(1), 10, 100)
            .await
            .unwrap();
        // A real concurrent deletion forces a CAS failure, not a fake signer.
        scope
            .execute("DELETE FROM csgn_state WHERE issuer = ?1", ["cmty"])
            .await
            .unwrap();
        assert_eq!(
            signer
                .sign(Kind::Credential, b"must not escape", 11, 90)
                .await,
            Err(StorageError::Conflict)
        );
        assert_eq!(signer.key_ring(), Err(StorageError::ReloadRequired));
    }

    #[tokio::test]
    async fn cancellation_while_database_is_locked_requires_reload() {
        let (_dir, db) = local().await;
        let scope = db.community("cancel").unwrap();
        let store = LibsqlStore::new(scope.clone());
        let mut signer = PersistentSigner::create(store.clone(), "cmty", key(1), 10, 100)
            .await
            .unwrap();
        let before = store.load("cmty").await.unwrap();
        let lock = scope.tx().await.unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            signer.sign(Kind::Credential, b"cancelled", 11, 90),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(signer.key_ring(), Err(StorageError::ReloadRequired));
        lock.rollback().await.unwrap();
        // Cancellation may race a commit on remote stores. Reload is mandatory;
        // this locked local case cannot have reached the write.
        assert_eq!(store.load("cmty").await.unwrap(), before);
        let mut reopened = PersistentSigner::open(store, "cmty", key(1), 12)
            .await
            .unwrap();
        assert!(
            reopened
                .sign(Kind::Credential, b"resumed", 12, 90)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn database_timeout_during_rotation_requires_reload() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("file://{}", dir.path().join("timeout.db").display());
        let mut config = Config::new(url, "");
        config.timeout = std::time::Duration::from_millis(500);
        config.busy_timeout = std::time::Duration::ZERO;
        let db = Db::open(config).await.unwrap();
        migrate(&db).await;
        let scope = db.community("timeout").unwrap();
        let store = LibsqlStore::new(scope.clone());
        let mut signer = PersistentSigner::create(store.clone(), "cmty", key(1), 10, 100)
            .await
            .unwrap();
        let before = store.load("cmty").await.unwrap();
        let lock = scope.tx().await.unwrap();
        assert_eq!(
            signer.rotate(key(2), 11).await,
            Err(StorageError::Unavailable)
        );
        assert_eq!(signer.key_ring(), Err(StorageError::ReloadRequired));
        lock.rollback().await.unwrap();
        assert_eq!(store.load("cmty").await.unwrap(), before);
        let mut reopened = PersistentSigner::open(store, "cmty", key(1), 12)
            .await
            .unwrap();
        reopened.rotate(key(2), 13).await.unwrap();
        assert_eq!(
            reopened.key_ring().unwrap().active().unwrap().key_id(),
            key(2).key_id()
        );
    }

    #[tokio::test]
    async fn hostile_issuer_text_is_a_bound_value() {
        let (_dir, db) = local().await;
        let store = LibsqlStore::new(db.community("namespace").unwrap());
        let issuer = "cmty:' OR 1 = 1; --";
        let mut signer = PersistentSigner::create(store.clone(), issuer, key(1), 10, 100)
            .await
            .unwrap();
        let bytes = signer.sign(Kind::Credential, b"x", 11, 99).await.unwrap();
        assert_eq!(
            store
                .load(issuer)
                .await
                .unwrap()
                .unwrap()
                .state
                .key_ring()
                .issuer(),
            issuer
        );
        assert_eq!(store.load("cmty").await.unwrap(), None);
        assert!(
            signer
                .key_ring()
                .unwrap()
                .verify(&bytes, Kind::Credential, 12)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn optional_real_turso() {
        let (Ok(url), Ok(token)) = (std::env::var("TURSO_URL"), std::env::var("TURSO_TOKEN"))
        else {
            eprintln!("skipped: TURSO_URL and TURSO_TOKEN are not both set");
            return;
        };
        if url.is_empty() || token.is_empty() {
            eprintln!("skipped: TURSO_URL and TURSO_TOKEN must be nonempty");
            return;
        }
        // Requires a dedicated disposable database. No credentials are printed.
        let db = Db::open(Config::new(url, token))
            .await
            .expect("connect test database");
        migrate(&db).await;
        let scope_name = format!(
            "csgn-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let scope = db.community(scope_name).unwrap();
        let store = LibsqlStore::new(scope.clone());
        store.check_query_plans().await.unwrap();
        round_trip(store.clone()).await;
        stale_writer(store).await;
        for issuer in ["cmty:test", "cmty:race"] {
            scope
                .execute("DELETE FROM csgn_state WHERE issuer = ?1", [issuer])
                .await
                .unwrap();
        }
    }
}
