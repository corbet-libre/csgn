//! Real in-memory corruption and poisoned-lock failures at the storage boundary.

use super::*;

fn key() -> SecretKey {
    SecretKey::from_seed(&mut [7; 32])
}

#[tokio::test]
async fn poisoned_store_refuses_reads_and_writes() {
    let store = MemoryStore::default();
    let state = Signer::new("issuer", key(), 10, 100).unwrap().state();
    store.compare_exchange(None, &state).await.unwrap();
    let broken = store.clone();
    let panic = std::thread::spawn(move || {
        let _guard = broken.0.lock().unwrap();
        panic!("simulate a panic while the real storage lock is held");
    });
    assert!(panic.join().is_err());
    assert_eq!(store.load("issuer").await, Err(StorageError::Unavailable));
    assert_eq!(
        store.compare_exchange(Some(1), &state).await,
        Err(StorageError::Unavailable)
    );
}

#[tokio::test]
async fn corrupt_revisions_and_namespaces_never_resume_a_signer() {
    for (revision, issuer) in [(0, "issuer"), (-1, "issuer"), (1, "other")] {
        let store = MemoryStore::default();
        let state = Signer::new(issuer, key(), 10, 100).unwrap().state();
        store
            .0
            .lock()
            .unwrap()
            .insert("issuer".into(), StoredState { revision, state });
        assert!(matches!(
            PersistentSigner::open(store, "issuer", key(), 10).await,
            Err(StorageError::InvalidState)
        ));
    }
    let state = Signer::new("issuer", key(), 10, 100).unwrap().state();
    for revision in [-1, 0, i64::MAX] {
        let store = MemoryStore::default();
        store.0.lock().unwrap().insert(
            "issuer".into(),
            StoredState {
                revision,
                state: state.clone(),
            },
        );
        let before = store.load("issuer").await.unwrap();
        assert_eq!(
            store.compare_exchange(Some(revision), &state).await,
            Err(StorageError::InvalidState)
        );
        assert_eq!(store.load("issuer").await.unwrap(), before);
    }
}
