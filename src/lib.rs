//! Ed25519 COSE signing and verification for one trusted issuer.
//!
//! Use `PersistentSigner` with a `Store` for commit-before-publication ordering.
//! The low-level `Signer` requires the non-default `volatile-signer` feature.
//! Verification requires only [`KeyRing`].
#![cfg_attr(
    not(feature = "volatile-signer"),
    doc = "\n```compile_fail\nuse csgn::Signer;\n```"
)]
#![forbid(unsafe_code)]

mod cose;
#[cfg(all(feature = "libsql", not(target_arch = "wasm32")))]
mod database;
mod key_id;
mod kind;
mod ring;
#[cfg(feature = "signer")]
mod signer;
#[cfg(feature = "signer")]
mod state;
#[cfg(feature = "signer")]
mod storage;

#[cfg(all(feature = "libsql", not(target_arch = "wasm32")))]
pub use database::{LibsqlStore, SCHEMA};
pub use key_id::{KEY_ID_LEN, KeyId};
pub use kind::Kind;
pub use ring::{KeyEntry, KeyRing, RingError, Verified, VerifyError};
#[cfg(feature = "volatile-signer")]
pub use signer::Signer;
#[cfg(feature = "signer")]
pub use signer::{SEED_LEN, SecretKey, SignError};
#[cfg(feature = "signer")]
pub use state::SigningState;
#[cfg(feature = "signer")]
pub use storage::{MemoryStore, PersistentSigner, StorageError, Store, StoredState};

/// Maximum attached payload size (one MiB).
pub const MAX_PAYLOAD_LEN: usize = 1 << 20;
/// Maximum issuer size in UTF-8 bytes.
pub const MAX_ISSUER_LEN: usize = 256;
/// Maximum number of simultaneously published public keys.
pub const MAX_RING_KEYS: usize = 1024;
/// Maximum number of key IDs retained to prohibit reuse, including pruned keys.
pub const MAX_USED_KEYS: usize = 16384;
