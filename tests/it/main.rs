//! The crate's native integration tests in one binary.
//!
//! `genesis`, `signing` and `storage` were per-file binaries; they are modules here now, so the
//! warm edit loop links one test executable. `adversarial`, `ring`, `transitions` and `vectors`
//! stay separate: the repo's wasm32/wasip1 CI legs drive them by name
//! (`.ci/verify.sh:23-24`).
mod genesis;
mod signing;
mod storage;
