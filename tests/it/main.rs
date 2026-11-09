//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`it::<name>::<test>`). The gates stay inside the moved files: `adversarial` and
//! `transitions` need `volatile-signer`, `storage` needs the native `signer` store.
//! `vectors` and `ring` run on every platform, which is why the wasip1 CI leg drives the
//! same binary. `genesis` and `signing` keep their native gate in this file: the wasip1
//! leg selects the same suites it always did (vectors, ring, adversarial, transitions).
mod adversarial;
#[cfg(all(feature = "volatile-signer", not(target_arch = "wasm32")))]
mod genesis;
mod ring;
#[cfg(all(feature = "volatile-signer", not(target_arch = "wasm32")))]
mod signing;
mod storage;
mod transitions;
mod vectors;
