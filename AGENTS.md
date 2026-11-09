# csgn agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run commands from the lane root (`<lane>/ws`); `<lane>` below is your lane name.

Build and test (quote the verdict line, never infer from a pipe):
- `~/agents/scratch/cbuild <lane> test -p csgn` — green, exit 0; same with
  `--all-features` and `--no-default-features` (feature-gated suites differ).
  `optional_real_turso` skips without `TURSO_URL`+`TURSO_TOKEN`.
- `cargo fmt -p csgn -- --check` and `clippy -p csgn --all-targets -- -D warnings`
  — clean/green at HEAD.
- `check -p csgn --target wasm32-unknown-unknown` — green, exit 0
  (default verifier-only config builds for wasm; wasmtime execution is CI-only).
- Full gate (locked deps, all-features/no-default clippy+test, wasip1 vectors,
  coverage) runs in CI only: `.ci/verify.sh`. Lane `--locked` needs CI's
  resolve refresh.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test):
- Every single-bit message mutation is refused; alternate outer encodings
  cannot change a signed object's byte identity
  -> `tests/it/adversarial.rs::every_single_bit_mutation_of_a_message_is_refused`,
  `alternate_outer_encodings_cannot_change_a_signed_objects_byte_identity`
- Key IDs are RFC 9679 thumbprints; swapped/unknown/weak keys refused
  -> `tests/it/signing.rs::key_id_is_the_thumbprint_of_the_public_key`,
  `key_id_swapped_to_another_ring_key_is_rejected`,
  `tests/it/ring.rs::invalid_and_weak_public_keys_are_refused`
- Rotation keeps old credentials valid; pruned IDs stay unusable; failed
  commits return no signature -> `tests/it/storage.rs::close_and_reopen_database_preserves_exact_retention`,
  `tests/it/signing.rs::pruned_keys_cannot_be_reused_even_after_restart`,
  `tests/it/adversarial.rs::failed_commit_never_returns_a_signature_or_mutated_ring`
- No secret output: debug shows public identifiers only; recovery metadata
  holds no member data -> `tests/it/ring.rs::secret_key_material_is_refused`
- Clocks never regress; messages expire at `valid_until`
  -> `tests/it/signing.rs::future_messages_and_clock_rollback_are_rejected`,
  `message_expires_at_valid_until`
- No login dates, request logs, or raw gate evidence accepted
  (`docs/CONTRACT.md`); `forbid(unsafe_code)` (`src/lib.rs`).

Pointers: `src/`, `tests/`, `scripts/check-dependency-pins.py`,
`docs/CONTRACT.md`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
`publish=false`; LGPL-3.0-only WITH linking exception; no registry publication.
