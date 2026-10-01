# csgn

Ed25519 COSE credentials and snapshots, with private signing keys and a public
verification ring. Part of `cvld`. Development API; never publish to a registry.
The [implemented contract](docs/CONTRACT.md) specifies the wire and storage formats.

## API

- `SecretKey::from_seed(&mut seed)` consumes a platform-provided 32-byte seed and
  wipes the supplied buffer. `SecretKey::generate(rng)` creates an ephemeral key
  internally; it cannot be exported for later recovery.
- With explicit feature `volatile-signer`, `Signer::new(issuer, key, now, max_validity)`
  creates a volatile signer.
  `sign(kind, payload, now, valid_until)` returns tagged COSE_Sign1 bytes.
- `KeyRing::verify(cose, expected_kind, now)` returns `Verified` metadata and
  payload only after signature, issuer, kind, maximum lifetime, key-period and time checks.
  `max_validity()` exposes the bound carried by the authenticated public ring.
- `rotate(new_key, now)` retains the old public key until a rounded deadline
  after the latest expiry it signed. `prune(now)` removes expired public keys. `key_ring()` publishes only
  public keys; `to_cbor` / `from_cbor` handle transport.
- `PersistentSigner::create` / `open` use `Store`, with `MemoryStore` and
  `LibsqlStore` implementations. Persistent `sign`, `rotate` and `prune` are async.
  Use this API for production issuance: it commits exact recovery metadata before
  returning a credential or exposing a changed ring.

One issuer and independent keys per global service and per community; use unique,
fully scoped issuer names, e.g. `cmty:example` and `cglb:platform`. Times are unsigned
Unix seconds supplied by the caller. The maximum lifetime is explicit policy
(e.g. 30 days); every kind, including snapshots, has an expiry. Credentials and
snapshots are opaque payloads: their owners validate member fields, revisions,
epochs, gates and schema semantics. Never pass raw gate evidence to this crate.

For an explicitly volatile test issuer, enable `volatile-signer`:

```rust
use csgn::{Kind, SecretKey, Signer};

// Test-only seed. Production seeds come from the platform secret store.
let key = SecretKey::from_seed(&mut [1; 32]);
let mut signer = Signer::new("cmty:example", key, 100, 30 * 86_400)?;
let cose = signer.sign(Kind::Credential, b"validated credential", 100, 200)?;
let verified = signer.key_ring().verify(&cose, Kind::Credential, 150)?;
assert_eq!(verified.payload(), b"validated credential");
# Ok::<(), Box<dyn std::error::Error>>(())
```

| Feature | Default | Content |
|---|---|---|
| `signer` | yes | Secret key ownership, persistent signer, storage trait and memory store |
| `volatile-signer` | no | Low-level `Signer` and manual commit-before-publication responsibility; includes `signer` |
| `libsql` | no | Native `LibsqlStore` via `crlt`; includes `signer` |
| no default features | — | Public-ring verification only, including wasm32 |

The database dependency is native-only. Default, verifier-only and all-features
library configurations compile for `wasm32-unknown-unknown`; the native libSQL
adapter is absent there. The crate uses `std`, not a `no_std` API.

## Dependencies: survey and choice

Checked crates.io releases and upstream APIs on 2026-09-30. No cryptographic
primitive or CBOR parser is implemented here.

| Need | Candidates and decision |
|---|---|
| COSE | [coset 0.4.2](https://github.com/google/coset) (Apache-2.0) supplies Sign1, Sig_structure, headers and COSE keys. Selected over [cose-rust 0.1.8](https://github.com/tramires/cose-rust) (MIT) for its crypto-independent interface and wasm-friendly Rust CBOR stack. AWS Nitro's COSE adapter and the SSI stack add unrelated platform/dependency surface. |
| Bounded shape inspection | [ciborium-ll 0.2.2](https://github.com/enarx/ciborium) (Apache-2.0), already in coset's dependency graph, supplies an allocation-free token decoder. Chosen over adding another CBOR stack or writing a parser. It checks the fixed outer layout and skips bounded byte strings before full decoding. |
| Ed25519 | [ed25519-dalek 3.0.0](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/ed25519-dalek) (BSD-3-Clause) supplies signing and `verify_strict`. [ed25519-compact 2.6.0](https://github.com/jedisct1/rust-ed25519-compact) is maintained and MIT; dalek provides the requested strict-verification and zeroization interfaces. `ring`/`aws-lc-rs` introduce native toolchains; zebra targets ZIP-215 consensus semantics. |
| Secret memory | [zeroize 1.9](https://github.com/RustCrypto/utils/tree/master/zeroize) (MIT/Apache-2.0), also used by dalek. No export-capable secrecy wrapper is needed. |
| Key IDs | [sha2 0.11](https://github.com/RustCrypto/hashes/tree/master/sha2) (MIT/Apache-2.0), also used by dalek, hashes the fixed RFC 9679 public-key encoding. |
| Randomness | `rand_core 0.10` traits: the caller supplies a CSPRNG. No OS RNG backend in the library; `getrandom` is test-only. |
| Persistence | [crlt](https://github.com/corbet-foss/crlt/tree/6b94dacd7fa04aa8847c62c6471a1fc5c0f6c9dc) already exposes scoped transactions, migrations and index checks. Pin its git dependency by full `rev` (`6b94dacd7fa04aa8847c62c6471a1fc5c0f6c9dc`), checked against `Cargo.lock` in CI, over the official [libsql 0.9.30](https://github.com/tursodatabase/libsql) client. No direct libSQL fallback is needed. `crlt` carries the same LGPL linking exception; its dependencies are permissively licensed. |

`tokio`, `getrandom` and `tempfile` are native test-only direct dependencies. No dependency is available
only under GPL or AGPL. The 220 registry packages in the initial CI lock were
checked against crates.io license metadata; none requires GPL or AGPL. There are
no dependencies on unfinished cvld leaf APIs.

## Security decisions

**Secret ownership.** No seed/private-key getter, serialization, `Clone`, `Deref`
or seed-returning generator exists. Debug shows public identifiers only. The
boxed dalek key is erased by dalek's `zeroize` feature on replacement/drop; input
seeds and generation buffers are wiped with `zeroize`. Heap ownership avoids
copies on ordinary wrapper moves. This is not protection against process-memory
compromise, swap/core dumps, caller copies or compiler-created stack/register
copies during construction. We do not claim to prove freed-memory erasure with
an unsafe inspection test. The service must protect its secret-store inputs.

**Strict, bounded verification.** Only tagged COSE_Sign1, attached payloads,
empty unprotected headers and Ed25519 algorithm -19 (RFC 9864) are accepted.
The algorithm, key ID, issuer, kind, issuance and expiry are protected. Required
`crit` lists both kind and CWT claims; missing, duplicate or unknown critical
labels are rejected. Verifiers enforce the ring's published maximum lifetime. `coset`
constructs the signature input from the original protected bytes; dalek's
`verify_strict` rejects weak keys and signature malleability. Raw-map validation
also rejects duplicate/unknown labels and empty optional fields which a generic
COSE decoder might normalize away. Key rings reject private `d` parameters and
IDs that do not match their public-key thumbprints. Parsers bound input sizes;
CBOR decoding and its recursion limit come from coset/ciborium. An allocation-free
outer-shape check runs before recursive decoding, including header/payload bounds
and the exact 64-byte signature length.
The outer COSE bytes must equal `coset::to_tagged_vec()` re-encoding: long
lengths/tags, overlong empty maps and indefinite byte strings are rejected.
Original protected bytes stay signature-bound, preserving their signed identity.

Messages require `issued <= now < expiry`. Successful signer operations require
nondecreasing time, including restart and pruning, to prevent rotation from
invalidating previously issued credentials. Multiple operations in one second
are supported; the retirement second is inclusive. Rotation cannot prevent a
compromised old key from backdating a forgery into its valid window. Emergency
key revocation is a separate, currently unimplemented operation.

**Crash and concurrency safety.** Run one writer per issuer and serialize issuance
and public-ring distribution through it. Revision fencing stops stale mutations;
it cannot retract a ring read before another process rotates the key or coordinate
publication outside the store. The private key is never stored in the database.
Private recovery state contains the public ring, exact active retention deadline,
maximum lifetime, one aggregate clock
high-water mark and used key IDs. It contains no credential bytes, member IDs,
login dates, request history or raw gate evidence. Every mutation uses a
transactional revision compare-and-swap. An older writer cannot overwrite a
rotation. No signature escapes before its retention deadline commits. Failed or
cancelled persistence disables the instance, including access to its potentially
stale ring. Reopen against current state and the matching secret-store key;
never retry a mutation blindly after an uncertain remote commit.

Provision the next seed in the platform secret store **before** rotation and keep
both provisioning references until the database outcome is known. On recovery,
load the private recovery state to discover which active key to request. `open` itself
claims a new revision, fencing previous writers. A verifier holding an older
published ring must refresh through an authenticated channel; already delivered
rings and signatures cannot be retracted by fencing a server process.

The public ring omits active-key `signed_until` entirely (its getter returns zero).
Signing never changes that ring. On retirement, the deadline is rounded up to a
UTC day, saturating at `u64::MAX`; pruning uses this same rounded deadline so
removal cannot reveal the exact expiry. Message expiry remains exact.
Recovery blobs are private operational data and must never be published.
Public rings and recovery state now use format version 2; version 1 is rejected.
Existing COSE messages without the required `crit` header must be reissued;
re-encoding cannot add a signed header. Ring v2 requires nonzero `max_validity`.
Short signatures now fail shape validation with `Malformed`, not `BadSignature`.

`Signer` is intentionally volatile; `state()` / `resume(state, key, now)` are
low-level primitives for callers implementing their own commit-before-publication
protocol. A published `KeyRing` is insufficient recovery state. No recovery-time
retention estimates or per-request logs are used. Used key-ID tombstones prevent
reusing an old key even after its public key is pruned. Bounds: 1 MiB payload,
256-byte issuer, 1,024 retained public keys, 16,384 lifetime key IDs. Exhaustion
fails closed; plan a new issuer lifecycle before reaching the history limit.

**Trust boundary.** A ring must arrive over an authenticated, freshness-protected
channel and be associated with the expected issuer by the caller. Importing an
attacker-supplied ring does not establish trust. Database integrity and rollback
protection are deployment responsibilities: revisions stop concurrent writers,
not restoration of an old backup. Verification is not an authorization decision,
revocation-list evaluation or replay detector; callers enforce epochs, revisions,
payload semantics and freshness. Do not enable SQL/HTTP debug tracing of inputs.

## Storage integration

Enable `libsql`, append `csgn::SCHEMA` to the service-owned ordered
`crlt::Migration` history, and pass a `crlt::Community` to `LibsqlStore::new`.
The service owns numbering and migration execution; this library does not assume
it is the only schema user. Apply the complete migration history on reopening.

Use one database per community; `cglb` has a separate database and scope. The
single `csgn_state` table has primary key `(community_id, issuer)` and stores a
revision plus a private recovery metadata blob. `crlt` injects the community key into every
statement and enforces indexed plans. `check_query_plans` checks every adapter
statement using `EXPLAIN QUERY PLAN`. Never delete/reset a live issuer row or
restore stale state while its credentials remain valid.

## Validation

GitHub Actions runs formatting, Clippy with warnings denied, native tests (default,
all features, verification only), wasm32 library checks, and execution of the same
independent vectors and security regressions on `wasm32-wasip1` with
[Wasmtime](https://docs.wasmtime.dev/cli.html). `wasm32-unknown-unknown` remains
a compile check; WASI execution does not claim browser integration coverage.
Cargo is never run on the workstation. CI retains its resolved lockfile as an artifact; committed locks
keep the same dependency identity on subsequent runs.

Independent fixtures can be regenerated with `scripts/generate-vectors.py` using
Python `cryptography` and `cbor2`, without csgn or coset. `scripts/check-dependency-pins.py`
checks that reviewed git revisions match the lockfile.

Tests cover all five kinds, independent COSE vectors, every single-bit message
mutation, weak keys/signatures, malformed and oversized CBOR, expiry boundaries,
clock regression, rotation and reuse after pruning. Storage tests use a real
in-memory implementation and real local libSQL files: restart, concurrency,
namespace isolation, corruption, cancellation, failed publication and query plans.

`optional_real_turso` runs only with nonempty `TURSO_URL` and `TURSO_TOKEN`.
Otherwise it reports a skip and returns. Use a dedicated disposable database on
an approved runner: the test migrates it and writes/removes synthetic test rows.
Never put credentials into this repository or public CI. Local libSQL tests do
not constitute evidence of a live Turso run.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).

## Continuous verification

Dependency updates follow main and are tested against one CI-resolved lockfile.
Line and branch coverage target 100%; failures remain blocking. See
[the coverage contract](docs/COVERAGE.md) for measurement and exclusions.
