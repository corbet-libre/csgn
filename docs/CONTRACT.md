# csgn contract as implemented

Implements the csgn layer-0 contract of cvld and the v0.4 split: separate global
and community signing instances, own keys per issuer, Ed25519 COSE_Sign1,
rotation, retained public keys and verification on native and wasm32.

## API and responsibilities

| Interface | Contract |
|---|---|
| `SecretKey::from_seed(&mut [u8; 32])` | Loads a platform-secret-store seed and wipes the input buffer. No secret output API, serialization or Clone. `generate(CryptoRng)` generates an ephemeral non-exportable key. |
| `Signer::new(issuer, key, now, max_validity)` | Requires non-default `volatile-signer`. Volatile signing instance. Nonempty issuer, at most 256 bytes, no NUL; nonzero maximum lifetime. |
| `sign(kind, payload, now, valid_until)` | Tagged COSE_Sign1 with attached opaque payload; `now < valid_until`, lifetime bounded by configured maximum, payload at most 1 MiB. |
| `KeyRing::verify(cose, expected_kind, now)` | Returns `Verified` payload, kind, key ID, issued time and expiry only after all checks. `Signer::verify` delegates. |
| `rotate(new_key, now)` | Replace the active secret, retiring its public key and retaining it until everything it signed expires. Reject all previously used key IDs, including pruned ones. |
| `prune(now)` | Remove expired retired public keys. Never remove used-ID tombstones. |
| `key_ring()` | Public keys, maximum lifetime, activation/retirement and rounded retired retention times; no active issuance progress. CBOR import/export; no secret material. |
| `state()` / `resume(SigningState, key, now)` | Exact recovery metadata; resume requires the active secret and a nondecreasing clock. No approximate recovery from a public ring. Low-level caller must persist before publication. |
| `PersistentSigner::create(store, issuer, key, now, max_validity)` | Create-only atomic persistence. Existing issuers cannot be overwritten. |
| `PersistentSigner::open(store, issuer, key, now)` | Read exact state and atomically advance its revision to fence older writers. |
| Persistent `sign`, `rotate`, `prune` | Async; commit state before returning output or exposing changed ring. On failed/cancelled persistence, all further operations require reopening. Validation errors leave state usable. |

Kinds: `Credential`, `SettingsSnapshot`, `SchemaSnapshot`,
`CommunitiesSnapshot`, `RevocationListSnapshot`. Every object has a finite expiry.
All times are caller-supplied unsigned Unix seconds; successful signing, rotation,
pruning and resume require time at least the last successful operation's time.
Credentials' community, member pseudonym, handle, gates with expiry, pins, schema
version and policy epoch are validated by the issuing facade. Snapshot community,
revision, policy epoch and content are likewise caller-owned. csgn binds opaque
bytes to a protected kind, issuer, issued time, expiry and key ID; payload fields
must agree with these authenticated values. No raw gate evidence is accepted by
the product contract; the opaque byte API cannot inspect or enforce its semantics.

## Message and public-ring formats

Tagged `18([protected_bstr, {}, payload_bstr, signature_bstr])`; external AAD is
empty.

The outer bytes must equal coset's tagged re-encoding byte for byte. Alternate
length/tag encodings and indefinite byte strings are rejected even when their
signatures verify. Protected header bytes are preserved, since they are signed.
Exactly these protected header labels:

| Label | Value |
|---|---|
| 1 | -19, fully specified Ed25519 (RFC 9864), not generic EdDSA -8 |
| 2 | Required critical labels `[15, -65537]` (either order), each exactly once; no other labels |
| 4 | 32-byte RFC 9679 COSE key thumbprint: SHA-256 of deterministic CBOR `{1: 1, -1: 6, -2: public_key}` |
| 15 | RFC 9597 CWT claims `{1: issuer_text, 4: expiry_uint, 6: issued_uint}` |
| -65537 | `credential`, `snapshot/settings`, `snapshot/schema`, `snapshot/communities`, `snapshot/revocation-list` |

Ring: CBOR `{1: 2, 2: issuer, 3: [COSE_Key, ...], 4: max_validity}`. Each COSE_Key has `1: 1`
(OKP), `2: kid`, `3: -19`, `4: [2]` (verify only), `-1: 6` (Ed25519),
`-2: public_key`, `-65537: activated_at`, optional `-65538: retired_at`,
`-65539: signed_until` only on retired keys. The active key omits both retirement
and retention fields; its `signed_until()` getter returns zero. The retired
deadline is the latest expiry rounded up to a UTC day (saturating at `u64::MAX`),
or zero if unused. Pruning uses that rounded deadline; message expiry stays exact.
Imported rings may contain zero active keys for verification, but at most one; resumable state requires exactly one. At most 1,024 public keys and 256 KiB
encoded ring. `max_validity` is a required nonzero unsigned lifetime in seconds,
available through `KeyRing::max_validity()`. The ring must be authenticated and
bound to the expected issuer by the application; parsing it does not authenticate it.

## Verification and rotation rules

- Only Ed25519, tag 18 and attached payloads are supported. Trailing bytes,
  duplicate/unknown labels, unexpected fields even when empty, unknown versions,
  private key material, invalid/weak keys and incorrect thumbprints are refused.
- Verification order: allocation-free outer shape check → bounded full decode and
  byte-equal re-encoding → known key → key not expired → strict signature → issuer
  → expected kind → maximum lifetime → key period → issued/expiry validity.
  The shape check uses ciborium-ll: tag 18, four-element array, protected bstr at
  most 4,096 bytes, empty map, payload bstr at most 1 MiB, signature bstr exactly
  64 bytes, no trailing input. Indefinite lengths are rejected before allocation.
- A message requires `expiry - issued <= max_validity` (otherwise `ValidityTooLong`),
  `issued <= now < expiry` and `activated_at <= issued`.
  A retired key additionally requires `issued <= retired_at`,
  `expiry <= signed_until` and `now < signed_until`.
- Issuance in the retirement second is valid, allowing same-second sign/rotate.
  At message expiry, verification returns `Expired` while the key remains within
  retention; at the rounded retention deadline it returns `KeyExpired`; after
  pruning it returns `UnknownKey`.
- Signing updates the maximum expiry, never the most recent expiry alone.
  Refused operations do not change state. A retired unused key is pruned at once.
- Clock regression is refused even within one active key period. Maximum lifetime
  stays part of recovery state. Up to 16,384 used key IDs are retained; exhaustion
  refuses further rotation. No key reuse or history reset API exists.
- Retirement is not emergency revocation: a compromised key can backdate a
  signature. Freshness/epochs, replay policy and emergency revocation belong to
  the application and future contract extensions.

## Storage contract

`Store::load(issuer) -> Option<StoredState>` and
`Store::compare_exchange(expected_revision, state) -> new_revision` operate
inside one fixed, authorized community scope. One writer per issuer must serialize
issuance and external ring publication. Fencing protects future store mutations,
not rings already read or delivered; it is not a multi-writer publication protocol.
Replacement is atomic, success means durable commit, revisions are positive i64 values which never wrap or reset.
Missing expected revision means create-only; stale revisions produce `Conflict`.
Implementations must not log values or store private keys or signed payloads.

`MemoryStore` is a real volatile implementation; clones share its scope and new
instances are isolated. Native feature `libsql` provides `LibsqlStore` over the
ready `crlt` git dependency, pinned by full revision
`6b94dacd7fa04aa8847c62c6471a1fc5c0f6c9dc` in the manifest and lockfile.
The official libSQL client is reached only through crlt. A `crlt::Community` capability injects namespace constraints. Schema:

```sql
CREATE TABLE csgn_state (
    community_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    state BLOB NOT NULL,
    PRIMARY KEY (community_id, issuer)
) WITHOUT ROWID;
```

The service appends `SCHEMA` to its own numbered migration history. It owns
one-database-per-community routing; cgbl uses its separate database. All reads and
updates use the composite primary key, inserts check it, and adapter query plans
are tested with `EXPLAIN QUERY PLAN` and enforced by crlt.

Private state CBOR: `{1: 2, 2: ring_cbor_bstr, 3: max_validity, 4: clock_high_water,
5: [used_kid_bstr, ...], 6: exact_active_signed_until}`; at most 1 MiB.
No secrets, payloads, member identifiers, login dates, request logs or raw evidence. The clock is a single per-issuer
coordination value, not a history. The active deadline is exact across restart;
it is rounded only on retirement. Never publish recovery state. Version 1 rings
and states are rejected; they require an explicit trusted migration. The maximum
lifetime in private state must equal the public ring policy. Existing messages
without `crit` require reissuance. Public Rust method signatures are preserved;
`Signer` now requires explicit feature opt-in, active `signed_until()` returns zero,
and short signatures return `Malformed` at shape validation. Database
failure/cancellation may have an unknown commit outcome; the instance becomes
unusable. Reload current state and its matching secret-store key. Provision a
rotation key before the transaction and retain provisioning references until its
outcome is known. Store integrity and rollback protection are deployment duties.

## Platform and validation

Default feature `signer` provides persistent signing and generic storage;
non-default `volatile-signer` exposes low-level `Signer`; no default features
provides verification only. All library feature configurations build for
`wasm32-unknown-unknown`; native libSQL is excluded on wasm. Rust stable, LGPL-3.0-only
WITH LGPL-3.0-linking-exception, no GPL/AGPL-only dependencies, no own primitives.

Tests include independent vectors; every kind; issuer separation; payload,
header, ID and signature tampering; signature malleability and weak keys;
truncated, nested, duplicate and oversized CBOR; expiry and clock boundaries;
rotation, exact restart and reuse prevention; real libSQL reopen, namespace
isolation, competing writers, failed/cancelled publication, corruption and index
plans. CI checks fmt, Clippy, tests, full git revision pins and wasm32 builds.
The identical independent vectors execute natively and on `wasm32-wasip1` under
Wasmtime, for verification-only and signing configurations, along with adversarial
regressions. Browser (`wasm32-unknown-unknown`) integration remains compile-only. An optional real Turso test skips
unless both `TURSO_URL` and `TURSO_TOKEN` are nonempty; never supply secrets in
public CI.

Open boundaries: emergency key revocation, authenticated ring distribution,
rollback-proof database recovery, payload authorization/replay/epoch policy and
process-memory hardening are not implemented here. `zeroize` protects owned
buffers; it cannot guarantee removal of caller or compiler-created copies.


## Key-ring continuity and pending publication

The signer atomically persists a public ring transition proof with the successor
state before releasing either. Rotation endorses with the old active key before
wiping it; pruning also requires an endorsement. Only a ring change increments
the independent public sequence. CAS revisions remain private activity metadata.
A pending proof blocks another ring change until the consumer durably retains
it and acknowledges that exact revision. Failure/cancellation fences the signer;
reopen recovers the stored original proof, never regenerates it under a new key.

`verify_transition` checks the dedicated kind, signature, public ring encodings,
issuer and predecessor active signing key using existing primitives. It does not
choose initial trust, compare the predecessor with installed state, accept a
revision floor or install the successor. Those policy checks belong to Charter.
Use the configured ring, never one supplied by the response under evaluation.
The producer keeps a bounded chain of original proofs; unavailable or expired
history must fail closed until explicit configuration refresh.

State v3 reads existing v2 with ring revision zero. It adds only a u64 sequence
and optional public COSE transition; maximum private encoded state is two MiB.
The new TrustManifest kind is separate from settings and transition kinds.
