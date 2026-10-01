# Coverage contract

CI targets 100% of reachable production lines and branches. Stable Rust runs
the existing native and wasm checks. Nightly Rust is used only for LLVM branch
instrumentation, which currently requires it. Both jobs use the same resolved
Cargo.lock snapshot; all build and test commands after resolution use --locked.

The coverage job executes real tests with cargo-llvm-cov and retains the raw JSON
even when the gate fails. The checker compares integer covered/total counts for
both metrics; rounded percentages cannot pass. An empty report cannot pass.
The report excludes integration-test harness files under tests/, not production
code. The source-specific proposed exceptions below require independent review.

A failing gate is missing evidence, not permission to lower the threshold or
change domain behavior. Add meaningful failure and round-trip tests. Document
any genuinely unreachable defensive branch precisely before excluding it. Native
coverage does not establish browser execution; keep the actual wasm vectors.

First-party dependencies follow main. Their resolved full revisions remain in
Cargo.lock, with exactly one source per first-party crate. Dependabot maintains
committed snapshots; CI refreshes once per run and retains the tested snapshot.
Auto-merge requires protected main and successful substantive checks on the
exact current Dependabot head. It never executes PR code with write permissions.

## Emitted source metric

The acceptance metric is now 100% of upstream LLVM LCOV's emitted production
source line counters (DA) and branch counters (BRDA), from the same execution as
the retained raw JSON. This is source coverage, not every generic instantiation.
LLVM JSON and LCOV summary totals can count generic copies differently from
the merged source records. The original JSON checker remains diagnostic code;
its stricter instantiation totals are not described as passed.

The source gate requires a nonempty report, an exact file inventory matching the
companion JSON, matching raw summary metadata, complete emitted branch counts
and no duplicate or unknown counters. Every reachable source counter must be positive.
Only the exact documented exceptions below are proposed; no function or file is omitted.
Actual browser/device execution remains separate from native coverage.

## Proposed unreachable defensive paths

Native/default/verifier/all-feature and actual Wasmtime vectors passed at
4e79494a96d9f4ed8de82fc6366d384c9963e295 in
[CI36915156803](https://github.com/corbet-foss/csgn/actions/runs/36915156803).
Before proposed exceptions and the subsequent canonical-envelope and imported
multirow regressions, source coverage was1255/1274 lines and260/280 branches.
The manifest proposes17 exact unexecuted lines and19 exact branch arms below.
Independent review is mandatory; CI success alone is not security acceptance.
No signing, verification or persistence behavior was edited for coverage.

The checker first validates all raw JSON/LCOV/annotated file, line and branch
inventories. Exceptions identify one source line or branch arm and hash every
local source file that owns the invariants. Moved/changed source, absent counters
and newly executed exceptions fail closed. The opposite arms remain measured.
Dependencies still follow main, refresh once in CI and run actual crypto/storage
vectors; these source hashes do not pin dependency versions or suppress tests.

### Validated COSE shape

`parse` calls `check_shape` before allocating a recursive Value. Its upstream
ciborium-ll token decoder requires tag18 and a definite four-part array, then
bounded protected bytes, an empty map, bounded payload bytes and64 signature
bytes with no trailing input. The repeated semantic shape checks after Value
conversion cannot fail: lines136,139,142–144,147,150,163,178,181 and their exact
manifest arms are defensive restatements. Truncated, deeply nested, oversized,
detached, unprotected-field and malformed-signature vectors continue to refuse
through the real earlier gate. Alternative nonminimal outer encodings are a
separate reachable canonicalization refusal and have a real signed-byte test;
the rejection at line175 is deliberately not excluded.

### Raw header allowlist

Before coset interprets a protected header, `int_map` rejects noninteger or
duplicate labels and the allowlist permits only1,2,4,15 and-65537. Consequently
content type, IV, partial IV and countersignatures cannot be present at195–198;
the `header.rest` wildcard at212 cannot receive a different label. Critical-label
membership and malformed kind/claims remain reachable, tested and fully gated.

### Raw public key allowlist

`KeyRing::from_cbor` checks the raw key map before coset can normalize empty
optional fields. Only the declared key type, key ID, algorithm, operations,
curve/public key, forbidden-secret marker and activation/retirement/retention
labels survive. Thus base IV at134, a text label at140 and leftover unknown
parameters at176 cannot reach the private decoder. Their earlier public refusal
paths, including empty optional and duplicate labels, run natively and on wasm.

### Private signer invariant

`Signer` fields are private. `new` derives the sole active entry from the owned
key, `resume` compares that key against the validated state before constructing
it, and rotation installs the newly derived ring and key together without an
intervening await or callback. The extra key-ID mismatch check at185–186 cannot
fail through these public operations. Wrong resume keys, stale clocks, reused
keys, full rings and cancelled persistent operations remain real refusal tests.

### Constructed envelope encoding

`protected_header` builds one fixed set of unique typed labels. Signatures come
from maintained ed25519-dalek, and coset writes their constructed Sign1 structure
to an in-memory Vec. The fallible mapping at206 is retained for the upstream
API, but this builder supplies none of the duplicate/invalid labels or failing
writers that can cause an encoding error. The parser re-encoding mapper at
cose.rs173 is likewise unreachable: successful coset decoding has already
validated the Sign1 object, original protected bytes are preserved, and its
unprotected map is empty. Re-encoding cannot add conflicting labels or an I/O
failure. This is distinct from the reachable canonical-byte comparison at175. Untrusted envelopes use the separately
tested strict parser. No failing crypto or serializer stub is substituted.

### Validated active key

`SigningState::from_cbor` already obtains `ring.active()` at102 and returns an
error if it is absent. The ring is immutable throughout subsequent validation.
Only the redundant `is_none()` arm at111 is excluded. The same line's extra-field
and used-key-capacity refusals, all retirement/retention bounds, duplicate
history, pending-proof signature/issuer/successor/revision and v2 upgrade paths
remain tested and included.

The libSQL affected-row guard is not excluded: imported tables can have an
incompatible composite key. A real multirow fixture requires the entire update
to roll back and fences the signer. CRLT's real trigger rejection is also tested;
no direct-database bypass is used to invent a backend outcome.
