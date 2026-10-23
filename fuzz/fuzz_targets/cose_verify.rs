#![no_main]
//! Untrusted bytes at every csgn decode entry: genesis documents, key rings, COSE credentials and key-ring
//! transition proofs. Nothing may panic; a ring the decoder accepts must survive its own encoding; a credential
//! signed by the trusted ring must verify and return its payload unchanged, and byte edits of it must never panic
//! the verifier.
use csgn::{KeyRing, Kind, SEED_LEN, SecretKey, Signer};
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;

const NOW: u64 = 1_800_000_000;

thread_local! {
    // One fixed issuer: its ring is the trusted ring every credential below is verified against.
    static ISSUER: RefCell<Signer> = RefCell::new({
        let mut seed = [7u8; SEED_LEN];
        Signer::new("fuzz-issuer", SecretKey::from_seed(&mut seed), NOW - 1_000, 86_400)
            .expect("the fixed issuer is valid")
    });
}

fuzz_target!(|data: &[u8]| {
    // Raw bytes straight into the public decoders.
    let _ = csgn::verify_genesis(data);
    if let Ok(ring) = KeyRing::from_cbor(data) {
        KeyRing::from_cbor(&ring.to_cbor())
            .expect("an accepted ring decodes from its own encoding");
    }
    ISSUER.with(|issuer| {
        let issuer = issuer.borrow();
        let ring = issuer.key_ring();
        for kind in Kind::ALL {
            let _ = ring.verify(data, kind, NOW);
        }
        let _ = csgn::verify_transition_at_issue(ring, data);
    });

    // Structured: a genuine credential made from the input, then edited byte by byte. The edits keep the fuzzer
    // next to valid COSE structure, where the parser branches are, instead of at random bytes that fail at once.
    let Some((&select, rest)) = data.split_first() else {
        return;
    };
    let kind = Kind::ALL[select as usize % Kind::ALL.len()];
    let (payload, edits) = rest.split_at(rest.len() / 2);
    ISSUER.with(|issuer| {
        let mut issuer = issuer.borrow_mut();
        let Ok(mut cose) = issuer.sign(kind, payload, NOW, NOW + 3_600) else {
            return;
        };
        let ring = issuer.key_ring().clone();
        let intact = edits.len() < 3;
        for edit in edits.chunks_exact(3) {
            let at = usize::from(u16::from_le_bytes([edit[0], edit[1]])) % cose.len();
            cose[at] ^= edit[2];
        }
        let result = ring.verify(&cose, kind, NOW);
        if intact && kind == Kind::Credential {
            let verified = result.expect("a credential signed by the trusted ring verifies");
            assert_eq!(verified.payload(), payload);
        }
    });
});
