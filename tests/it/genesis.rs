//! Genesis document and the chain walked from it.
#![cfg(feature = "volatile-signer")]

use csgn::{
    Kind, SecretKey, Signer, UNFOUNDED_FINGERPRINT_TAG, VerifyError, community_fingerprint,
    verify_genesis, verify_transition_at_issue,
};

fn key(value: u8) -> SecretKey {
    SecretKey::from_seed(&mut [value; 32])
}

#[test]
fn genesis_round_trips_and_names_the_first_ring() {
    let mut signer = Signer::new("community", key(1), 10, 1000).unwrap();
    let document = signer.genesis().unwrap();
    let genesis = verify_genesis(&document).unwrap();
    assert_eq!(genesis.community(), "community");
    assert_eq!(genesis.created_at(), 10);
    assert_eq!(genesis.founding_key(), key(1).public_key());
    // The fingerprint is SHA-256 of the founding public key, the one definition.
    use sha2::Digest as _;
    let expected: [u8; 32] = sha2::Sha256::digest(key(1).public_key()).into();
    assert_eq!(genesis.fingerprint(), expected);
    assert_eq!(
        genesis.fingerprint(),
        community_fingerprint("community", Some(&key(1).public_key()))
    );
    assert_eq!(&genesis.ring(), signer.key_ring());
    assert_eq!(genesis.ring().digest(), signer.key_ring().digest());
    let other = Signer::new("community", key(2), 10, 1000).unwrap();
    assert_ne!(other.key_ring().digest(), signer.key_ring().digest());
}

#[test]
fn only_a_fresh_ring_has_a_genesis_and_nothing_else_verifies_as_one() {
    let mut signer = Signer::new("community", key(1), 10, 1000).unwrap();
    let credential = signer.sign(Kind::Credential, b"x", 10, 20).unwrap();
    assert!(matches!(
        verify_genesis(&credential),
        Err(VerifyError::WrongKind { .. })
    ));
    signer.rotate_with_proof(key(2), 11, 100).unwrap();
    assert!(signer.genesis().is_err());
    assert!(verify_genesis(b"junk").is_err());
}

#[test]
fn a_document_signed_by_another_key_or_altered_is_refused() {
    let mut signer = Signer::new("community", key(1), 10, 1000).unwrap();
    let document = signer.genesis().unwrap();
    let mut flipped = document.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert!(verify_genesis(&flipped).is_err());
    // Another community's document has another fingerprint.
    let other = Signer::new("community", key(3), 10, 1000)
        .unwrap()
        .genesis()
        .unwrap();
    assert_ne!(
        verify_genesis(&document).unwrap().fingerprint(),
        verify_genesis(&other).unwrap().fingerprint()
    );
}

#[test]
fn the_chain_is_walked_from_the_genesis_ring_after_proofs_expired() {
    let mut signer = Signer::new("community", key(1), 10, 1000).unwrap();
    let genesis = verify_genesis(&signer.genesis().unwrap()).unwrap();
    let first = signer.rotate_with_proof(key(2), 20, 100).unwrap();
    signer.acknowledge_transition(1).unwrap();
    let second = signer.rotate_with_proof(key(3), 30, 100).unwrap();
    let ring0 = genesis.ring();
    let step1 = verify_transition_at_issue(&ring0, &first).unwrap();
    assert_eq!(step1.previous(), &ring0);
    let step2 = verify_transition_at_issue(step1.next(), &second).unwrap();
    assert_eq!(step2.next(), signer.key_ring());
    // Out of order or skipping a link is not chained.
    assert!(verify_transition_at_issue(&ring0, &second).is_err());
    // A replayed old link verifies as a signature but does not continue the head.
    let replay = verify_transition_at_issue(step2.next(), &first).unwrap();
    assert_ne!(replay.previous(), step2.next());
}

#[test]
fn an_unfounded_community_is_fingerprinted_by_tag_and_id() {
    use sha2::Digest as _;
    let expected: [u8; 32] = sha2::Sha256::new()
        .chain_update(UNFOUNDED_FINGERPRINT_TAG)
        .chain_update(b"community")
        .finalize()
        .into();
    assert_eq!(community_fingerprint("community", None), expected);
    assert_ne!(community_fingerprint("other", None), expected);
}

// ---- refusals of validly signed documents with a bad genesis payload ----

use coset::{CborSerializable, cbor::value::Value};

fn field(number: i64, value: Value) -> (Value, Value) {
    (Value::Integer(number.into()), value)
}

fn payload(fields: Vec<(Value, Value)>) -> Vec<u8> {
    Value::Map(fields).to_vec().unwrap()
}

fn canonical(
    community: &str,
    created_at: u64,
    max_validity: u64,
    key: &[u8; 32],
) -> Vec<(Value, Value)> {
    vec![
        field(1, Value::Text(community.to_owned())),
        field(2, Value::Integer(created_at.into())),
        field(3, Value::Integer(max_validity.into())),
        field(4, Value::Bytes(key.to_vec())),
    ]
}

/// Sign `payload` as a genesis document with the founding key of `community`.
fn signed(payload: &[u8], issued_at: u64, valid_until: u64) -> Vec<u8> {
    let mut signer = Signer::new("community", key(1), 10, 1000).unwrap();
    signer
        .sign(Kind::Genesis, payload, issued_at, valid_until)
        .unwrap()
}

#[test]
fn the_hand_built_canonical_payload_is_the_accepted_baseline() {
    let public = key(1).public_key();
    let document = signed(&payload(canonical("community", 10, 1000, &public)), 10, 11);
    let genesis = verify_genesis(&document).unwrap();
    assert_eq!(genesis.community(), "community");
}

#[test]
fn a_community_that_is_not_a_plain_bounded_text_is_refused() {
    let public = key(1).public_key();
    let long = "c".repeat(csgn::MAX_ISSUER_LEN + 1);
    for community in [
        Value::Text(String::new()),
        Value::Text(long),
        Value::Text("a\0b".into()),
        Value::Bytes(b"community".to_vec()),
    ] {
        let mut fields = canonical("community", 10, 1000, &public);
        fields[0] = field(1, community);
        let document = signed(&payload(fields), 10, 11);
        assert!(matches!(
            verify_genesis(&document),
            Err(VerifyError::Malformed(_))
        ));
    }
}

#[test]
fn a_founding_key_that_is_not_bytes_is_refused() {
    let public = key(1).public_key();
    let mut fields = canonical("community", 10, 1000, &public);
    fields[3] = field(4, Value::Text("not bytes".into()));
    let document = signed(&payload(fields), 10, 11);
    assert!(matches!(
        verify_genesis(&document),
        Err(VerifyError::Malformed(_))
    ));
}

#[test]
fn a_non_canonical_or_extended_payload_is_refused() {
    let public = key(1).public_key();
    let mut reordered = canonical("community", 10, 1000, &public);
    reordered.reverse();
    let mut extended = canonical("community", 10, 1000, &public);
    extended.push(field(5, Value::Integer(0.into())));
    for fields in [reordered, extended] {
        let document = signed(&payload(fields), 10, 11);
        assert!(matches!(
            verify_genesis(&document),
            Err(VerifyError::Malformed(_))
        ));
    }
}

#[test]
fn a_weak_or_foreign_founding_key_is_an_unknown_key() {
    // The identity point is a weak public key.
    let mut weak = [0u8; 32];
    weak[0] = 1;
    // A valid key that did not sign the document has another thumbprint.
    for founding in [weak, key(2).public_key()] {
        let document = signed(
            &payload(canonical("community", 10, 1000, &founding)),
            10,
            11,
        );
        assert!(matches!(
            verify_genesis(&document),
            Err(VerifyError::UnknownKey)
        ));
    }
}

#[test]
fn a_document_issued_by_another_community_is_refused() {
    let public = key(1).public_key();
    let document = signed(&payload(canonical("other", 10, 1000, &public)), 10, 11);
    assert!(matches!(
        verify_genesis(&document),
        Err(VerifyError::WrongIssuer)
    ));
}

#[test]
fn genesis_times_must_match_the_creation_time_and_the_one_second_validity() {
    let public = key(1).public_key();
    let body = payload(canonical("community", 10, 1000, &public));
    // Issue time differs from the creation time.
    let issued_later = signed(&body, 12, 13);
    // Valid until differs from the creation time plus one second.
    let long_lived = signed(&body, 10, 15);
    for document in [issued_later, long_lived] {
        assert!(matches!(
            verify_genesis(&document),
            Err(VerifyError::Malformed("genesis times differ"))
        ));
    }
}
