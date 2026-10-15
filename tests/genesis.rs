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
