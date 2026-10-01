//! The same signed transition parsing and rejection vectors on native and wasm.
#![cfg(feature = "volatile-signer")]

use coset::CborSerializable;
use coset::cbor::value::Value;
use csgn::{KeyRing, Kind, SecretKey, SignError, Signer, SigningState, verify_transition};

fn int(value: i64) -> Value {
    Value::Integer(value.into())
}
fn key(value: u8) -> SecretKey {
    SecretKey::from_seed(&mut [value; 32])
}
fn signer() -> Signer {
    Signer::new("issuer", key(1), 10, 1000).unwrap()
}

fn replace(bytes: &[u8], field: i64, replacement: Value) -> Vec<u8> {
    let Value::Map(mut fields) = Value::from_slice(bytes).unwrap() else {
        unreachable!()
    };
    fields
        .iter_mut()
        .find(|(label, _)| *label == int(field))
        .unwrap()
        .1 = replacement;
    Value::Map(fields).to_vec().unwrap()
}
#[test]
fn signed_transition_round_trip_and_hostile_payloads() {
    let mut source = signer();
    let previous = source.key_ring().clone();
    let mut successor = signer();
    successor
        .sign(Kind::Credential, b"retention", 11, 200)
        .unwrap();
    let proof = successor.rotate_with_proof(key(2), 12, 200).unwrap();
    let next = successor.key_ring().clone();
    assert_eq!(successor.ring_revision(), 1);
    assert_eq!(successor.pending_transition(), Some(proof.as_slice()));
    let encoded = previous
        .verify(&proof, Kind::KeyRingTransition, 12)
        .unwrap()
        .into_payload();
    let data = Value::from_slice(&encoded).unwrap();
    let transition = verify_transition(&previous, &proof, 12).unwrap();
    assert_eq!(transition.revision(), 1);
    assert_eq!(transition.previous().to_cbor(), previous.to_cbor());
    assert_eq!(transition.next().to_cbor(), next.to_cbor());
    assert!(verify_transition(&previous, &proof, 200).is_err());
    assert!(
        verify_transition(
            &KeyRing::from_cbor(
                &Signer::new("issuer", key(9), 10, 1000)
                    .unwrap()
                    .key_ring()
                    .to_cbor()
            )
            .unwrap(),
            &proof,
            12
        )
        .is_err()
    );
    let mut corrupt = proof.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(verify_transition(&previous, &corrupt, 12).is_err());
    let wrong_kind = source.sign(Kind::TrustManifest, &encoded, 12, 200).unwrap();
    assert!(verify_transition(&previous, &wrong_kind, 12).is_err());
    for (field, replacement) in [
        (1, int(2)),
        (2, Value::Text("other".into())),
        (3, int(0)),
        (3, int(-1)),
        (4, Value::Null),
        (5, Value::Null),
        (4, Value::Bytes(vec![0])),
        (5, Value::Bytes(vec![0])),
    ] {
        let Value::Map(mut fields) = data.clone() else {
            unreachable!()
        };
        fields
            .iter_mut()
            .find(|(label, _)| *label == int(field))
            .unwrap()
            .1 = replacement;
        let proof = source
            .sign(
                Kind::KeyRingTransition,
                &Value::Map(fields).to_vec().unwrap(),
                12,
                200,
            )
            .unwrap();
        assert!(verify_transition(&previous, &proof, 12).is_err());
    }
    let Value::Map(mut fields) = data.clone() else {
        unreachable!()
    };
    fields.push((int(6), int(0)));
    let proof = source
        .sign(
            Kind::KeyRingTransition,
            &Value::Map(fields).to_vec().unwrap(),
            12,
            200,
        )
        .unwrap();
    assert!(verify_transition(&previous, &proof, 12).is_err());
    let Value::Map(mut fields) = data else {
        unreachable!()
    };
    fields.reverse();
    let proof = source
        .sign(
            Kind::KeyRingTransition,
            &Value::Map(fields).to_vec().unwrap(),
            12,
            200,
        )
        .unwrap();
    assert!(verify_transition(&previous, &proof, 12).is_err());
}

#[test]
fn version_two_recovery_upgrades_without_a_public_ring_change() {
    let original = signer().state();
    let Value::Map(mut fields) = Value::from_slice(&original.to_cbor()).unwrap() else {
        unreachable!()
    };
    fields.retain(|(label, _)| *label != int(7) && *label != int(8));
    fields
        .iter_mut()
        .find(|(label, _)| *label == int(1))
        .unwrap()
        .1 = int(2);
    let restored = SigningState::from_cbor(&Value::Map(fields).to_vec().unwrap()).unwrap();
    assert_eq!(restored.key_ring(), original.key_ring());
    assert_eq!(restored, original);
    let upgraded = restored.to_cbor();
    assert_eq!(SigningState::from_cbor(&upgraded).unwrap(), original);
}

#[test]
fn recovered_transition_must_match_its_signature_revision_and_successor() {
    let mut producer = signer();
    let proof = producer.rotate_with_proof(key(2), 12, 200).unwrap();
    let original = producer.state();
    let encoded = original.to_cbor();
    assert_eq!(SigningState::from_cbor(&encoded).unwrap(), original);
    let mut corrupted = proof.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    let mut other = signer();
    let different = other.rotate_with_proof(key(3), 12, 200).unwrap();
    let ordinary = producer
        .sign(Kind::TrustManifest, b"manifest", 13, 200)
        .unwrap();
    for (field, value) in [
        (7, int(0)),
        (7, int(2)),
        (7, int(-1)),
        (8, int(1)),
        (8, Value::Bytes(vec![])),
        (8, Value::Bytes(corrupted)),
        (8, Value::Bytes(different)),
        (8, Value::Bytes(ordinary)),
    ] {
        assert!(SigningState::from_cbor(&replace(&encoded, field, value)).is_err());
    }
    // The proof is intentionally verified at issuance during recovery: it must
    // survive a restart after expiry without becoming a current publication.
    let mut restored = Signer::resume(original, key(2), 201).unwrap();
    assert_eq!(restored.pending_transition(), Some(proof.as_slice()));
    restored.acknowledge_transition(1).unwrap();
    assert_eq!(restored.pending_transition(), None);
    assert_eq!(restored.ring_revision(), 1);
    assert_eq!(
        restored.acknowledge_transition(1),
        Err(SignError::InvalidTransition)
    );
}

#[test]
fn exhausted_ring_revision_refuses_mutation_without_losing_the_active_key() {
    let encoded = replace(
        &signer().state().to_cbor(),
        7,
        Value::Integer(u64::MAX.into()),
    );
    let state = SigningState::from_cbor(&encoded).unwrap();
    let mut restored = Signer::resume(state, key(1), 10).unwrap();
    let before = restored.state();
    assert_eq!(
        restored.rotate_with_proof(key(2), 12, 200),
        Err(SignError::LimitExceeded)
    );
    assert_eq!(
        restored.prune_with_proof(12, 200),
        Err(SignError::LimitExceeded)
    );
    assert_eq!(restored.state(), before);
    let bytes = restored
        .sign(Kind::TrustManifest, b"current", 12, 200)
        .unwrap();
    assert!(restored.verify(&bytes, Kind::TrustManifest, 12).is_ok());
    assert_eq!(restored.ring_revision(), u64::MAX);
}

#[test]
fn signed_transition_refuses_unrelated_rings_and_invalid_payload_shapes() {
    let mut source = signer();
    let trusted = source.key_ring().clone();
    let mut producer = signer();
    let proof = producer.rotate_with_proof(key(2), 12, 200).unwrap();
    let encoded = trusted
        .verify(&proof, Kind::KeyRingTransition, 12)
        .unwrap()
        .into_payload();
    let other_issuer = Signer::new("other", key(2), 10, 1000).unwrap();
    let other_lifetime = Signer::new("issuer", key(2), 10, 500).unwrap();
    let wrong_active = Signer::new("issuer", key(3), 10, 1000).unwrap();
    let empty_ring = replace(&trusted.to_cbor(), 3, Value::Array(vec![]));
    assert!(KeyRing::from_cbor(&empty_ring).is_ok());
    for (field, value) in [
        (2, Value::Null),
        (3, Value::Text("1".into())),
        (4, Value::Bytes(other_issuer.key_ring().to_cbor())),
        (5, Value::Bytes(other_issuer.key_ring().to_cbor())),
        (5, Value::Bytes(other_lifetime.key_ring().to_cbor())),
        (4, Value::Bytes(empty_ring.clone())),
        (5, Value::Bytes(empty_ring)),
        (4, Value::Bytes(wrong_active.key_ring().to_cbor())),
    ] {
        let payload = replace(&encoded, field, value);
        let bytes = source
            .sign(Kind::KeyRingTransition, &payload, 12, 200)
            .unwrap();
        assert!(verify_transition(&trusted, &bytes, 12).is_err());
    }
    for payload in [vec![], vec![0xff], Value::Array(vec![]).to_vec().unwrap()] {
        let bytes = source
            .sign(Kind::KeyRingTransition, &payload, 12, 200)
            .unwrap();
        assert!(verify_transition(&trusted, &bytes, 12).is_err());
    }
    let foreign = Value::Bytes(other_issuer.key_ring().to_cbor());
    let payload = replace(&encoded, 2, Value::Text("other".into()));
    let payload = replace(&payload, 4, foreign.clone());
    let payload = replace(&payload, 5, foreign);
    let bytes = source
        .sign(Kind::KeyRingTransition, &payload, 12, 200)
        .unwrap();
    assert!(verify_transition(&trusted, &bytes, 12).is_err());
}
