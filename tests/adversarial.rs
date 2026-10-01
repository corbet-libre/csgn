//! Hostile encodings, cryptographic edge cases and state corruption.
#![cfg(feature = "volatile-signer")]

use coset::cbor::value::Value;
use coset::{CborSerializable, CoseSign1, TaggedCborSerializable};
use csgn::{KeyRing, Kind, SecretKey, SignError, Signer, SigningState, VerifyError};

fn signer() -> Signer {
    Signer::new(
        "cmty:adversarial",
        SecretKey::from_seed(&mut [42; 32]),
        10,
        100,
    )
    .unwrap()
}

fn int(value: i64) -> Value {
    Value::Integer(value.into())
}

fn parts(value: &mut Value) -> &mut Vec<Value> {
    let Value::Tag(18, value) = value else {
        panic!()
    };
    let Value::Array(parts) = value.as_mut() else {
        panic!()
    };
    parts
}

fn fields(value: &mut Value) -> &mut Vec<(Value, Value)> {
    let Value::Map(fields) = value else { panic!() };
    fields
}

#[test]
fn every_single_bit_mutation_of_a_message_is_refused() {
    let mut signer = signer();
    let message = signer.sign(Kind::Credential, b"payload", 11, 99).unwrap();
    for index in 0..message.len() {
        for bit in 0..8 {
            let mut changed = message.clone();
            changed[index] ^= 1 << bit;
            assert!(
                signer.verify(&changed, Kind::Credential, 12).is_err(),
                "byte {index}, bit {bit}"
            );
        }
    }
}

#[test]
fn raw_empty_optional_headers_and_duplicate_labels_are_refused() {
    let mut signer = signer();
    let message = signer.sign(Kind::Credential, b"x", 10, 90).unwrap();
    for (label, value) in [
        (2, Value::Array(vec![])),
        (4, Value::Bytes(vec![])),
        (5, Value::Bytes(vec![])),
    ] {
        let mut raw = Value::from_slice(&message).unwrap();
        parts(&mut raw)[1] = Value::Map(vec![(int(label), value)]);
        assert!(matches!(
            signer.verify(&raw.to_vec().unwrap(), Kind::Credential, 10),
            Err(VerifyError::Malformed(_))
        ));
    }
    for label in [1, 4, 15, -65537] {
        let mut raw = Value::from_slice(&message).unwrap();
        let Value::Bytes(bytes) = &mut parts(&mut raw)[0] else {
            panic!()
        };
        let mut header = Value::from_slice(bytes).unwrap();
        let duplicate = fields(&mut header)
            .iter()
            .find(|(key, _)| *key == int(label))
            .unwrap()
            .clone();
        fields(&mut header).push(duplicate);
        *bytes = header.to_vec().unwrap();
        assert!(
            signer
                .verify(&raw.to_vec().unwrap(), Kind::Credential, 10)
                .is_err()
        );
    }
    for duplicate in [true, false] {
        let mut raw = Value::from_slice(&message).unwrap();
        let Value::Bytes(bytes) = &mut parts(&mut raw)[0] else {
            panic!()
        };
        let mut header = Value::from_slice(bytes).unwrap();
        if duplicate {
            let claims = &mut fields(&mut header)
                .iter_mut()
                .find(|(key, _)| *key == int(15))
                .unwrap()
                .1;
            let repeated = fields(claims)[0].clone();
            fields(claims).push(repeated);
        } else {
            fields(&mut header).push((int(5), Value::Bytes(vec![])));
        }
        *bytes = header.to_vec().unwrap();
        assert!(
            signer
                .verify(&raw.to_vec().unwrap(), Kind::Credential, 10)
                .is_err()
        );
    }
}

#[test]
fn noncanonical_scalar_and_small_order_signature_point_are_refused() {
    let mut signer = signer();
    let message = signer.sign(Kind::Credential, b"x", 10, 90).unwrap();
    let mut decoded = CoseSign1::from_tagged_slice(&message).unwrap();
    decoded.signature[63] |= 0xf0;
    assert_eq!(
        signer.verify(&decoded.to_tagged_vec().unwrap(), Kind::Credential, 10),
        Err(VerifyError::BadSignature)
    );
    let mut decoded = CoseSign1::from_tagged_slice(&message).unwrap();
    decoded.signature[..32].fill(0);
    decoded.signature[0] = 1;
    assert_eq!(
        signer.verify(&decoded.to_tagged_vec().unwrap(), Kind::Credential, 10),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn truncation_deep_nesting_and_oversized_input_do_not_panic() {
    let mut signer = signer();
    let message = signer.sign(Kind::Credential, b"x", 10, 90).unwrap();
    let ring = signer.key_ring().to_cbor();
    let state = signer.state().to_cbor();
    for end in 0..message.len() {
        assert!(
            signer
                .verify(&message[..end], Kind::Credential, 10)
                .is_err()
        );
    }
    for end in 0..ring.len() {
        assert!(KeyRing::from_cbor(&ring[..end]).is_err());
    }
    for end in 0..state.len() {
        assert!(SigningState::from_cbor(&state[..end]).is_err());
    }
    let mut nested = vec![0x81; 256];
    nested.push(0);
    let huge = vec![0; csgn::MAX_PAYLOAD_LEN + 8193];
    for input in [&nested, &huge] {
        assert!(signer.verify(input, Kind::Credential, 10).is_err());
        assert!(KeyRing::from_cbor(input).is_err());
        assert!(SigningState::from_cbor(input).is_err());
    }
    assert_eq!(
        signer.sign(Kind::Credential, &huge, 10, 90),
        Err(SignError::LimitExceeded)
    );
}

#[test]
fn signing_state_rejects_missing_tombstones_and_invalid_clock_or_validity() {
    let mut signer = signer();
    signer.sign(Kind::Credential, b"x", 20, 90).unwrap();
    let state = signer.state().to_cbor();
    for (label, value) in [
        (3, int(0)),
        (4, int(9)),
        (5, Value::Array(vec![])),
        (3, int(1)),
    ] {
        let mut changed = Value::from_slice(&state).unwrap();
        fields(&mut changed)
            .iter_mut()
            .find(|(key, _)| *key == int(label))
            .unwrap()
            .1 = value;
        assert!(SigningState::from_cbor(&changed.to_vec().unwrap()).is_err());
    }
    let mut trailing = state.clone();
    trailing.push(0);
    assert!(SigningState::from_cbor(&trailing).is_err());
    let mut duplicate = Value::from_slice(&state).unwrap();
    let first = fields(&mut duplicate)[0].clone();
    fields(&mut duplicate).push(first);
    assert!(SigningState::from_cbor(&duplicate.to_vec().unwrap()).is_err());
}

#[test]
fn external_aad_is_bound_by_the_cose_signature() {
    use ed25519_dalek::Signer as _;
    let mut signer = signer();
    let message = signer.sign(Kind::Credential, b"x", 10, 90).unwrap();
    let mut decoded = CoseSign1::from_tagged_slice(&message).unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    decoded.signature = key
        .sign(&decoded.tbs_data(b"wrong aad"))
        .to_bytes()
        .to_vec();
    assert_eq!(
        signer.verify(&decoded.to_tagged_vec().unwrap(), Kind::Credential, 10),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn critical_headers_require_exactly_kind_and_claims() {
    use coset::{RegisteredLabelWithPrivate as Critical, iana};
    use ed25519_dalek::Signer as _;

    let mut signer = signer();
    let message = signer.sign(Kind::Credential, b"x", 10, 90).unwrap();
    let original = CoseSign1::from_tagged_slice(&message).unwrap();
    let claims = Critical::Assigned(iana::HeaderParameter::CwtClaims);
    let kind = Critical::PrivateUse(-65537);
    assert_eq!(
        original.protected.header.crit,
        vec![claims.clone(), kind.clone()]
    );
    for critical in [
        vec![],
        vec![claims.clone()],
        vec![kind.clone()],
        vec![claims.clone(), claims.clone()],
        vec![claims.clone(), kind.clone(), kind.clone()],
        vec![claims.clone(), Critical::PrivateUse(-65538)],
        vec![claims.clone(), kind.clone(), Critical::PrivateUse(-65538)],
    ] {
        let mut changed = original.clone();
        changed.protected.original_data = None;
        changed.protected.header.crit = critical;
        changed.signature = ed25519_dalek::SigningKey::from_bytes(&[42; 32])
            .sign(&changed.tbs_data(&[]))
            .to_bytes()
            .to_vec();
        assert!(matches!(
            signer.verify(&changed.to_tagged_vec().unwrap(), Kind::Credential, 10),
            Err(VerifyError::Malformed(_))
        ));
    }
    // Order is immaterial; both labels must be understood and signature-bound.
    let mut reversed = original;
    reversed.protected.original_data = None;
    reversed.protected.header.crit = vec![kind, claims];
    reversed.signature = ed25519_dalek::SigningKey::from_bytes(&[42; 32])
        .sign(&reversed.tbs_data(&[]))
        .to_bytes()
        .to_vec();
    assert!(
        signer
            .verify(&reversed.to_tagged_vec().unwrap(), Kind::Credential, 10)
            .is_ok()
    );
}

#[test]
fn issuer_and_key_history_limits_fail_closed() {
    let key = || SecretKey::from_seed(&mut [42; 32]);
    for issuer in [
        String::new(),
        "x".repeat(csgn::MAX_ISSUER_LEN + 1),
        "a\0b".into(),
    ] {
        assert_eq!(
            Signer::new(issuer, key(), 10, 100).unwrap_err(),
            SignError::InvalidIssuer
        );
    }
    let mut boundary = Signer::new("x".repeat(csgn::MAX_ISSUER_LEN), key(), 10, 100).unwrap();
    let bytes = boundary.sign(Kind::Credential, b"x", 10, 90).unwrap();
    assert!(
        KeyRing::from_cbor(&boundary.key_ring().to_cbor())
            .unwrap()
            .verify(&bytes, Kind::Credential, 10)
            .is_ok()
    );

    let mut state = Value::from_slice(&signer().state().to_cbor()).unwrap();
    let ids = &mut fields(&mut state)
        .iter_mut()
        .find(|(label, _)| *label == int(5))
        .unwrap()
        .1;
    let Value::Array(ids) = ids else { panic!() };
    for index in 0..csgn::MAX_USED_KEYS - 1 {
        let mut id = [0; 32];
        id[..8].copy_from_slice(&(index as u64).to_be_bytes());
        ids.push(Value::Bytes(id.to_vec()));
    }
    let loaded = SigningState::from_cbor(&state.clone().to_vec().unwrap()).unwrap();
    let mut resumed = Signer::resume(loaded, key(), 10).unwrap();
    assert_eq!(
        resumed.rotate(SecretKey::from_seed(&mut [43; 32]), 10),
        Err(SignError::LimitExceeded)
    );
    let ids = &mut fields(&mut state)
        .iter_mut()
        .find(|(label, _)| *label == int(5))
        .unwrap()
        .1;
    let Value::Array(ids) = ids else { panic!() };
    ids.push(Value::Bytes(vec![99; 32]));
    assert!(SigningState::from_cbor(&state.to_vec().unwrap()).is_err());
}
