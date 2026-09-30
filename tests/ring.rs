//! Key ring encoding: round trips and refusal of anything that is not a clean public ring.

use coset::CborSerializable;
use coset::cbor::value::Value;
use csgn::{KeyId, KeyRing, RingError};

/// Ring of test vector 1 (issuer `cmnt`, one active key); see `tests/vectors.rs`.
const RING_1: &str = concat!(
    "a401020264636d6e740381a70101025820866eefbd6718c8846cd7ddfe43fc74ab1daac4538ff851",
    "4ea2ec2d410a41574303320481022006215820d75a980182b10ab7d54bfed3c964073a0ee172f3da",
    "a62325af021a68f707511a3a000100001a6ab13b80041a00278d00",
);
/// Ring of test vector 2 (issuer `cglb`, another active key).
const RING_2: &str = concat!(
    "a40102026463676c620381a70101025820dd2fb4e18b5e1ce30c4633aaa5f681da79c3b32998cc5a",
    "a21b1149c37231a6ac033204810220062158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d",
    "94121bf3748801b40f6f5c3a000100001a6ab13b80041a00278d00",
);

const PARAM_D: i64 = -4;
const PARAM_X: i64 = -2;
const PARAM_ACTIVATED_AT: i64 = -65537;
const PARAM_RETIRED_AT: i64 = -65538;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn int(value: i64) -> Value {
    Value::Integer(value.into())
}

fn decode(text: &str) -> Value {
    Value::from_slice(&hex(text)).unwrap()
}

fn map(value: &mut Value) -> &mut Vec<(Value, Value)> {
    match value {
        Value::Map(entries) => entries,
        _ => panic!("not a map"),
    }
}

fn field(value: &mut Value, key: i64) -> &mut Value {
    &mut map(value)
        .iter_mut()
        .find(|(k, _)| *k == int(key))
        .unwrap()
        .1
}

fn keys(ring: &mut Value) -> &mut Vec<Value> {
    match field(ring, 3) {
        Value::Array(keys) => keys,
        _ => panic!("keys are an array"),
    }
}

fn first_key(ring: &mut Value) -> &mut Value {
    &mut keys(ring)[0]
}

/// Decodes RING_1, applies `edit`, and decodes the result as a key ring.
fn edited(edit: impl FnOnce(&mut Value)) -> Result<KeyRing, RingError> {
    let mut ring = decode(RING_1);
    edit(&mut ring);
    KeyRing::from_cbor(&ring.to_vec().unwrap())
}

fn set_public_key(ring: &mut Value, public_key: [u8; 32]) {
    let key = first_key(ring);
    *field(key, PARAM_X) = Value::Bytes(public_key.to_vec());
    *field(key, 2) = Value::Bytes(KeyId::from_public_key(&public_key).as_bytes().to_vec());
}

#[test]
fn ring_round_trips_byte_for_byte() {
    for text in [RING_1, RING_2] {
        let ring = KeyRing::from_cbor(&hex(text)).unwrap();
        assert_eq!(ring.to_cbor(), hex(text));
        assert_eq!(KeyRing::from_cbor(&ring.to_cbor()).unwrap(), ring);
    }
}

#[test]
fn unedited_ring_is_accepted() {
    assert!(edited(|_| {}).is_ok());
}

#[test]
fn maximum_validity_is_required_and_must_be_positive() {
    for invalid in [int(0), int(-1), Value::Null, Value::Text("86400".into())] {
        assert!(edited(|ring| *field(ring, 4) = invalid).is_err());
    }
    assert!(edited(|ring| map(ring).retain(|(key, _)| *key != int(4))).is_err());
}

#[test]
fn active_retention_is_absent_and_retired_retention_is_rounded() {
    let mut raw = decode(RING_1);
    assert!(
        !map(first_key(&mut raw))
            .iter()
            .any(|(key, _)| *key == int(-65539))
    );
    for deadline in [0u64, 1_790_086_400, u64::MAX] {
        assert!(
            edited(|ring| {
                map(first_key(ring)).push((int(-65539), Value::Integer(deadline.into())));
            })
            .is_err()
        );
    }
    // Retired keys must carry a rounded deadline (or zero for an unused key).
    for (deadline, accepted) in [
        (0u64, true),
        (1_790_035_200, true),
        (1_790_035_201, false),
        (u64::MAX, true),
    ] {
        let result = edited(|ring| {
            map(first_key(ring)).extend([
                (
                    int(PARAM_RETIRED_AT),
                    Value::Integer(1_790_000_100u64.into()),
                ),
                (int(-65539), Value::Integer(deadline.into())),
            ]);
        });
        assert_eq!(result.is_ok(), accepted);
        if let Ok(ring) = result {
            assert_eq!(KeyRing::from_cbor(&ring.to_cbor()).unwrap(), ring);
        }
    }
    assert!(
        edited(|ring| {
            map(first_key(ring)).push((
                int(PARAM_RETIRED_AT),
                Value::Integer(1_790_000_100u64.into()),
            ));
        })
        .is_err()
    );
}

#[test]
fn secret_key_material_is_refused() {
    let result = edited(|ring| {
        map(first_key(ring)).push((int(PARAM_D), Value::Bytes(vec![7; 32])));
    });
    assert_eq!(result, Err(RingError::SecretKeyMaterial));
}

#[test]
fn key_id_must_be_the_thumbprint() {
    let result = edited(|ring| {
        *field(first_key(ring), 2) = Value::Bytes(vec![0x55; 32]);
    });
    assert_eq!(result, Err(RingError::KeyIdMismatch));
}

#[test]
fn invalid_and_weak_public_keys_are_refused() {
    // y = 2 is not on the curve.
    let mut not_on_curve = [0u8; 32];
    not_on_curve[0] = 2;
    // y = 1 is the identity point, of small order.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    for public_key in [not_on_curve, identity] {
        let result = edited(|ring| set_public_key(ring, public_key));
        assert_eq!(result, Err(RingError::InvalidPublicKey));
    }
}

#[test]
fn duplicate_keys_are_refused() {
    let result = edited(|ring| {
        let copy = first_key(ring).clone();
        keys(ring).push(copy);
    });
    assert_eq!(result, Err(RingError::DuplicateKey));
}

#[test]
fn more_than_one_active_key_is_refused() {
    let mut other = decode(RING_2);
    let other_key = first_key(&mut other).clone();
    let result = edited(|ring| keys(ring).push(other_key.clone()));
    assert_eq!(result, Err(RingError::MultipleActiveKeys));

    // With the second key retired, the ring is fine.
    let result = edited(|ring| {
        let mut retired = other_key;
        map(&mut retired).push((
            int(PARAM_RETIRED_AT),
            Value::Integer(1_790_000_100u64.into()),
        ));
        map(&mut retired).push((int(-65539), Value::Integer(1_790_035_200u64.into())));
        keys(ring).push(retired);
    });
    let ring = result.unwrap();
    assert_eq!(ring.keys().len(), 2);
    assert_eq!(ring.keys().iter().filter(|k| k.is_active()).count(), 1);
}

#[test]
fn unknown_version_is_refused() {
    let result = edited(|ring| *field(ring, 1) = int(99));
    assert_eq!(result, Err(RingError::UnsupportedVersion));
}

#[test]
fn malformed_rings_are_refused() {
    let malformed =
        |result: Result<KeyRing, RingError>| matches!(result, Err(RingError::Malformed(_)));

    assert!(malformed(KeyRing::from_cbor(&[])));
    assert!(malformed(KeyRing::from_cbor(b"\xff\xff")));
    let mut trailing = hex(RING_1);
    trailing.push(0);
    assert!(malformed(KeyRing::from_cbor(&trailing)));
    assert!(malformed(edited(|ring| *ring = Value::Array(vec![]))));
    assert!(malformed(edited(|ring| {
        map(ring).push((int(4), Value::Null));
    })));
    assert!(malformed(edited(|ring| {
        map(ring).retain(|(k, _)| *k != int(2));
    })));
    assert!(malformed(edited(
        |ring| *field(ring, 2) = Value::Text(String::new())
    )));
    assert!(malformed(edited(|ring| {
        map(ring).push((int(1), int(1)));
    })));
    assert!(malformed(edited(|ring| {
        map(first_key(ring)).push((int(-70000), Value::Null));
    })));
    assert!(malformed(edited(|ring| {
        map(first_key(ring)).push((Value::Text("note".into()), Value::Null));
    })));
    assert!(malformed(edited(|ring| {
        // alg EdDSA (-8) instead of Ed25519 (-19).
        *field(first_key(ring), 3) = int(-8);
    })));
    assert!(malformed(edited(|ring| {
        *field(first_key(ring), 4) = Value::Array(vec![int(1), int(2)]);
    })));
    assert!(malformed(edited(|ring| {
        // crv X25519 (4) instead of Ed25519 (6).
        *field(first_key(ring), -1) = int(4);
    })));
    assert!(malformed(edited(|ring| {
        *field(first_key(ring), PARAM_X) = Value::Bytes(vec![1; 31]);
    })));
    assert!(malformed(edited(|ring| {
        *field(first_key(ring), PARAM_ACTIVATED_AT) = int(-1);
    })));
    assert!(malformed(edited(|ring| {
        map(first_key(ring)).push((int(PARAM_RETIRED_AT), int(1)));
    })));
}

#[test]
fn duplicate_parameters_and_normalized_optional_fields_are_refused() {
    for parameter in [1, 2, 3, 4, -1, -2, -65537] {
        assert!(
            edited(|ring| {
                let entries = map(first_key(ring));
                let duplicate = entries
                    .iter()
                    .find(|(key, _)| *key == int(parameter))
                    .unwrap()
                    .clone();
                entries.push(duplicate);
            })
            .is_err()
        );
    }
    assert!(
        edited(|ring| {
            map(first_key(ring)).push((int(5), Value::Bytes(vec![])));
        })
        .is_err()
    );
    assert!(
        edited(|ring| {
            *field(first_key(ring), 4) = Value::Array(vec![int(2), int(2)]);
        })
        .is_err()
    );
    assert!(
        edited(|ring| {
            map(first_key(ring)).push((int(-65539), int(1)));
        })
        .is_err()
    );
}
