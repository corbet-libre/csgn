//! Signing and verification round trips, tampering, key validity and rotation.
#![cfg(feature = "volatile-signer")]

use coset::cbor::value::Value;
use coset::{CoseSign1, Header, Label, TaggedCborSerializable, iana};
use csgn::{KeyRing, Kind, SecretKey, SignError, Signer, VerifyError};

// Day boundary keeps the original rotation scenarios on retention boundaries.
const NOW: u64 = 1_789_948_800;
const DAY: u64 = 86_400;
const MAX_VALIDITY: u64 = 30 * DAY;

fn key(byte: u8) -> SecretKey {
    SecretKey::from_seed(&mut [byte; 32])
}

fn signer_with(issuer: &str, byte: u8, now: u64) -> Signer {
    Signer::new(issuer, key(byte), now, MAX_VALIDITY).unwrap()
}

fn signer() -> Signer {
    signer_with("cmty", 1, NOW)
}

#[test]
fn retained_public_key_limit_preserves_the_last_valid_signer() {
    let mut producer = signer();
    for index in 1..csgn::MAX_RING_KEYS {
        producer
            .sign(Kind::Credential, b"retained", NOW, NOW + DAY)
            .unwrap();
        let mut seed = [0; 32];
        seed[..8].copy_from_slice(&(index as u64).to_be_bytes());
        producer
            .rotate(SecretKey::from_seed(&mut seed), NOW)
            .unwrap();
    }
    assert_eq!(producer.key_ring().keys().len(), csgn::MAX_RING_KEYS);
    let before = producer.state();
    assert_eq!(producer.rotate(key(2), NOW), Err(SignError::LimitExceeded));
    assert_eq!(producer.state(), before);
    let proof = producer
        .sign(Kind::Credential, b"still usable", NOW, NOW + DAY)
        .unwrap();
    assert!(
        published(&producer)
            .verify(&proof, Kind::Credential, NOW)
            .is_ok()
    );
}

/// The ring as a member's device sees it: encoded, published, decoded.
fn published(signer: &Signer) -> KeyRing {
    KeyRing::from_cbor(&signer.key_ring().to_cbor()).unwrap()
}

/// Decodes a message, lets `edit` change it, and re-encodes it. With `reencode_protected`
/// the protected header is serialized again from the edited fields.
fn edit(message: &[u8], reencode_protected: bool, edit: impl FnOnce(&mut CoseSign1)) -> Vec<u8> {
    let mut sign1 = CoseSign1::from_tagged_slice(message).unwrap();
    edit(&mut sign1);
    if reencode_protected {
        sign1.protected.original_data = None;
    }
    sign1.to_tagged_vec().unwrap()
}

fn header_value(header: &mut Header, label: i64) -> &mut Value {
    &mut header
        .rest
        .iter_mut()
        .find(|(l, _)| *l == Label::Int(label))
        .unwrap()
        .1
}

fn claim(header: &mut Header, claim: i64) -> &mut Value {
    let Value::Map(claims) = header_value(header, iana::HeaderParameter::CwtClaims as i64) else {
        panic!("claims are a map");
    };
    &mut claims
        .iter_mut()
        .find(|(k, _)| *k == Value::Integer(claim.into()))
        .unwrap()
        .1
}

const KIND_LABEL: i64 = -65537;

// Round trips.

#[test]
fn every_kind_round_trips() {
    let mut signer = signer();
    let ring = published(&signer);
    for kind in Kind::ALL {
        let payload = format!("payload for {kind}");
        let message = signer
            .sign(kind, payload.as_bytes(), NOW + 5, NOW + DAY)
            .unwrap();
        for verifier in [signer.key_ring(), &ring] {
            let verified = verifier.verify(&message, kind, NOW + 10).unwrap();
            assert_eq!(verified.payload(), payload.as_bytes());
            assert_eq!(verified.kind(), kind);
            assert_eq!(verified.key_id(), signer.active_key_id());
            assert_eq!(verified.issued_at(), NOW + 5);
            assert_eq!(verified.valid_until(), NOW + DAY);
        }
    }
}

#[test]
fn empty_and_large_payloads_round_trip() {
    let mut signer = signer();
    for payload in [Vec::new(), vec![0xab; 1 << 20]] {
        let message = signer
            .sign(Kind::SchemaSnapshot, &payload, NOW, NOW + 1)
            .unwrap();
        let verified = signer.verify(&message, Kind::SchemaSnapshot, NOW).unwrap();
        assert_eq!(verified.into_payload(), payload);
    }
}

#[test]
fn signing_is_deterministic() {
    let mut a = signer();
    let mut b = signer();
    let first = a.sign(Kind::Credential, b"same", NOW, NOW + DAY).unwrap();
    let second = b.sign(Kind::Credential, b"same", NOW, NOW + DAY).unwrap();
    assert_eq!(first, second);
}

#[test]
fn generated_keys_round_trip_and_differ() {
    let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
    let first = SecretKey::generate(&mut rng);
    let second = SecretKey::generate(&mut rng);
    assert_ne!(first.key_id(), second.key_id());
    let mut signer = Signer::new("cgbl", first, NOW, MAX_VALIDITY).unwrap();
    let message = signer.sign(Kind::Credential, b"x", NOW, NOW + 1).unwrap();
    assert!(
        published(&signer)
            .verify(&message, Kind::Credential, NOW)
            .is_ok()
    );
}

#[test]
fn key_id_is_the_thumbprint_of_the_public_key() {
    let key = key(9);
    assert_eq!(
        key.key_id(),
        csgn::KeyId::from_public_key(&key.public_key())
    );
}

// Tampering.

#[test]
fn tampered_payload_is_rejected() {
    let mut signer = signer();
    let message = signer
        .sign(Kind::Credential, b"member:alice", NOW, NOW + DAY)
        .unwrap();
    let tampered = edit(&message, false, |m| {
        m.payload = Some(b"member:mallory".to_vec());
    });
    assert_eq!(
        signer.verify(&tampered, Kind::Credential, NOW),
        Err(VerifyError::BadSignature)
    );

    // A single flipped bit in the raw bytes of the payload.
    let at = message
        .windows(12)
        .position(|w| w == b"member:alice")
        .unwrap();
    let mut flipped = message.clone();
    flipped[at + 7] ^= 0x01;
    assert_eq!(
        signer.verify(&flipped, Kind::Credential, NOW),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn tampered_signature_is_rejected() {
    let mut signer = signer();
    let message = signer.sign(Kind::Credential, b"x", NOW, NOW + DAY).unwrap();
    for index in [message.len() - 1, message.len() - 64] {
        let mut flipped = message.clone();
        flipped[index] ^= 0x80;
        assert_eq!(
            signer.verify(&flipped, Kind::Credential, NOW),
            Err(VerifyError::BadSignature)
        );
    }
    let zeroed = edit(&message, false, |m| m.signature = vec![0; 64]);
    assert_eq!(
        signer.verify(&zeroed, Kind::Credential, NOW),
        Err(VerifyError::BadSignature)
    );
    let short = edit(&message, false, |m| m.signature.truncate(63));
    assert_eq!(
        signer.verify(&short, Kind::Credential, NOW),
        Err(VerifyError::Malformed("invalid COSE shape"))
    );
}

#[test]
fn tampered_protected_header_is_rejected() {
    let mut signer = signer();
    let message = signer
        .sign(Kind::SettingsSnapshot, b"x", NOW, NOW + DAY)
        .unwrap();

    let longer = edit(&message, true, |m| {
        *claim(&mut m.protected.header, 4) = Value::Integer((NOW + 30 * DAY).into());
    });
    let earlier = edit(&message, true, |m| {
        *claim(&mut m.protected.header, 6) = Value::Integer((NOW - 1).into());
    });
    let issuer = edit(&message, true, |m| {
        *claim(&mut m.protected.header, 1) = Value::Text("cgbl".into());
    });
    let kind = edit(&message, true, |m| {
        *header_value(&mut m.protected.header, KIND_LABEL) = Value::Text("credential".into());
    });
    for tampered in [&longer, &earlier, &issuer] {
        assert_eq!(
            signer.verify(tampered, Kind::SettingsSnapshot, NOW),
            Err(VerifyError::BadSignature)
        );
    }
    // Relabelling a snapshot as a credential does not make it one.
    assert_eq!(
        signer.verify(&kind, Kind::Credential, NOW),
        Err(VerifyError::BadSignature)
    );

    // A flipped bit inside the protected header bytes (in the issuer text).
    let at = message.windows(4).position(|w| w == b"cmty").unwrap();
    let mut flipped = message.clone();
    flipped[at] ^= 0x02;
    assert_eq!(
        signer.verify(&flipped, Kind::SettingsSnapshot, NOW),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn key_id_swapped_to_another_ring_key_is_rejected() {
    let mut signer = signer();
    let message = signer.sign(Kind::Credential, b"x", NOW, NOW + DAY).unwrap();
    let old_id = signer.active_key_id();
    signer.rotate(key(2), NOW + 1).unwrap();
    let new_id = signer.active_key_id();
    assert_ne!(old_id, new_id);
    let swapped = edit(&message, true, |m| {
        m.protected.header.key_id = new_id.as_bytes().to_vec();
    });
    assert_eq!(
        signer.verify(&swapped, Kind::Credential, NOW + 2),
        Err(VerifyError::BadSignature)
    );
}

// Key IDs, kinds and issuers.

#[test]
fn unknown_key_id_is_rejected() {
    let mut signer = signer();
    let message = signer.sign(Kind::Credential, b"x", NOW, NOW + DAY).unwrap();
    let unknown = edit(&message, true, |m| {
        m.protected.header.key_id = vec![0x55; 32];
    });
    assert_eq!(
        signer.verify(&unknown, Kind::Credential, NOW),
        Err(VerifyError::UnknownKey)
    );
}

#[test]
fn key_of_another_signer_is_unknown() {
    let mut community = signer_with("cmty", 1, NOW);
    let other = signer_with("cmty", 2, NOW);
    let message = community
        .sign(Kind::Credential, b"x", NOW, NOW + DAY)
        .unwrap();
    assert_eq!(
        published(&other).verify(&message, Kind::Credential, NOW),
        Err(VerifyError::UnknownKey)
    );
}

#[test]
fn levels_do_not_accept_each_other() {
    // Separate keys per level: the global ring does not know community keys.
    let mut community = signer_with("cmty", 1, NOW);
    let global = signer_with("cgbl", 2, NOW);
    let message = community
        .sign(Kind::RevocationListSnapshot, b"x", NOW, NOW + DAY)
        .unwrap();
    assert_eq!(
        published(&global).verify(&message, Kind::RevocationListSnapshot, NOW),
        Err(VerifyError::UnknownKey)
    );

    // Even a misconfiguration that loads the same key at both levels is caught by the issuer.
    let same_key_global = signer_with("cgbl", 1, NOW);
    assert_eq!(
        published(&same_key_global).verify(&message, Kind::RevocationListSnapshot, NOW),
        Err(VerifyError::WrongIssuer)
    );
}

#[test]
fn wrong_kind_is_rejected_for_every_pair() {
    let mut signer = signer();
    for signed in Kind::ALL {
        let message = signer.sign(signed, b"x", NOW, NOW + DAY).unwrap();
        for expected in Kind::ALL {
            let result = signer.verify(&message, expected, NOW);
            if signed == expected {
                assert!(result.is_ok());
            } else {
                assert_eq!(
                    result,
                    Err(VerifyError::WrongKind {
                        expected,
                        found: signed
                    })
                );
            }
        }
    }
}

// Validity of messages and keys.

#[test]
fn message_expires_at_valid_until() {
    let mut signer = signer();
    let message = signer.sign(Kind::Credential, b"x", NOW, NOW + DAY).unwrap();
    assert!(
        signer
            .verify(&message, Kind::Credential, NOW + DAY - 1)
            .is_ok()
    );
    assert_eq!(
        signer.verify(&message, Kind::Credential, NOW + DAY),
        Err(VerifyError::Expired)
    );
    assert_eq!(
        signer.verify(&message, Kind::Credential, u64::MAX),
        Err(VerifyError::Expired)
    );
}

#[test]
fn retired_key_expires_after_its_last_signature() {
    let mut signer = signer();
    let message = signer.sign(Kind::Credential, b"x", NOW, NOW + DAY).unwrap();
    signer.rotate(key(2), NOW + 10).unwrap();
    // A verifier that still holds the retired key.
    let ring = published(&signer);
    assert!(
        ring.verify(&message, Kind::Credential, NOW + DAY - 1)
            .is_ok()
    );
    assert_eq!(
        ring.verify(&message, Kind::Credential, NOW + DAY),
        Err(VerifyError::KeyExpired)
    );
}

#[test]
fn rotation_keeps_old_credentials_until_their_expiry() {
    let mut signer = signer();
    let first_key = signer.active_key_id();
    let established = signer
        .sign(Kind::Credential, b"established", NOW, NOW + 30 * DAY)
        .unwrap();
    let newcomer = signer
        .sign(Kind::Credential, b"newcomer", NOW + 1, NOW + 1 + DAY)
        .unwrap();

    signer.rotate(key(2), NOW + 2).unwrap();
    let second_key = signer.active_key_id();
    let fresh = signer
        .sign(Kind::Credential, b"fresh", NOW + 3, NOW + 3 + DAY)
        .unwrap();

    let ring = published(&signer);
    assert_eq!(ring.keys().len(), 2);
    let retired = ring.get(&first_key).unwrap();
    assert_eq!(retired.retired_at(), Some(NOW + 2));
    assert_eq!(retired.signed_until(), NOW + 30 * DAY);
    assert!(!retired.is_active());
    assert_eq!(ring.active().unwrap().key_id(), second_key);

    for message in [&established, &newcomer, &fresh] {
        assert!(ring.verify(message, Kind::Credential, NOW + 10).is_ok());
    }
    assert_eq!(
        ring.verify(&newcomer, Kind::Credential, NOW + 1 + DAY),
        Err(VerifyError::Expired)
    );
    assert!(
        ring.verify(&established, Kind::Credential, NOW + 30 * DAY - 1)
            .is_ok()
    );
    assert_eq!(
        ring.verify(&established, Kind::Credential, NOW + 30 * DAY),
        Err(VerifyError::KeyExpired)
    );

    // Once pruned, the old key leaves the published ring.
    signer.prune(NOW + 30 * DAY).unwrap();
    let pruned = published(&signer);
    assert_eq!(pruned.keys().len(), 1);
    assert!(pruned.get(&first_key).is_none());
    assert_eq!(
        pruned.verify(&established, Kind::Credential, NOW + 30 * DAY),
        Err(VerifyError::UnknownKey)
    );
    let later = signer
        .sign(Kind::Credential, b"later", NOW + 30 * DAY, NOW + 31 * DAY)
        .unwrap();
    assert!(
        pruned
            .verify(&later, Kind::Credential, NOW + 30 * DAY)
            .is_ok()
    );
}

#[test]
fn unused_key_is_dropped_on_rotation() {
    let mut signer = signer();
    let first_key = signer.active_key_id();
    signer.rotate(key(2), NOW + 5).unwrap();
    assert!(signer.key_ring().get(&first_key).is_none());
    assert_eq!(signer.key_ring().keys().len(), 1);
}

#[test]
fn repeated_rotations_keep_each_key_for_its_own_signatures() {
    let mut signer = signer();
    let a = signer
        .sign(Kind::Credential, b"a", NOW, NOW + 3 * DAY)
        .unwrap();
    signer.rotate(key(2), NOW + DAY).unwrap();
    let b = signer
        .sign(Kind::Credential, b"b", NOW + DAY, NOW + 2 * DAY)
        .unwrap();
    signer.rotate(key(3), NOW + DAY + 1).unwrap();
    let c = signer
        .sign(Kind::Credential, b"c", NOW + DAY + 2, NOW + 10 * DAY)
        .unwrap();
    assert_eq!(signer.key_ring().keys().len(), 3);

    let ring = published(&signer);
    for message in [&a, &b, &c] {
        assert!(
            ring.verify(message, Kind::Credential, NOW + DAY + 5)
                .is_ok()
        );
    }
    // Key 2 expires first, although it was retired after key 1.
    assert_eq!(
        ring.verify(&b, Kind::Credential, NOW + 2 * DAY),
        Err(VerifyError::KeyExpired)
    );
    assert!(ring.verify(&a, Kind::Credential, NOW + 2 * DAY).is_ok());

    signer.rotate(key(4), NOW + 2 * DAY).unwrap();
    // Key 2 has expired and is dropped; keys 1 and 3 remain beside the new key 4.
    assert_eq!(signer.key_ring().keys().len(), 3);
    assert!(signer.verify(&a, Kind::Credential, NOW + 2 * DAY).is_ok());
    assert!(signer.verify(&c, Kind::Credential, NOW + 2 * DAY).is_ok());
}

#[test]
fn signature_outside_the_key_period_is_rejected() {
    // Models an old key used after it was rotated out (e.g. leaked): the published ring
    // retired key 1 at NOW + 50, but a second holder of key 1 keeps signing.
    let mut official = signer();
    let issued = official
        .sign(Kind::Credential, b"ok", NOW + 10, NOW + 10 + DAY)
        .unwrap();
    official.rotate(key(2), NOW + 50).unwrap();
    let ring = published(&official);

    let mut rogue = signer();
    let after_retirement = rogue
        .sign(Kind::Credential, b"late", NOW + 60, NOW + 60 + DAY)
        .unwrap();
    let mut rogue = signer();
    let beyond_last_expiry = rogue
        .sign(Kind::Credential, b"long", NOW + 20, NOW + 20 + 2 * DAY)
        .unwrap();

    assert!(ring.verify(&issued, Kind::Credential, NOW + 100).is_ok());
    assert_eq!(
        ring.verify(&after_retirement, Kind::Credential, NOW + 100),
        Err(VerifyError::OutsideKeyPeriod)
    );
    assert_eq!(
        ring.verify(&beyond_last_expiry, Kind::Credential, NOW + 100),
        Err(VerifyError::OutsideKeyPeriod)
    );

    // Issued before the key's activation.
    let late_start = signer_with("cmty", 1, NOW + 1_000);
    let early = rogue
        .sign(Kind::Credential, b"early", NOW + 100, NOW + DAY)
        .unwrap();
    assert_eq!(
        published(&late_start).verify(&early, Kind::Credential, NOW + 2_000),
        Err(VerifyError::OutsideKeyPeriod)
    );
}

// Signer rules.

#[test]
fn signing_checks_validity_bounds() {
    let mut signer = signer();
    assert_eq!(
        signer.sign(Kind::Credential, b"x", NOW, NOW),
        Err(SignError::InvalidValidity)
    );
    assert_eq!(
        signer.sign(Kind::Credential, b"x", NOW + 5, NOW),
        Err(SignError::InvalidValidity)
    );
    assert_eq!(
        signer.sign(Kind::Credential, b"x", NOW, NOW + MAX_VALIDITY + 1),
        Err(SignError::ValidityTooLong)
    );
    assert!(
        signer
            .sign(Kind::Credential, b"x", NOW, NOW + MAX_VALIDITY)
            .is_ok()
    );
    assert_eq!(
        signer.sign(Kind::Credential, b"x", NOW - 1, NOW + DAY),
        Err(SignError::ClockBeforeActivation)
    );
    // Times up to the end of u64 encode and verify.
    let far = signer
        .sign(Kind::Credential, b"x", u64::MAX - 1, u64::MAX)
        .unwrap();
    assert!(signer.verify(&far, Kind::Credential, u64::MAX - 1).is_ok());
}

#[test]
fn refused_signatures_do_not_extend_the_key() {
    let mut signer = signer();
    signer.sign(Kind::Credential, b"x", NOW, NOW + DAY).unwrap();
    let before = signer.state();
    let _ = signer.sign(Kind::Credential, b"x", NOW, NOW + MAX_VALIDITY + 1);
    assert_eq!(signer.state(), before);
    assert_eq!(signer.key_ring().active().unwrap().signed_until(), 0);
}

#[test]
fn signer_construction_is_checked() {
    assert_eq!(
        Signer::new("", key(1), NOW, MAX_VALIDITY).unwrap_err(),
        SignError::InvalidIssuer
    );
    assert_eq!(
        Signer::new("cmty", key(1), NOW, 0).unwrap_err(),
        SignError::InvalidMaxValidity
    );
}

#[test]
fn rotation_refuses_reused_keys_and_clock_regressions() {
    let mut signer = signer();
    signer.sign(Kind::Credential, b"x", NOW, NOW + DAY).unwrap();
    assert_eq!(signer.rotate(key(1), NOW + 1), Err(SignError::KeyReused));
    signer.rotate(key(2), NOW + 2).unwrap();
    // Key 1 is retired but still in the ring.
    assert_eq!(signer.rotate(key(1), NOW + 3), Err(SignError::KeyReused));
    assert_eq!(
        signer.rotate(key(3), NOW + 1),
        Err(SignError::ClockBeforeActivation)
    );
}

#[test]
fn resume_continues_exact_state() {
    let mut signer = signer();
    let message = signer.sign(Kind::Credential, b"x", NOW, NOW + DAY).unwrap();
    let state = csgn::SigningState::from_cbor(&signer.state().to_cbor()).unwrap();
    drop(signer);
    let mut resumed = Signer::resume(state, key(1), NOW + 200).unwrap();
    resumed.rotate(key(2), NOW + 300).unwrap();
    assert_eq!(resumed.key_ring().keys()[0].signed_until(), NOW + DAY);
    assert!(
        resumed
            .verify(&message, Kind::Credential, NOW + DAY - 1)
            .is_ok()
    );
    assert_eq!(
        resumed.verify(&message, Kind::Credential, NOW + DAY),
        Err(VerifyError::KeyExpired)
    );
}

#[test]
fn issuance_changes_private_state_but_never_the_active_public_ring() {
    let mut signer = signer();
    let public = signer.key_ring().clone();
    let before = signer.state();
    signer
        .sign(Kind::Credential, b"first", NOW + 1, NOW + DAY + 1)
        .unwrap();
    signer
        .sign(Kind::Credential, b"second", NOW + 9, NOW + DAY + 99)
        .unwrap();
    assert_eq!(signer.key_ring(), &public);
    assert_eq!(signer.key_ring().to_cbor(), public.to_cbor());
    assert_eq!(format!("{:?}", signer.key_ring()), format!("{public:?}"));
    assert_eq!(public.active().unwrap().signed_until(), 0);
    assert_ne!(signer.state(), before);

    let state = csgn::SigningState::from_cbor(&signer.state().to_cbor()).unwrap();
    let mut signer = Signer::resume(state, key(1), NOW + 10).unwrap();
    signer.rotate(key(2), NOW + 11).unwrap();
    assert_eq!(signer.key_ring().keys()[0].signed_until(), NOW + 2 * DAY);
    signer.prune(NOW + DAY + 99).unwrap();
    assert_eq!(signer.key_ring().keys().len(), 2);
    signer.prune(NOW + 2 * DAY).unwrap();
    assert_eq!(signer.key_ring().keys().len(), 1);
}

#[test]
fn retention_rounding_saturates_without_premature_expiry() {
    let mut signer = signer_with("cmty", 1, u64::MAX - 100);
    let message = signer
        .sign(Kind::Credential, b"x", u64::MAX - 99, u64::MAX)
        .unwrap();
    signer.rotate(key(2), u64::MAX - 1).unwrap();
    let ring = published(&signer);
    assert_eq!(ring.keys()[0].signed_until(), u64::MAX);
    assert!(
        ring.verify(&message, Kind::Credential, u64::MAX - 1)
            .is_ok()
    );
    assert_eq!(
        ring.verify(&message, Kind::Credential, u64::MAX),
        Err(VerifyError::KeyExpired)
    );
}

#[test]
fn resume_requires_the_active_key_and_a_sane_clock() {
    let mut signer = signer();
    signer
        .sign(Kind::Credential, b"x", NOW + 10, NOW + DAY)
        .unwrap();
    assert_eq!(
        Signer::resume(signer.state(), key(2), NOW + 10).unwrap_err(),
        SignError::KeyMismatch
    );
    assert_eq!(
        Signer::resume(signer.state(), key(1), NOW + 9).unwrap_err(),
        SignError::ClockBeforeActivation
    );
    signer.rotate(key(2), NOW + 20).unwrap();
    assert_eq!(
        Signer::resume(signer.state(), key(1), NOW + 20).unwrap_err(),
        SignError::KeyMismatch
    );
}

#[test]
fn future_messages_and_clock_rollback_are_rejected() {
    let mut signer = signer();
    let message = signer
        .sign(Kind::Credential, b"x", NOW + 50, NOW + DAY)
        .unwrap();
    assert_eq!(
        signer.verify(&message, Kind::Credential, NOW + 49),
        Err(VerifyError::NotYetValid)
    );
    let state = signer.state();
    assert_eq!(
        signer.rotate(key(2), NOW + 49),
        Err(SignError::ClockBeforeActivation)
    );
    assert_eq!(
        signer.sign(Kind::Credential, b"x", NOW + 49, NOW + DAY),
        Err(SignError::ClockBeforeActivation)
    );
    assert_eq!(
        signer.prune(NOW + 49),
        Err(SignError::ClockBeforeActivation)
    );
    assert_eq!(state, signer.state());
    signer.rotate(key(2), NOW + 50).unwrap();
    assert!(signer.verify(&message, Kind::Credential, NOW + 50).is_ok());
}

#[test]
fn pruned_keys_cannot_be_reused_even_after_restart() {
    let mut signer = signer();
    signer.rotate(key(2), NOW).unwrap();
    assert_eq!(signer.key_ring().keys().len(), 1);
    let state = csgn::SigningState::from_cbor(&signer.state().to_cbor()).unwrap();
    let mut signer = Signer::resume(state, key(2), NOW).unwrap();
    assert_eq!(signer.rotate(key(1), NOW), Err(SignError::KeyReused));
}

// Structure.

#[test]
fn malformed_messages_are_rejected() {
    let mut signer = signer();
    let message = signer.sign(Kind::Credential, b"x", NOW, NOW + DAY).unwrap();
    let malformed = |bytes: &[u8]| {
        matches!(
            signer.verify(bytes, Kind::Credential, NOW),
            Err(VerifyError::Malformed(_))
        )
    };

    assert!(malformed(&[]));
    assert!(malformed(b"not cbor at all"));
    assert!(malformed(&message[..message.len() - 1]));
    let mut trailing = message.clone();
    trailing.push(0x00);
    assert!(malformed(&trailing));
    // Untagged COSE_Sign1 (the tag is the first byte, 0xd2).
    assert_eq!(message[0], 0xd2);
    assert!(malformed(&message[1..]));

    let detached = edit(&message, false, |m| m.payload = None);
    assert!(malformed(&detached));
    let unprotected_kid = edit(&message, false, |m| {
        m.unprotected.key_id = vec![1; 32];
    });
    assert!(malformed(&unprotected_kid));
    let content_type = edit(&message, true, |m| {
        m.protected.header.content_type = Some(coset::ContentType::Assigned(
            iana::CoapContentFormat::CoseSign1,
        ));
    });
    assert!(malformed(&content_type));
    let extra = edit(&message, true, |m| {
        m.protected
            .header
            .rest
            .push((Label::Int(-70000), Value::Null));
    });
    assert!(malformed(&extra));
    let unknown_kind = edit(&message, true, |m| {
        *header_value(&mut m.protected.header, KIND_LABEL) = Value::Text("passport".into());
    });
    assert!(malformed(&unknown_kind));
    let no_kind = edit(&message, true, |m| {
        m.protected
            .header
            .rest
            .retain(|(l, _)| *l != Label::Int(KIND_LABEL));
    });
    assert!(malformed(&no_kind));
    let short_kid = edit(&message, true, |m| m.protected.header.key_id.truncate(16));
    assert!(malformed(&short_kid));
    let negative_time = edit(&message, true, |m| {
        *claim(&mut m.protected.header, 6) = Value::Integer((-1i64).into());
    });
    assert!(malformed(&negative_time));
    let inverted = edit(&message, true, |m| {
        *claim(&mut m.protected.header, 6) = Value::Integer((NOW + 2 * DAY).into());
    });
    assert!(malformed(&inverted));
    let extra_claim = edit(&message, true, |m| {
        let Value::Map(claims) = header_value(
            &mut m.protected.header,
            iana::HeaderParameter::CwtClaims as i64,
        ) else {
            panic!("claims are a map");
        };
        claims.push((Value::Integer(5i64.into()), Value::Integer(NOW.into())));
    });
    assert!(malformed(&extra_claim));
}

#[test]
fn other_algorithms_are_rejected() {
    let mut signer = signer();
    let message = signer.sign(Kind::Credential, b"x", NOW, NOW + DAY).unwrap();
    for alg in [iana::Algorithm::EdDSA, iana::Algorithm::ES256] {
        let other = edit(&message, true, |m| {
            m.protected.header.alg = Some(coset::Algorithm::Assigned(alg));
        });
        assert_eq!(
            signer.verify(&other, Kind::Credential, NOW),
            Err(VerifyError::UnsupportedAlgorithm)
        );
    }
    let none = edit(&message, true, |m| m.protected.header.alg = None);
    assert_eq!(
        signer.verify(&none, Kind::Credential, NOW),
        Err(VerifyError::UnsupportedAlgorithm)
    );
}

// Secrets.

#[test]
fn no_secret_in_debug_output() {
    // 0xa5 = 165: look for both the hex and the decimal rendering of the seed bytes.
    let hex_pattern = "a5a5a5a5";
    let decimal_pattern = "165, 165";

    let secret = SecretKey::from_seed(&mut [0xa5u8; 32]);
    let key_id = secret.key_id();
    let mut signer = Signer::new("cmty", secret, NOW, MAX_VALIDITY).unwrap();
    let message = signer.sign(Kind::Credential, b"x", NOW, NOW + DAY).unwrap();
    let verified = signer.verify(&message, Kind::Credential, NOW).unwrap();
    let secret = SecretKey::from_seed(&mut [0xa5u8; 32]);

    for output in [
        format!("{secret:?}"),
        format!("{secret:#?}"),
        format!("{signer:?}"),
        format!("{signer:#?}"),
        format!("{:?}", signer.key_ring()),
        format!("{verified:?}"),
    ] {
        assert!(!output.contains(hex_pattern), "{output}");
        assert!(!output.contains(decimal_pattern), "{output}");
    }
    assert!(format!("{secret:?}").contains(&key_id.to_string()));
}
