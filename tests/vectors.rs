//! Deterministic test vectors.
//!
//! The expected bytes were computed independently of this crate, with Python's
//! `cryptography` (Ed25519) and `cbor2` (CBOR), following RFC 9052 (COSE_Sign1 and
//! Sig_structure) and RFC 9679 (key thumbprint). Vector 1 uses the key of RFC 8032,
//! section 7.1, test 1.

use csgn::{KeyId, KeyRing, Kind, VerifyError};

const NOW: u64 = 1_790_000_000;

/// RFC 8032, section 7.1, TEST 1.
const RFC8032_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

const KID_1: &str = "866eefbd6718c8846cd7ddfe43fc74ab1daac4538ff8514ea2ec2d410a415743";
const PAYLOAD_1: &[u8] = b"csgn test vector";
const COSE_1: &str = concat!(
    "d2845852a5013202820f3a00010000045820866eefbd6718c8846cd7ddfe43fc74ab1daac4538ff8",
    "514ea2ec2d410a4157430fa30164636d7479041a6ab28d00061a6ab13b803a000100006a63726564",
    "656e7469616ca0506373676e207465737420766563746f7258409d99588cbdc60a395557303e7aac",
    "9aee707d5808e7730bf747e79b27bad6dbdc326161c059354413922cff95457790cfde84be2be06e",
    "1dd3a3784014635afe0c",
);
const RING_1: &str = concat!(
    "a401020264636d74790381a70101025820866eefbd6718c8846cd7ddfe43fc74ab1daac4538ff851",
    "4ea2ec2d410a41574303320481022006215820d75a980182b10ab7d54bfed3c964073a0ee172f3da",
    "a62325af021a68f707511a3a000100001a6ab13b80041a00278d00",
);

const PUBLIC_2: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const KID_2: &str = "dd2fb4e18b5e1ce30c4633aaa5f681da79c3b32998cc5aa21b1149c37231a6ac";
const PAYLOAD_2: &str = "a1636e657701";
const COSE_2: &str = concat!(
    "d2845861a5013202820f3a00010000045820dd2fb4e18b5e1ce30c4633aaa5f681da79c3b32998cc",
    "5aa21b1149c37231a6ac0fa3016463676c62041a6ab14990061a6ab13b803a000100007818736e61",
    "7073686f742f7265766f636174696f6e2d6c697374a046a1636e6577015840af7b3ad3984eff5cd3",
    "303069907ac248586811ea75eeabc961736b848e3548ae3d011ab14771051f5ba9d1252e3c21e2a9",
    "bd6ab418dd24ff6759ca804b35a300",
);
const RING_2: &str = concat!(
    "a40102026463676c620381a70101025820dd2fb4e18b5e1ce30c4633aaa5f681da79c3b32998cc5a",
    "a21b1149c37231a6ac033204810220062158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d",
    "94121bf3748801b40f6f5c3a000100001a6ab13b80041a00278d00",
);

fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn array32(text: &str) -> [u8; 32] {
    hex(text).try_into().unwrap()
}

#[test]
fn key_ids_are_rfc9679_thumbprints() {
    assert_eq!(
        KeyId::from_public_key(&array32(RFC8032_PUBLIC)).as_bytes(),
        &array32(KID_1)
    );
    assert_eq!(
        KeyId::from_public_key(&array32(PUBLIC_2)).as_bytes(),
        &array32(KID_2)
    );
    assert_eq!(KeyId::from_bytes(array32(KID_1)).to_string(), KID_1);
}

#[test]
fn vector_1_verifies_with_its_published_ring() {
    let ring = KeyRing::from_cbor(&hex(RING_1)).unwrap();
    assert_eq!(ring.issuer(), "cmty");
    assert_eq!(ring.to_cbor(), hex(RING_1));
    let entry = ring.active().unwrap();
    assert_eq!(entry.public_key(), array32(RFC8032_PUBLIC));
    assert_eq!(entry.key_id().as_bytes(), &array32(KID_1));
    assert_eq!(entry.activated_at(), NOW);
    assert_eq!(entry.signed_until(), 0);

    let verified = ring.verify(&hex(COSE_1), Kind::Credential, NOW).unwrap();
    assert_eq!(verified.payload(), PAYLOAD_1);
    assert_eq!(verified.issued_at(), NOW);
    assert_eq!(verified.valid_until(), NOW + 86_400);
    assert_eq!(verified.key_id().as_bytes(), &array32(KID_1));
}

#[test]
fn vector_2_verifies_with_its_published_ring() {
    let ring = KeyRing::from_cbor(&hex(RING_2)).unwrap();
    assert_eq!(ring.issuer(), "cglb");
    assert_eq!(ring.to_cbor(), hex(RING_2));
    let verified = ring
        .verify(&hex(COSE_2), Kind::RevocationListSnapshot, NOW + 3_599)
        .unwrap();
    assert_eq!(verified.payload(), hex(PAYLOAD_2));
}

#[test]
fn vectors_are_refused_outside_their_terms() {
    let ring_1 = KeyRing::from_cbor(&hex(RING_1)).unwrap();
    let ring_2 = KeyRing::from_cbor(&hex(RING_2)).unwrap();
    assert_eq!(
        ring_1.verify(&hex(COSE_1), Kind::SettingsSnapshot, NOW),
        Err(VerifyError::WrongKind {
            expected: Kind::SettingsSnapshot,
            found: Kind::Credential
        })
    );
    assert_eq!(
        ring_1.verify(&hex(COSE_1), Kind::Credential, NOW + 86_400),
        Err(VerifyError::Expired)
    );
    assert_eq!(
        ring_2.verify(&hex(COSE_1), Kind::Credential, NOW),
        Err(VerifyError::UnknownKey)
    );
    assert_eq!(
        ring_1.verify(&hex(COSE_2), Kind::RevocationListSnapshot, NOW),
        Err(VerifyError::UnknownKey)
    );
}

fn rejects_reencoding(changed: Vec<u8>) {
    use coset::{CoseSign1, TaggedCborSerializable};
    use ed25519_dalek::{Signature, VerifyingKey};

    let original = hex(COSE_1);
    assert_ne!(changed, original);
    // Prove these are alternate encodings of a valid signed object, not damaged
    // signatures. Generic COSE verification accepts each of them.
    let decoded = CoseSign1::from_tagged_slice(&changed).unwrap();
    assert_eq!(decoded.clone().to_tagged_vec().unwrap(), original);
    let key = VerifyingKey::from_bytes(&array32(RFC8032_PUBLIC)).unwrap();
    decoded
        .verify_signature(&[], |signature, data| {
            key.verify_strict(data, &Signature::from_slice(signature).unwrap())
        })
        .unwrap();
    let ring = KeyRing::from_cbor(&hex(RING_1)).unwrap();
    assert!(matches!(
        ring.verify(&changed, Kind::Credential, NOW),
        Err(VerifyError::Malformed(_))
    ));
}

fn unprotected_offset(message: &[u8]) -> usize {
    use coset::{CoseSign1, TaggedCborSerializable};
    let header = CoseSign1::from_tagged_slice(message)
        .unwrap()
        .protected
        .original_data
        .unwrap();
    // These vectors have a one-byte tag, array length and two-byte bstr length.
    4 + header.len()
}

#[test]
fn noncanonical_long_lengths_are_refused() {
    let mut message = hex(COSE_1);
    message.splice(1..2, [0x98, 0x04]);
    rejects_reencoding(message);
    let mut message = hex(COSE_1);
    message.splice(2..4, [0x59, 0x00, message[3]]);
    rejects_reencoding(message);
}

#[test]
fn noncanonical_long_empty_map_is_refused() {
    let mut message = hex(COSE_1);
    let offset = unprotected_offset(&message);
    assert_eq!(message[offset], 0xa0);
    message.splice(offset..offset + 1, [0xb8, 0x00]);
    rejects_reencoding(message);
}

#[test]
fn noncanonical_long_tags_are_refused() {
    for tag in [vec![0xd8, 18], vec![0xd9, 0, 18]] {
        let mut message = hex(COSE_1);
        message.splice(0..1, tag);
        rejects_reencoding(message);
    }
}

#[test]
fn noncanonical_indefinite_byte_strings_are_refused() {
    let mut message = hex(COSE_1);
    let offset = unprotected_offset(&message) + 1;
    assert_eq!(message[offset], 0x40 + PAYLOAD_1.len() as u8);
    message.insert(offset + 1 + PAYLOAD_1.len(), 0xff);
    message.insert(offset, 0x5f);
    rejects_reencoding(message);
}

#[test]
fn outer_shape_is_rejected_before_recursive_decoding() {
    let ring = KeyRing::from_cbor(&hex(RING_1)).unwrap();
    // A million-element payload array fits the wire-size bound but would inflate
    // into a large Value tree if full CBOR decoding ran before the shape check.
    let mut many_values = vec![0xd2, 0x84, 0x40, 0xa0, 0x9a, 0x00, 0x10, 0x00, 0x00];
    many_values.resize(many_values.len() + csgn::MAX_PAYLOAD_LEN, 0);
    many_values.extend_from_slice(&[0x58, 0x40]);
    many_values.extend_from_slice(&[0; 64]);
    let mut nested = vec![0xd2, 0x84, 0x40, 0xa0];
    nested.extend_from_slice(&[0x81; 1000]);
    nested.push(0);
    let huge_claimed_length = vec![
        0xd2, 0x84, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    for message in [many_values, nested, huge_claimed_length] {
        assert_eq!(
            ring.verify(&message, Kind::Credential, NOW),
            Err(VerifyError::Malformed("invalid COSE shape"))
        );
    }
}

#[test]
fn published_maximum_lifetime_is_enforced_on_valid_signatures() {
    use coset::CborSerializable;
    use coset::cbor::value::Value;
    let mut value = Value::from_slice(&hex(RING_1)).unwrap();
    for (maximum, expected) in [(86_400u64, true), (86_399, false), (u64::MAX, true)] {
        let Value::Map(fields) = &mut value else {
            panic!()
        };
        fields
            .iter_mut()
            .find(|(key, _)| *key == Value::Integer(4.into()))
            .unwrap()
            .1 = Value::Integer(maximum.into());
        let ring = KeyRing::from_cbor(&value.clone().to_vec().unwrap()).unwrap();
        assert_eq!(ring.max_validity(), maximum);
        let result = ring.verify(&hex(COSE_1), Kind::Credential, NOW);
        if expected {
            assert!(result.is_ok());
        } else {
            assert_eq!(result, Err(VerifyError::ValidityTooLong));
        }
    }
}

#[cfg(feature = "volatile-signer")]
mod signing {
    use super::*;
    use csgn::{SecretKey, Signer};

    /// RFC 8032, section 7.1, TEST 1.
    const RFC8032_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    #[test]
    fn rfc8032_seed_gives_the_rfc8032_public_key() {
        let key = SecretKey::from_seed(&mut array32(RFC8032_SEED));
        assert_eq!(key.public_key(), array32(RFC8032_PUBLIC));
        assert_eq!(key.key_id().as_bytes(), &array32(KID_1));
    }

    #[test]
    fn signing_reproduces_vector_1() {
        let key = SecretKey::from_seed(&mut array32(RFC8032_SEED));
        let mut signer = Signer::new("cmty", key, NOW, 30 * 86_400).unwrap();
        let message = signer
            .sign(Kind::Credential, PAYLOAD_1, NOW, NOW + 86_400)
            .unwrap();
        assert_eq!(message, hex(COSE_1));
        assert_eq!(signer.key_ring().to_cbor(), hex(RING_1));
    }

    #[test]
    fn signing_reproduces_vector_2() {
        let key = SecretKey::from_seed(&mut [1u8; 32]);
        let mut signer = Signer::new("cglb", key, NOW, 30 * 86_400).unwrap();
        let message = signer
            .sign(
                Kind::RevocationListSnapshot,
                &hex(PAYLOAD_2),
                NOW,
                NOW + 3_600,
            )
            .unwrap();
        assert_eq!(message, hex(COSE_2));
        assert_eq!(signer.key_ring().to_cbor(), hex(RING_2));
    }
}
