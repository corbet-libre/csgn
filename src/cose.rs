//! The COSE_Sign1 layout csgn writes and the strict parser for it.
//!
//! Protected header (the only header; the unprotected header must be empty):
//!
//! | Label | Name | Value |
//! |---|---|---|
//! | 1 | alg | -19 (Ed25519, RFC 9864) |
//! | 2 | crit | [15, -65537]: claims and kind must be understood |
//! | 4 | kid | RFC 9679 thumbprint of the signing key, 32 bytes |
//! | 15 | CWT Claims (RFC 9597) | `{1 (iss): issuer, 4 (exp): valid until, 6 (iat): issued}` |
//! | -65537 | kind (private use) | text, see [`Kind::as_str`] |
//!
//! Anything else in the headers is refused. The payload is attached, never detached.

use coset::cbor::value::Value;
use coset::{
    Algorithm, AsCborValue, CborSerializable, CoseSign1, Label, RegisteredLabelWithPrivate,
    TaggedCborSerializable, iana,
};
#[cfg(feature = "signer")]
use coset::{Header, HeaderBuilder};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::{KeyId, Kind, VerifyError};

/// Private-use header label (RFC 9052, section 3.1: below -65536) carrying the [`Kind`].
pub(crate) const KIND_LABEL: i64 = -65537;
const CWT_CLAIMS_LABEL: i64 = iana::HeaderParameter::CwtClaims as i64;
const CLAIM_ISS: i64 = iana::CwtClaimName::Iss as i64;
const CLAIM_EXP: i64 = iana::CwtClaimName::Exp as i64;
const CLAIM_IAT: i64 = iana::CwtClaimName::Iat as i64;

/// External additional authenticated data; csgn binds everything in the protected header.
pub(crate) const EXTERNAL_AAD: &[u8] = &[];

/// The only algorithm csgn writes or accepts.
pub(crate) fn algorithm() -> Algorithm {
    Algorithm::Assigned(iana::Algorithm::Ed25519)
}

/// Builds the protected header for one signature.
#[cfg(feature = "signer")]
pub(crate) fn protected_header(
    key_id: &KeyId,
    kind: Kind,
    issuer: &str,
    issued_at: u64,
    valid_until: u64,
) -> Header {
    let claims = Value::Map(vec![
        (int(CLAIM_ISS), Value::Text(issuer.to_owned())),
        (int(CLAIM_EXP), Value::Integer(valid_until.into())),
        (int(CLAIM_IAT), Value::Integer(issued_at.into())),
    ]);
    HeaderBuilder::new()
        .algorithm(iana::Algorithm::Ed25519)
        .add_critical(iana::HeaderParameter::CwtClaims)
        .add_critical_label(RegisteredLabelWithPrivate::PrivateUse(KIND_LABEL))
        .key_id(key_id.as_bytes().to_vec())
        .value(CWT_CLAIMS_LABEL, claims)
        .value(KIND_LABEL, Value::Text(kind.as_str().to_owned()))
        .build()
}

/// Check only the fixed outer shape with ciborium's allocation-free token decoder.
/// Byte strings are skipped as slices, never decoded as arbitrary nested Values.
fn check_shape(mut input: &[u8]) -> Result<(), VerifyError> {
    use ciborium_ll::{Decoder, Header};
    const BAD: VerifyError = VerifyError::Malformed("invalid COSE shape");

    fn pull(input: &mut &[u8]) -> Result<Header, VerifyError> {
        Decoder::from(input).pull().map_err(|_| BAD)
    }
    fn skip_bytes(input: &mut &[u8], max: usize) -> Result<usize, VerifyError> {
        let Header::Bytes(Some(length)) = pull(input)? else {
            return Err(BAD);
        };
        if length > max {
            return Err(BAD);
        }
        *input = input.get(length..).ok_or(BAD)?;
        Ok(length)
    }

    if pull(&mut input)? != Header::Tag(18) || pull(&mut input)? != Header::Array(Some(4)) {
        return Err(BAD);
    }
    skip_bytes(&mut input, 4096)?;
    if pull(&mut input)? != Header::Map(Some(0)) {
        return Err(BAD);
    }
    skip_bytes(&mut input, crate::MAX_PAYLOAD_LEN)?;
    if skip_bytes(&mut input, 64)? != 64 || !input.is_empty() {
        return Err(BAD);
    }
    Ok(())
}

/// A structurally valid csgn message whose signature has not been checked yet.
pub(crate) struct Parsed {
    sign1: CoseSign1,
    pub(crate) key_id: KeyId,
    pub(crate) kind: Kind,
    pub(crate) issuer: String,
    pub(crate) issued_at: u64,
    pub(crate) valid_until: u64,
}

impl Parsed {
    /// Checks the Ed25519 signature over the RFC 9052 `Sig_structure` (built by `coset` from
    /// the original protected header bytes). Uses strict verification, which also refuses weak
    /// keys and non-canonical signatures.
    pub(crate) fn verify_signature(&self, key: &VerifyingKey) -> Result<(), VerifyError> {
        self.sign1
            .verify_signature(EXTERNAL_AAD, |signature, signed_data| {
                let signature =
                    Signature::from_slice(signature).map_err(|_| VerifyError::BadSignature)?;
                key.verify_strict(signed_data, &signature)
                    .map_err(|_| VerifyError::BadSignature)
            })
    }

    pub(crate) fn into_payload(self) -> Vec<u8> {
        self.sign1.payload.unwrap_or_default()
    }
}

/// Parses a tagged COSE_Sign1 and checks that it has exactly the csgn layout.
pub(crate) fn parse(bytes: &[u8]) -> Result<Parsed, VerifyError> {
    if bytes.len() > crate::MAX_PAYLOAD_LEN + 8192 {
        return Err(VerifyError::Malformed("message too large"));
    }
    check_shape(bytes)?;
    let value = Value::from_slice(bytes).map_err(|_| VerifyError::Malformed("not CBOR"))?;
    let Value::Tag(18, value) = value else {
        return Err(VerifyError::Malformed("not a tagged COSE_Sign1"));
    };
    let Value::Array(parts) = value.as_ref() else {
        return Err(VerifyError::Malformed("not a COSE_Sign1 array"));
    };
    if parts.len() != 4 || !matches!(&parts[1], Value::Map(map) if map.is_empty()) {
        return Err(VerifyError::Malformed(
            "invalid message or unprotected header",
        ));
    }
    let Value::Bytes(protected) = &parts[0] else {
        return Err(VerifyError::Malformed("protected header is not bytes"));
    };
    if protected.len() > 4096 {
        return Err(VerifyError::Malformed("protected header too large"));
    }
    let raw_header = Value::from_slice(protected)
        .ok()
        .and_then(int_map)
        .ok_or(VerifyError::Malformed("invalid protected map"))?;
    if raw_header
        .iter()
        .any(|(label, _)| ![1, 2, 4, CWT_CLAIMS_LABEL, KIND_LABEL].contains(label))
    {
        return Err(VerifyError::Malformed("unexpected header parameter"));
    }
    if !matches!(&parts[2], Value::Bytes(payload) if payload.len() <= crate::MAX_PAYLOAD_LEN) {
        return Err(VerifyError::Malformed("missing or oversized payload"));
    }
    let sign1 = CoseSign1::from_cbor_value(*value)
        .map_err(|_| VerifyError::Malformed("not a COSE_Sign1"))?;
    // The outer encoding is not signed. Require coset's unique encoding so a
    // credential cannot acquire another byte identity without another signature.
    // Preserve original protected bytes: those are already signature-bound.
    let canonical = sign1
        .clone()
        .to_tagged_vec()
        .map_err(|_| VerifyError::Malformed("cannot re-encode COSE_Sign1"))?;
    if canonical != bytes {
        return Err(VerifyError::Malformed("non-canonical COSE_Sign1"));
    }
    if !sign1.unprotected.is_empty() {
        return Err(VerifyError::Malformed("unprotected header is not empty"));
    }
    if sign1.payload.is_none() {
        return Err(VerifyError::Malformed("detached payload"));
    }

    let header = &sign1.protected.header;
    if header.alg != Some(algorithm()) {
        return Err(VerifyError::UnsupportedAlgorithm);
    }
    if header.crit.len() != 2
        || !header
            .crit
            .contains(&iana::HeaderParameter::CwtClaims.into())
        || !header
            .crit
            .contains(&RegisteredLabelWithPrivate::PrivateUse(KIND_LABEL))
        || header.content_type.is_some()
        || !header.iv.is_empty()
        || !header.partial_iv.is_empty()
        || !header.counter_signatures.is_empty()
    {
        return Err(VerifyError::Malformed("unexpected header parameter"));
    }
    let key_id = KeyId::from_slice(&header.key_id)
        .ok_or(VerifyError::Malformed("key ID is not 32 bytes"))?;

    // coset already refuses duplicate labels within a header map.
    let mut kind = None;
    let mut claims = None;
    for (label, value) in &header.rest {
        match label {
            Label::Int(KIND_LABEL) => kind = Some(value),
            Label::Int(CWT_CLAIMS_LABEL) => claims = Some(value),
            _ => return Err(VerifyError::Malformed("unexpected header parameter")),
        }
    }
    let kind = match kind {
        Some(Value::Text(text)) => {
            Kind::from_wire(text).ok_or(VerifyError::Malformed("unknown kind"))?
        }
        _ => return Err(VerifyError::Malformed("missing kind")),
    };
    let mut claims = claims
        .cloned()
        .and_then(int_map)
        .ok_or(VerifyError::Malformed("CWT claims are not a map"))?;
    let issuer = match take(&mut claims, CLAIM_ISS) {
        Some(Value::Text(text))
            if !text.is_empty() && text.len() <= crate::MAX_ISSUER_LEN && !text.contains('\0') =>
        {
            text
        }
        _ => return Err(VerifyError::Malformed("missing issuer")),
    };
    let valid_until = take(&mut claims, CLAIM_EXP)
        .and_then(as_u64)
        .ok_or(VerifyError::Malformed("missing expiry"))?;
    let issued_at = take(&mut claims, CLAIM_IAT)
        .and_then(as_u64)
        .ok_or(VerifyError::Malformed("missing issued time"))?;
    if !claims.is_empty() {
        return Err(VerifyError::Malformed("unexpected claim"));
    }
    if issued_at >= valid_until {
        return Err(VerifyError::Malformed("expiry not after issued time"));
    }

    Ok(Parsed {
        sign1,
        key_id,
        kind,
        issuer,
        issued_at,
        valid_until,
    })
}

pub(crate) fn int(value: i64) -> Value {
    Value::Integer(value.into())
}

/// Turns a CBOR map with integer keys into key/value pairs. `None` if the value is not a map,
/// a key is not an integer in `i64` range, or a key repeats.
pub(crate) fn int_map(value: Value) -> Option<Vec<(i64, Value)>> {
    let Value::Map(entries) = value else {
        return None;
    };
    if entries.len() > 16 {
        return None;
    }
    let mut pairs: Vec<(i64, Value)> = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let Value::Integer(key) = key else {
            return None;
        };
        let key = i64::try_from(key).ok()?;
        if pairs.iter().any(|(seen, _)| *seen == key) {
            return None;
        }
        pairs.push((key, value));
    }
    Some(pairs)
}

/// Removes and returns the value for `key`.
pub(crate) fn take(pairs: &mut Vec<(i64, Value)>, key: i64) -> Option<Value> {
    let index = pairs.iter().position(|(k, _)| *k == key)?;
    Some(pairs.swap_remove(index).1)
}

/// An unsigned integer; `None` for anything else, including negative integers.
pub(crate) fn as_u64(value: Value) -> Option<u64> {
    match value {
        Value::Integer(integer) => u64::try_from(integer).ok(),
        _ => None,
    }
}
