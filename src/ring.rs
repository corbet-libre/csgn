//! The public key ring: what verifiers hold, what the signer publishes.

use std::collections::BTreeSet;

use coset::cbor::value::Value;
use coset::{AsCborValue, CborSerializable, CoseKey, KeyOperation, KeyType, Label, iana};
use ed25519_dalek::VerifyingKey;

use crate::cose::{self, as_u64, int, int_map, take};
use crate::{KeyId, Kind};

/// Version of the key ring encoding.
const RING_FORMAT_VERSION: u64 = 2;
const RING_VERSION: i64 = 1;
const RING_ISSUER: i64 = 2;
const RING_KEYS: i64 = 3;
const RING_MAX_VALIDITY: i64 = 4;

const PARAM_CRV: i64 = iana::OkpKeyParameter::Crv as i64;
const PARAM_X: i64 = iana::OkpKeyParameter::X as i64;
const PARAM_D: i64 = iana::OkpKeyParameter::D as i64;
/// Private-use COSE_Key parameters (RFC 9052, section 7.1: below -65536).
const PARAM_ACTIVATED_AT: i64 = -65537;
const PARAM_RETIRED_AT: i64 = -65538;
const PARAM_SIGNED_UNTIL: i64 = -65539;

/// One public key in the ring and the period it is good for.
///
/// All times are Unix seconds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEntry {
    pub(crate) key_id: KeyId,
    pub(crate) public_key: VerifyingKey,
    pub(crate) activated_at: u64,
    pub(crate) retired_at: Option<u64>,
    pub(crate) signed_until: u64,
}

impl KeyEntry {
    pub(crate) fn new_active(key_id: KeyId, public_key: VerifyingKey, activated_at: u64) -> Self {
        KeyEntry {
            key_id,
            public_key,
            activated_at,
            retired_at: None,
            signed_until: 0,
        }
    }

    /// The key ID (RFC 9679 thumbprint of the public key).
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    /// When the key started signing.
    pub fn activated_at(&self) -> u64 {
        self.activated_at
    }

    /// When the key stopped signing (was rotated out); `None` while it is the active key.
    pub fn retired_at(&self) -> Option<u64> {
        self.retired_at
    }

    /// Retired retention deadline, rounded up to a UTC day; zero while active or unused.
    ///
    /// The active key's exact deadline is private recovery metadata, never published.
    pub fn signed_until(&self) -> u64 {
        self.signed_until
    }

    /// Whether this is the key currently signing.
    pub fn is_active(&self) -> bool {
        self.retired_at.is_none()
    }

    /// Whether a retired key has outlived everything it signed.
    pub(crate) fn is_expired(&self, now: u64) -> bool {
        self.retired_at.is_some() && now >= self.signed_until
    }

    fn to_cose_key(&self) -> CoseKey {
        let mut params = vec![
            (
                Label::Int(PARAM_CRV),
                int(iana::EllipticCurve::Ed25519 as i64),
            ),
            (
                Label::Int(PARAM_X),
                Value::Bytes(self.public_key.to_bytes().to_vec()),
            ),
            (
                Label::Int(PARAM_ACTIVATED_AT),
                Value::Integer(self.activated_at.into()),
            ),
        ];
        if let Some(retired_at) = self.retired_at {
            params.push((
                Label::Int(PARAM_RETIRED_AT),
                Value::Integer(retired_at.into()),
            ));
            params.push((
                Label::Int(PARAM_SIGNED_UNTIL),
                Value::Integer(self.signed_until.into()),
            ));
        }
        CoseKey {
            kty: KeyType::Assigned(iana::KeyType::OKP),
            key_id: self.key_id.as_bytes().to_vec(),
            alg: Some(cose::algorithm()),
            key_ops: verify_only(),
            params,
            ..CoseKey::default()
        }
    }

    fn from_cose_key(key: CoseKey) -> Result<KeyEntry, RingError> {
        if key.kty != KeyType::Assigned(iana::KeyType::OKP) {
            return Err(RingError::Malformed("key type is not OKP"));
        }
        if key.alg != Some(cose::algorithm()) {
            return Err(RingError::Malformed("key algorithm is not Ed25519"));
        }
        if key.key_ops != verify_only() {
            return Err(RingError::Malformed("key operations are not [verify]"));
        }
        if !key.base_iv.is_empty() {
            return Err(RingError::Malformed("unexpected key parameter"));
        }
        let mut params: Vec<(i64, Value)> = Vec::with_capacity(key.params.len());
        for (label, value) in key.params {
            match label {
                Label::Int(label) => params.push((label, value)),
                Label::Text(_) => return Err(RingError::Malformed("unexpected key parameter")),
            }
        }
        if params.iter().any(|(label, _)| *label == PARAM_D) {
            return Err(RingError::SecretKeyMaterial);
        }
        match take(&mut params, PARAM_CRV) {
            Some(value) if value == int(iana::EllipticCurve::Ed25519 as i64) => {}
            _ => return Err(RingError::Malformed("curve is not Ed25519")),
        }
        let public_bytes: [u8; 32] = match take(&mut params, PARAM_X) {
            Some(Value::Bytes(bytes)) => <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| RingError::Malformed("public key is not 32 bytes"))?,
            _ => return Err(RingError::Malformed("missing public key")),
        };
        let activated_at = take(&mut params, PARAM_ACTIVATED_AT)
            .and_then(as_u64)
            .ok_or(RingError::Malformed("missing activation time"))?;
        let retired_at = match take(&mut params, PARAM_RETIRED_AT) {
            None => None,
            Some(value) => {
                Some(as_u64(value).ok_or(RingError::Malformed("retirement time is not a uint"))?)
            }
        };
        let signed_until = match (retired_at, take(&mut params, PARAM_SIGNED_UNTIL)) {
            (None, None) => 0,
            (Some(_), Some(value)) => as_u64(value)
                .filter(|value| rounded_deadline(*value) == *value)
                .ok_or(RingError::Malformed("invalid rounded retention deadline"))?,
            _ => {
                return Err(RingError::Malformed(
                    "unexpected or missing retention deadline",
                ));
            }
        };
        if !params.is_empty() {
            return Err(RingError::Malformed("unexpected key parameter"));
        }
        if retired_at.is_some_and(|retired_at| retired_at < activated_at) {
            return Err(RingError::Malformed("key retired before it was activated"));
        }

        if signed_until != 0 && signed_until <= activated_at {
            return Err(RingError::Malformed("invalid signed-until time"));
        }
        let public_key =
            VerifyingKey::from_bytes(&public_bytes).map_err(|_| RingError::InvalidPublicKey)?;
        if public_key.is_weak() {
            return Err(RingError::InvalidPublicKey);
        }
        let key_id = KeyId::from_public_key(&public_bytes);
        if key.key_id != key_id.as_bytes() {
            return Err(RingError::KeyIdMismatch);
        }
        Ok(KeyEntry {
            key_id,
            public_key,
            activated_at,
            retired_at,
            signed_until,
        })
    }
}

/// Ceiling to a UTC day, saturating at the representable end of time.
pub(crate) fn rounded_deadline(exact: u64) -> u64 {
    let remainder = exact % 86_400;
    if remainder == 0 {
        exact
    } else {
        exact.saturating_add(86_400 - remainder)
    }
}

fn verify_only() -> BTreeSet<KeyOperation> {
    BTreeSet::from([KeyOperation::Assigned(iana::KeyOperation::Verify)])
}

/// The public keys of one issuer (one level: global or community).
///
/// Holds the active key and every retired key that still has unexpired signatures. The
/// signer publishes it with [`KeyRing::to_cbor`]; verifiers load it with
/// [`KeyRing::from_cbor`] and call [`KeyRing::verify`]. It contains no secret material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRing {
    issuer: String,
    keys: Vec<KeyEntry>,
    max_validity: u64,
}

impl KeyRing {
    pub(crate) fn new(issuer: String, first: KeyEntry, max_validity: u64) -> Self {
        KeyRing {
            issuer,
            keys: vec![first],
            max_validity,
        }
    }

    /// The issuer every message in this ring must name (e.g. `cgbl` or `cmty`).
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Maximum accepted message lifetime in seconds, authenticated with this ring.
    pub fn max_validity(&self) -> u64 {
        self.max_validity
    }

    /// All keys, oldest first.
    pub fn keys(&self) -> &[KeyEntry] {
        &self.keys
    }

    /// The key with this ID, if the ring holds it.
    pub fn get(&self, key_id: &KeyId) -> Option<&KeyEntry> {
        self.keys.iter().find(|entry| entry.key_id == *key_id)
    }

    /// The key currently signing, if any.
    pub fn active(&self) -> Option<&KeyEntry> {
        self.keys.iter().find(|entry| entry.is_active())
    }

    #[cfg(feature = "signer")]
    pub(crate) fn active_mut(&mut self) -> Option<&mut KeyEntry> {
        self.keys.iter_mut().find(|entry| entry.is_active())
    }

    #[cfg(feature = "signer")]
    pub(crate) fn push(&mut self, entry: KeyEntry) {
        self.keys.push(entry);
    }

    /// Drops retired keys that have outlived everything they signed.
    #[cfg(feature = "signer")]
    pub(crate) fn prune(&mut self, now: u64) {
        self.keys.retain(|entry| !entry.is_expired(now));
    }

    /// Verifies a COSE_Sign1 produced by csgn and returns its payload.
    ///
    /// `now` is the verifier's clock in Unix seconds. The payload is returned only if all of
    /// these hold, checked in this order:
    ///
    /// 1. the bytes are a tagged COSE_Sign1 with exactly the csgn header layout
    ///    ([`VerifyError::Malformed`], [`VerifyError::UnsupportedAlgorithm`]);
    /// 2. the key ID is in this ring ([`VerifyError::UnknownKey`]);
    /// 3. the key has not expired: a retired key verifies only until its rounded
    ///    retention deadline ([`VerifyError::KeyExpired`]);
    /// 4. the Ed25519 signature over payload and protected header is valid
    ///    ([`VerifyError::BadSignature`]);
    /// 5. the issuer is this ring's issuer ([`VerifyError::WrongIssuer`]);
    /// 6. the kind is `expected` ([`VerifyError::WrongKind`]);
    /// 7. the message was issued while the key was active and, for a retired key, expires no
    ///    later than the key's signed-until time ([`VerifyError::OutsideKeyPeriod`]);
    /// 8. the message has not expired ([`VerifyError::Expired`]).
    ///
    /// The ring's maximum lifetime is enforced after issuer/kind checks
    /// ([`VerifyError::ValidityTooLong`]).
    pub fn verify(&self, cose: &[u8], expected: Kind, now: u64) -> Result<Verified, VerifyError> {
        let message = cose::parse(cose)?;
        let entry = self.get(&message.key_id).ok_or(VerifyError::UnknownKey)?;
        if entry.is_expired(now) {
            return Err(VerifyError::KeyExpired);
        }
        message.verify_signature(&entry.public_key)?;
        if message.issuer != self.issuer {
            return Err(VerifyError::WrongIssuer);
        }
        if message.kind != expected {
            return Err(VerifyError::WrongKind {
                expected,
                found: message.kind,
            });
        }
        if message.valid_until - message.issued_at > self.max_validity {
            return Err(VerifyError::ValidityTooLong);
        }
        let before_activation = message.issued_at < entry.activated_at;
        let after_retirement = entry.retired_at.is_some_and(|retired_at| {
            message.issued_at > retired_at || message.valid_until > entry.signed_until
        });
        if before_activation || after_retirement {
            return Err(VerifyError::OutsideKeyPeriod);
        }
        if now < message.issued_at {
            return Err(VerifyError::NotYetValid);
        }
        if now >= message.valid_until {
            return Err(VerifyError::Expired);
        }
        Ok(Verified {
            kind: message.kind,
            key_id: message.key_id,
            issued_at: message.issued_at,
            valid_until: message.valid_until,
            payload: message.into_payload(),
        })
    }

    /// Encodes the ring as CBOR: `{1: format version (2), 2: issuer, 3: COSE_KeySet,
    /// 4: max_validity}`.
    ///
    /// Each COSE_Key (RFC 9052, section 7) is an OKP Ed25519 public key with `kid`, `alg`
    /// Ed25519 and `key_ops` [verify], plus private-use parameters -65537 (activated at),
    /// -65538 (retired at) and -65539 (rounded retention), both absent while active.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut keys = Vec::with_capacity(self.keys.len());
        for entry in &self.keys {
            // A key built from a validated entry has no duplicate labels, the only thing
            // that makes coset's conversion fail.
            keys.push(
                entry
                    .to_cose_key()
                    .to_cbor_value()
                    .expect("key ring entries always encode"),
            );
        }
        let ring = Value::Map(vec![
            (
                int(RING_VERSION),
                Value::Integer(RING_FORMAT_VERSION.into()),
            ),
            (int(RING_ISSUER), Value::Text(self.issuer.clone())),
            (int(RING_KEYS), Value::Array(keys)),
            (
                int(RING_MAX_VALIDITY),
                Value::Integer(self.max_validity.into()),
            ),
        ]);
        ring.to_vec()
            .expect("CBOR encoding into memory cannot fail")
    }

    /// Decodes and validates a ring produced by [`KeyRing::to_cbor`].
    ///
    /// Refuses unknown versions and fields, secret key material, keys whose ID is not their
    /// thumbprint, invalid or weak public keys, duplicate keys and more than one active key.
    pub fn from_cbor(bytes: &[u8]) -> Result<KeyRing, RingError> {
        if bytes.len() > 256 * 1024 {
            return Err(RingError::Malformed("ring too large"));
        }
        let value = Value::from_slice(bytes).map_err(|_| RingError::Malformed("not CBOR"))?;
        let mut fields = int_map(value).ok_or(RingError::Malformed("ring is not a map"))?;
        match take(&mut fields, RING_VERSION).and_then(as_u64) {
            Some(RING_FORMAT_VERSION) => {}
            Some(_) => return Err(RingError::UnsupportedVersion),
            None => return Err(RingError::Malformed("missing version")),
        }
        let issuer = match take(&mut fields, RING_ISSUER) {
            Some(Value::Text(issuer))
                if !issuer.is_empty()
                    && issuer.len() <= crate::MAX_ISSUER_LEN
                    && !issuer.contains('\0') =>
            {
                issuer
            }
            _ => return Err(RingError::Malformed("missing issuer")),
        };
        let items = match take(&mut fields, RING_KEYS) {
            Some(Value::Array(items)) => items,
            _ => return Err(RingError::Malformed("missing keys")),
        };
        let max_validity = take(&mut fields, RING_MAX_VALIDITY)
            .and_then(as_u64)
            .filter(|value| *value > 0)
            .ok_or(RingError::Malformed("missing or invalid maximum validity"))?;
        if !fields.is_empty() {
            return Err(RingError::Malformed("unexpected ring field"));
        }

        if items.len() > crate::MAX_RING_KEYS {
            return Err(RingError::Malformed("too many keys"));
        }
        let mut keys: Vec<KeyEntry> = Vec::with_capacity(items.len());
        for item in items {
            // Inspect raw fields before coset normalizes empty optional values.
            let fields = int_map(item.clone()).ok_or(RingError::Malformed("invalid key map"))?;
            if fields.iter().any(|(label, _)| {
                ![
                    1,
                    2,
                    3,
                    4,
                    PARAM_CRV,
                    PARAM_X,
                    PARAM_D,
                    PARAM_ACTIVATED_AT,
                    PARAM_RETIRED_AT,
                    PARAM_SIGNED_UNTIL,
                ]
                .contains(label)
            }) {
                return Err(RingError::Malformed("unexpected key parameter"));
            }
            if fields
                .iter()
                .any(|(label, value)| *label == 4 && *value != Value::Array(vec![int(2)]))
            {
                return Err(RingError::Malformed("key operations are not [verify]"));
            }
            let key = CoseKey::from_cbor_value(item)
                .map_err(|_| RingError::Malformed("not a COSE_Key"))?;
            let entry = KeyEntry::from_cose_key(key)?;
            if keys.iter().any(|seen| seen.key_id == entry.key_id) {
                return Err(RingError::DuplicateKey);
            }
            keys.push(entry);
        }
        if keys.iter().filter(|entry| entry.is_active()).count() > 1 {
            return Err(RingError::MultipleActiveKeys);
        }
        Ok(KeyRing {
            issuer,
            keys,
            max_validity,
        })
    }
}

/// A verified message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    kind: Kind,
    key_id: KeyId,
    issued_at: u64,
    valid_until: u64,
    payload: Vec<u8>,
}

impl Verified {
    /// The kind (always the one verification asked for).
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// The key that signed the message.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// When the message was signed (Unix seconds).
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// When the message expires (Unix seconds, exclusive).
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }

    /// The signed payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Takes the signed payload.
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

/// Why a message was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyError {
    /// Not a tagged COSE_Sign1 with the csgn header layout.
    Malformed(&'static str),
    /// The algorithm is not Ed25519.
    UnsupportedAlgorithm,
    /// The key ID is not in the key ring.
    UnknownKey,
    /// The key is retired and everything it signed has expired.
    KeyExpired,
    /// The signature does not match the payload and protected header.
    BadSignature,
    /// The message names another issuer than the key ring.
    WrongIssuer,
    /// The message is of another kind than expected.
    WrongKind {
        /// The kind the caller asked for.
        expected: Kind,
        /// The kind in the message.
        found: Kind,
    },
    /// The message claims an issued time outside the key's active period, or an expiry after
    /// the latest the retired key recorded.
    OutsideKeyPeriod,
    /// The lifetime exceeds the maximum published in the authenticated ring.
    ValidityTooLong,
    /// The message was issued in the future.
    NotYetValid,
    /// The message has expired.
    Expired,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::Malformed(reason) => write!(f, "malformed message: {reason}"),
            VerifyError::UnsupportedAlgorithm => f.write_str("unsupported algorithm"),
            VerifyError::UnknownKey => f.write_str("unknown key ID"),
            VerifyError::KeyExpired => f.write_str("signing key has expired"),
            VerifyError::BadSignature => f.write_str("invalid signature"),
            VerifyError::WrongIssuer => f.write_str("wrong issuer"),
            VerifyError::WrongKind { expected, found } => {
                write!(f, "wrong kind: expected {expected}, found {found}")
            }
            VerifyError::OutsideKeyPeriod => f.write_str("outside the signing key's period"),
            VerifyError::ValidityTooLong => f.write_str("validity exceeds the ring's maximum"),
            VerifyError::NotYetValid => f.write_str("message is not yet valid"),
            VerifyError::Expired => f.write_str("message has expired"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Why a key ring was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RingError {
    /// Not a key ring in the csgn encoding.
    Malformed(&'static str),
    /// The encoding version is unknown.
    UnsupportedVersion,
    /// A key carries secret key material.
    SecretKeyMaterial,
    /// A public key is not a valid Ed25519 point or has small order.
    InvalidPublicKey,
    /// A key ID is not the thumbprint of its key.
    KeyIdMismatch,
    /// A key appears twice.
    DuplicateKey,
    /// More than one key is active.
    MultipleActiveKeys,
}

impl core::fmt::Display for RingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RingError::Malformed(reason) => write!(f, "malformed key ring: {reason}"),
            RingError::UnsupportedVersion => f.write_str("unsupported key ring version"),
            RingError::SecretKeyMaterial => f.write_str("key ring contains secret key material"),
            RingError::InvalidPublicKey => f.write_str("invalid public key"),
            RingError::KeyIdMismatch => f.write_str("key ID does not match its key"),
            RingError::DuplicateKey => f.write_str("duplicate key"),
            RingError::MultipleActiveKeys => f.write_str("more than one active key"),
        }
    }
}

impl std::error::Error for RingError {}
