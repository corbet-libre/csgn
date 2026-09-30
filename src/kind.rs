//! The kinds of payload csgn signs.

use core::fmt;

/// What a signed object is.
///
/// The kind is part of the protected header, so a signature over one kind can never be
/// accepted as another: verification takes the expected kind and refuses everything else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A community credential (community, member ID, handle, gates, pins, schema version,
    /// policy epoch, validity).
    Credential,
    /// A snapshot of the resolved settings of a community.
    SettingsSnapshot,
    /// A snapshot of a community's profile schema.
    SchemaSnapshot,
    /// A snapshot of the list of communities.
    CommunitiesSnapshot,
    /// A snapshot of the revocation list.
    RevocationListSnapshot,
}

impl Kind {
    /// Every kind, in a fixed order.
    pub const ALL: [Kind; 5] = [
        Kind::Credential,
        Kind::SettingsSnapshot,
        Kind::SchemaSnapshot,
        Kind::CommunitiesSnapshot,
        Kind::RevocationListSnapshot,
    ];

    /// The text value written into the protected header.
    pub const fn as_str(self) -> &'static str {
        match self {
            Kind::Credential => "credential",
            Kind::SettingsSnapshot => "snapshot/settings",
            Kind::SchemaSnapshot => "snapshot/schema",
            Kind::CommunitiesSnapshot => "snapshot/communities",
            Kind::RevocationListSnapshot => "snapshot/revocation-list",
        }
    }

    /// Parses the text value of the protected header; `None` for anything unknown.
    pub fn from_wire(value: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|kind| kind.as_str() == value)
    }

    /// Whether this kind is one of the snapshots.
    pub const fn is_snapshot(self) -> bool {
        !matches!(self, Kind::Credential)
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
