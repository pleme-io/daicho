//! Object ids.
//!
//! ── ★ THE HASH LENGTH IS DATA, NEVER A LITERAL 20 ──────────────────────
//! Git's SHA-256 transition is real in the format and absent from the forges
//! (GitHub does not serve sha256 repositories as of 2026-08). So sha1 is the
//! only variant we can construct today — and that is a *policy*, not an
//! *encoding*. The expensive half of a future migration is not swapping the
//! hash function; it is the literal `20` that leaks into pack-entry parsing,
//! `split_at` arithmetic and every index layout. Carrying the length as a
//! value from day one costs a parameter and buys the migration.

use core::fmt;

/// Which digest an object id uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Kind {
    /// 20-byte SHA-1. The only kind any forge we target serves today.
    #[default]
    Sha1,
    /// 32-byte SHA-256. Representable so that a server advertising
    /// `object-format=sha256` is a typed refusal rather than a silent
    /// mis-parse of every subsequent offset.
    Sha256,
}

impl Kind {
    /// Raw digest length in bytes.
    #[must_use]
    pub fn digest_len(self) -> usize {
        match self {
            Kind::Sha1 => 20,
            Kind::Sha256 => 32,
        }
    }

    /// Hex-encoded length in characters.
    #[must_use]
    pub fn hex_len(self) -> usize {
        self.digest_len() * 2
    }
}

/// A git object id.
///
/// Fixed 32-byte storage with an explicit length, rather than a `Vec`: an
/// object id is on the hot path of every graph walk, and a heap allocation
/// per node is the difference between a sub-millisecond ancestry answer and
/// a measurable one.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId {
    bytes: [u8; 32],
    kind: Kind,
}

impl ObjectId {
    /// Build from raw digest bytes.
    ///
    /// # Errors
    ///
    /// [`OidError::BadLength`] if the slice is not the kind's digest length.
    pub fn from_bytes(kind: Kind, raw: &[u8]) -> Result<Self, OidError> {
        if raw.len() != kind.digest_len() {
            return Err(OidError::BadLength {
                expected: kind.digest_len(),
                got: raw.len(),
            });
        }
        let mut bytes = [0u8; 32];
        bytes[..raw.len()].copy_from_slice(raw);
        Ok(Self { bytes, kind })
    }

    /// Parse a lowercase hex digest.
    ///
    /// Lowercase only. Git emits lowercase, and accepting mixed case would
    /// let one object occupy two entries in any map keyed on the id.
    ///
    /// # Errors
    ///
    /// [`OidError::BadLength`] on a wrong-length input, [`OidError::NotHex`]
    /// on any non-lowercase-hex byte.
    pub fn parse_hex(kind: Kind, hex: &[u8]) -> Result<Self, OidError> {
        if hex.len() != kind.hex_len() {
            return Err(OidError::BadLength {
                expected: kind.hex_len(),
                got: hex.len(),
            });
        }
        let mut bytes = [0u8; 32];
        for (i, pair) in hex.chunks_exact(2).enumerate() {
            let hi = hex_val(pair[0]).ok_or(OidError::NotHex)?;
            let lo = hex_val(pair[1]).ok_or(OidError::NotHex)?;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Self { bytes, kind })
    }

    /// The digest kind.
    #[must_use]
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// The raw digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.kind.digest_len()]
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({self})")
    }
}

/// Why an object id could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OidError {
    /// Wrong number of bytes or hex characters.
    #[error("object id: expected {expected} bytes, got {got}")]
    BadLength {
        /// The length the kind requires.
        expected: usize,
        /// The length supplied.
        got: usize,
    },
    /// A non-lowercase-hex character.
    #[error("object id: not lowercase hex")]
    NotHex,
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &[u8] = b"18e66859d87fb4b76599f73460b54f0848c76b16";

    #[test]
    fn hex_round_trips_through_bytes() {
        let oid = ObjectId::parse_hex(Kind::Sha1, HEX).unwrap();
        assert_eq!(oid.to_string().as_bytes(), HEX);
        assert_eq!(oid.as_bytes().len(), 20);
        let again = ObjectId::from_bytes(Kind::Sha1, oid.as_bytes()).unwrap();
        assert_eq!(oid, again);
    }

    #[test]
    fn uppercase_hex_is_refused_so_one_object_cannot_occupy_two_keys() {
        let upper = b"18E66859D87FB4B76599F73460B54F0848C76B16";
        assert_eq!(
            ObjectId::parse_hex(Kind::Sha1, upper),
            Err(OidError::NotHex)
        );
    }

    #[test]
    fn a_short_rev_is_not_an_object_id() {
        assert_eq!(
            ObjectId::parse_hex(Kind::Sha1, b"18e6685"),
            Err(OidError::BadLength {
                expected: 40,
                got: 7
            })
        );
    }

    #[test]
    fn sha256_lengths_are_carried_not_assumed() {
        assert_eq!(Kind::Sha256.digest_len(), 32);
        assert_eq!(Kind::Sha256.hex_len(), 64);
        let hex: Vec<u8> = std::iter::repeat_n(b'a', 64).collect();
        let oid = ObjectId::parse_hex(Kind::Sha256, &hex).unwrap();
        assert_eq!(oid.as_bytes().len(), 32, "the 20 must not leak in anywhere");
        // A sha1-length input must not be silently accepted as sha256.
        assert!(ObjectId::parse_hex(Kind::Sha256, HEX).is_err());
    }

    #[test]
    fn ids_of_different_kinds_are_not_confused() {
        let a = ObjectId::from_bytes(Kind::Sha1, &[0u8; 20]).unwrap();
        let b = ObjectId::from_bytes(Kind::Sha256, &[0u8; 32]).unwrap();
        assert_ne!(a, b, "same leading bytes, different kind, different id");
    }
}
