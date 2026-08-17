//! Packfile v2 — the only form in which git ever transfers objects.
//!
//! ── ★ A COMMIT-ONLY PACK IS NOT DELTA-FREE ─────────────────────────────
//! The tempting shortcut is "we only want commits, and commits are small, so
//! skip the delta engine." Measured on `pleme-io/nix`'s real packs:
//!
//! ```text
//! 6869 blob   DELTA / 2751 blob   FULL
//! 8870 tree   DELTA / 1992 tree   FULL
//!   86 commit DELTA / 4917 commit FULL
//! ```
//!
//! 86 of 5,003 commit entries are deltified — 1.7%, and 1.7% of the answer is
//! the whole answer when the question is "is this rev an ancestor". So delta
//! resolution is in the irreducible core, not an optimization.
//!
//! Reference: `Documentation/gitformat-pack.txt` in git.git.

use std::collections::HashMap;

use crate::oid::{Kind, ObjectId};

/// `PACK`, big-endian version, big-endian object count.
const HEADER_LEN: usize = 12;

/// Refuse to allocate more than this for one object.
///
/// The decompressed size is a varint read from bytes a remote sent us, so it
/// is attacker-controlled: a 12-byte entry header can claim a 2^60-byte
/// object. gix carries the same ceiling for the same reason.
const MAX_OBJECT_SIZE: usize = 512 * 1024 * 1024;

/// The object kinds a pack entry can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A whole commit.
    Commit,
    /// A whole tree.
    Tree,
    /// A whole blob.
    Blob,
    /// A whole annotated tag.
    Tag,
    /// A delta against an entry earlier in this pack, by relative offset.
    OfsDelta {
        /// How far back the base entry's header starts.
        back: u64,
    },
    /// A delta against an object named by id, which may not be in this pack.
    RefDelta {
        /// The base object's id.
        base: ObjectId,
    },
}

/// Why a pack could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PackError {
    /// Not a packfile.
    #[error("pack: bad magic; expected `PACK`")]
    BadMagic,
    /// Version other than 2 or 3.
    #[error("pack: unsupported version {version}")]
    BadVersion {
        /// The version the header declared.
        version: u32,
    },
    /// The stream ended mid-structure.
    #[error("pack: truncated at offset {at}")]
    Truncated {
        /// Where the read ran out.
        at: usize,
    },
    /// Type 0 or type 5.
    #[error("pack: entry type {type_id} is invalid at offset {at}")]
    BadType {
        /// The 3-bit type field.
        type_id: u8,
        /// Where the entry starts.
        at: usize,
    },
    /// A varint encoded with more bytes than its value needs.
    ///
    /// Rejected rather than tolerated: delta resolution reconstructs a base's
    /// offset as `entry_start - back`, so an overlong encoding lets a
    /// malformed pack point an entry at itself and hang the resolver.
    #[error("pack: non-canonical varint at offset {at}")]
    NonCanonicalVarint {
        /// Where the varint starts.
        at: usize,
    },
    /// A size field beyond [`MAX_OBJECT_SIZE`].
    #[error("pack: object at {at} declares {size} bytes, over the {MAX_OBJECT_SIZE} ceiling")]
    TooLarge {
        /// Where the entry starts.
        at: usize,
        /// The declared size.
        size: u64,
    },
    /// zlib failed.
    #[error("pack: decompression failed at offset {at}: {message}")]
    Inflate {
        /// Where the entry starts.
        at: usize,
        /// The decompressor's complaint.
        message: String,
    },
    /// A delta named a base that is not in this pack and not supplied.
    #[error("pack: delta at {at} needs base {base}, which is not in this pack")]
    MissingBase {
        /// Where the delta entry starts.
        at: usize,
        /// The base it wanted.
        base: String,
    },
    /// A delta instruction stream is malformed.
    #[error("pack: bad delta at offset {at}: {reason}")]
    BadDelta {
        /// Where the delta entry starts.
        at: usize,
        /// What was wrong.
        reason: &'static str,
    },
}

/// One entry's header, before decompression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryHeader {
    /// What the entry carries.
    pub kind: EntryKind,
    /// For a full object, the object's size. **For a delta, the size of the
    /// DELTA INSTRUCTION STREAM** — not of the reconstructed object.
    ///
    /// The two meanings share one field in the format, which is a genuine
    /// trap; the doc comment is the only thing separating them.
    pub packed_size: u64,
    /// Bytes this header occupied.
    pub header_len: usize,
}

/// Read the pack header, returning the declared object count.
///
/// # Errors
///
/// [`PackError::BadMagic`], [`PackError::BadVersion`], [`PackError::Truncated`].
pub fn read_header(data: &[u8]) -> Result<u32, PackError> {
    if data.len() < HEADER_LEN {
        return Err(PackError::Truncated { at: 0 });
    }
    if &data[..4] != b"PACK" {
        return Err(PackError::BadMagic);
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 && version != 3 {
        return Err(PackError::BadVersion { version });
    }
    Ok(u32::from_be_bytes([data[8], data[9], data[10], data[11]]))
}

/// Parse one entry header starting at `at`.
///
/// # Errors
///
/// See [`PackError`].
pub fn read_entry_header(
    data: &[u8],
    at: usize,
    kind: Kind,
) -> Result<EntryHeader, PackError> {
    let mut i = at;
    let c = *data.get(i).ok_or(PackError::Truncated { at })?;
    i += 1;

    let type_id = (c >> 4) & 0b111;
    let mut size = u64::from(c & 0b1111);
    let mut shift = 4u32;
    let mut cur = c;
    while cur & 0x80 != 0 {
        cur = *data.get(i).ok_or(PackError::Truncated { at })?;
        i += 1;
        size |= u64::from(cur & 0x7f)
            .checked_shl(shift)
            .ok_or(PackError::NonCanonicalVarint { at })?;
        shift += 7;
    }
    if size > MAX_OBJECT_SIZE as u64 {
        return Err(PackError::TooLarge { at, size });
    }

    let kind_parsed = match type_id {
        1 => EntryKind::Commit,
        2 => EntryKind::Tree,
        3 => EntryKind::Blob,
        4 => EntryKind::Tag,
        6 => {
            // ── ★ THIS VARINT IS NOT LEB128 ───────────────────────────────
            // Each continuation adds a bias: `value = ((value + 1) << 7) | next`.
            // Getting it wrong yields plausible offsets that point at the
            // wrong object, so it fails silently rather than loudly.
            let mut c = *data.get(i).ok_or(PackError::Truncated { at })?;
            i += 1;
            let mut back = u64::from(c & 0x7f);
            while c & 0x80 != 0 {
                c = *data.get(i).ok_or(PackError::Truncated { at })?;
                i += 1;
                back = back
                    .checked_add(1)
                    .and_then(|v| v.checked_shl(7))
                    .and_then(|v| v.checked_add(u64::from(c & 0x7f)))
                    .ok_or(PackError::NonCanonicalVarint { at })?;
            }
            EntryKind::OfsDelta { back }
        }
        7 => {
            let n = kind.digest_len();
            let raw = data
                .get(i..i + n)
                .ok_or(PackError::Truncated { at })?;
            i += n;
            let base = ObjectId::from_bytes(kind, raw)
                .map_err(|_| PackError::Truncated { at })?;
            EntryKind::RefDelta { base }
        }
        other => return Err(PackError::BadType { type_id: other, at }),
    };

    Ok(EntryHeader {
        kind: kind_parsed,
        packed_size: size,
        header_len: i - at,
    })
}

/// Inflate one zlib stream starting at `at`, returning the bytes and how many
/// COMPRESSED bytes were consumed.
///
/// The consumed count is the load-bearing return value: pack entries are
/// concatenated zlib streams with no length prefix, so the only way to find
/// the next entry is to ask the decompressor how far it read. Any convenience
/// API that returns just a `Vec` cannot drive a pack reader.
///
/// # Errors
///
/// [`PackError::Inflate`] on a malformed stream.
pub fn inflate_at(
    data: &[u8],
    at: usize,
    expected: usize,
) -> Result<(Vec<u8>, usize), PackError> {
    use zlib_rs::{Inflate, InflateFlush};

    if expected > MAX_OBJECT_SIZE {
        return Err(PackError::TooLarge {
            at,
            size: expected as u64,
        });
    }
    let input = data.get(at..).ok_or(PackError::Truncated { at })?;
    let mut out = vec![0u8; expected];
    let mut inflate = Inflate::new(true, 15);
    inflate
        .decompress(input, &mut out, InflateFlush::Finish)
        .map_err(|e| PackError::Inflate {
            at,
            message: e.as_str().to_owned(),
        })?;
    let consumed = usize::try_from(inflate.total_in()).unwrap_or(usize::MAX);
    let produced = usize::try_from(inflate.total_out()).unwrap_or(usize::MAX);
    if produced != expected {
        return Err(PackError::Inflate {
            at,
            message: "stream produced fewer bytes than the header promised".to_owned(),
        });
    }
    Ok((out, consumed))
}

/// Apply a git delta to `base`.
///
/// # Errors
///
/// [`PackError::BadDelta`] on any malformed instruction, a copy that runs off
/// the base, or a result that does not exactly fill its declared size.
pub fn apply_delta(base: &[u8], delta: &[u8], at: usize) -> Result<Vec<u8>, PackError> {
    let bad = |reason: &'static str| PackError::BadDelta { at, reason };

    let (base_size, mut i) = read_leb128(delta, 0).ok_or_else(|| bad("truncated base size"))?;
    // The delta states the size of the base it was built against. A mismatch
    // means we resolved the WRONG base, and applying anyway would produce
    // plausible garbage rather than an error.
    if !usize::try_from(base_size).is_ok_and(|n| n == base.len()) {
        return Err(bad("delta base size does not match the resolved base"));
    }
    let (result_size, j) = read_leb128(delta, i).ok_or_else(|| bad("truncated result size"))?;
    i = j;
    if result_size > MAX_OBJECT_SIZE as u64 {
        return Err(PackError::TooLarge {
            at,
            size: result_size,
        });
    }

    let cap = usize::try_from(result_size).map_err(|_| bad("result size overflow"))?;
    let mut out = Vec::with_capacity(cap);
    while i < delta.len() {
        let op = delta[i];
        i += 1;
        if op == 0 {
            // Reserved by the format, and a real corruption signal.
            return Err(bad("delta opcode 0 is reserved"));
        }
        if op & 0x80 != 0 {
            // COPY: present offset/size bytes assemble little-endian.
            let mut off = 0u64;
            for b in 0..4 {
                if op & (1 << b) != 0 {
                    let v = *delta.get(i).ok_or_else(|| bad("truncated copy offset"))?;
                    i += 1;
                    off |= u64::from(v) << (8 * b);
                }
            }
            let mut size = 0u64;
            for b in 0..3 {
                if op & (0x10 << b) != 0 {
                    let v = *delta.get(i).ok_or_else(|| bad("truncated copy size"))?;
                    i += 1;
                    size |= u64::from(v) << (8 * b);
                }
            }
            // ── ★ A ZERO COPY SIZE MEANS 0x10000 ─────────────────────────
            // Missing this yields zero-length copies and a silently truncated
            // object rather than an error.
            if size == 0 {
                size = 0x10000;
            }
            let start = usize::try_from(off).map_err(|_| bad("copy offset overflow"))?;
            let len = usize::try_from(size).map_err(|_| bad("copy size overflow"))?;
            let end = start
                .checked_add(len)
                .ok_or_else(|| bad("copy range overflow"))?;
            let chunk = base
                .get(start..end)
                .ok_or_else(|| bad("copy range exceeds the base object"))?;
            out.extend_from_slice(chunk);
        } else {
            // INSERT: the low 7 bits are a literal byte count, 1..=127.
            let n = (op & 0x7f) as usize;
            let chunk = delta
                .get(i..i + n)
                .ok_or_else(|| bad("truncated insert payload"))?;
            i += n;
            out.extend_from_slice(chunk);
        }
    }

    if out.len() as u64 != result_size {
        return Err(bad("delta produced a different size than it promised"));
    }
    Ok(out)
}

/// Plain LEB128 — no bias, unlike the `OFS_DELTA` offset.
fn read_leb128(d: &[u8], mut i: usize) -> Option<(u64, usize)> {
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        let c = *d.get(i)?;
        i += 1;
        v |= u64::from(c & 0x7f).checked_shl(shift)?;
        if c & 0x80 == 0 {
            return Some((v, i));
        }
        shift += 7;
    }
}

/// Every full object in a pack, keyed by its offset, with deltas resolved.
///
/// Materializes everything: under `--filter=tree:0` the whole object set for
/// `pleme-io/nix` is ~2.9 MB, so a delta tree would be over-engineering. The
/// shape stays behind this function so a wider filter can add one later.
///
/// # Errors
///
/// See [`PackError`].
pub fn resolve_all(
    data: &[u8],
    kind: Kind,
) -> Result<HashMap<usize, (EntryKind, Vec<u8>)>, PackError> {
    let count = read_header(data)?;
    let mut out: HashMap<usize, (EntryKind, Vec<u8>)> = HashMap::new();
    let mut at = HEADER_LEN;

    for _ in 0..count {
        let h = read_entry_header(data, at, kind)?;
        let body_at = at + h.header_len;
        let packed = usize::try_from(h.packed_size).map_err(|_| PackError::TooLarge {
            at,
            size: h.packed_size,
        })?;
        let (raw, consumed) = inflate_at(data, body_at, packed)?;

        let resolved = match h.kind {
            EntryKind::OfsDelta { back } => {
                let base_at = (at as u64)
                    .checked_sub(back)
                    .and_then(|v| usize::try_from(v).ok())
                    .ok_or(PackError::BadDelta {
                        at,
                        reason: "base offset points before the pack",
                    })?;
                let (base_kind, base_bytes) =
                    out.get(&base_at).ok_or_else(|| PackError::MissingBase {
                        at,
                        base: base_at.to_string(),
                    })?;
                // An OFS base is always earlier in the pack, which is why a
                // single forward pass resolves these without a second phase.
                (*base_kind, apply_delta(base_bytes, &raw, at)?)
            }
            EntryKind::RefDelta { base } => {
                // REF_DELTA has NO ordering guarantee and, in a thin pack, the
                // base may not be in this pack at all. A clone-shaped fetch
                // (no `have` lines) never produces one, which is why the
                // reconciler always fetches clone-shaped.
                let found = out.values().find_map(|(k, b)| {
                    let hdr = header_for(*k, b.len());
                    let mut h = <sha1::Sha1 as sha1::Digest>::new();
                    sha1::Digest::update(&mut h, &hdr);
                    sha1::Digest::update(&mut h, b);
                    let d = sha1::Digest::finalize(h);
                    (ObjectId::from_bytes(kind, &d).ok()? == base).then(|| (*k, b.clone()))
                });
                let (base_kind, base_bytes) = found.ok_or_else(|| PackError::MissingBase {
                    at,
                    base: base.to_string(),
                })?;
                (base_kind, apply_delta(&base_bytes, &raw, at)?)
            }
            k => (k, raw),
        };

        out.insert(at, resolved);
        at = body_at + consumed;
    }
    Ok(out)
}

/// The `<type> <size>\0` prefix that git hashes ahead of an object's content.
///
/// Never stored in a pack — the type and size live in the entry header
/// instead — so it must be reconstructed to verify an id.
#[must_use]
pub fn header_for(kind: EntryKind, len: usize) -> Vec<u8> {
    let ty: &[u8] = match kind {
        EntryKind::Commit => b"commit",
        EntryKind::Tree => b"tree",
        EntryKind::Tag => b"tag",
        // A resolved delta always carries its BASE's kind, so the delta arms
        // are unreachable here; `blob` is the harmless fallback and shares the
        // arm with the real blob case.
        EntryKind::Blob | EntryKind::OfsDelta { .. } | EntryKind::RefDelta { .. } => b"blob",
    };
    let mut v = Vec::with_capacity(ty.len() + 12);
    v.extend_from_slice(ty);
    v.push(b' ');
    v.extend_from_slice(len.to_string().as_bytes());
    v.push(0);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack_header(count: u32) -> Vec<u8> {
        let mut v = b"PACK".to_vec();
        v.extend_from_slice(&2u32.to_be_bytes());
        v.extend_from_slice(&count.to_be_bytes());
        v
    }

    #[test]
    fn header_accepts_v2_and_v3_and_refuses_the_rest() {
        assert_eq!(read_header(&pack_header(7)).unwrap(), 7);
        let mut v3 = pack_header(1);
        v3[4..8].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(read_header(&v3).unwrap(), 1, "v3 parses identically");
        let mut v9 = pack_header(1);
        v9[4..8].copy_from_slice(&9u32.to_be_bytes());
        assert_eq!(read_header(&v9), Err(PackError::BadVersion { version: 9 }));
        assert_eq!(
            read_header(b"NOPE\x00\x00\x00\x02\x00\x00\x00\x01"),
            Err(PackError::BadMagic)
        );
        assert_eq!(read_header(b"PACK"), Err(PackError::Truncated { at: 0 }));
    }

    #[test]
    fn entry_header_reads_type_and_size_across_the_shift_boundary() {
        // 4 size bits in byte 0, then 7 per continuation starting at shift 4.
        // type=1 (commit), size = 0b1_0000 = 16 → byte0 low nibble 0, cont 1.
        let d = [0b1001_0000, 0b0000_0001];
        let h = read_entry_header(&d, 0, Kind::Sha1).unwrap();
        assert_eq!(h.kind, EntryKind::Commit);
        assert_eq!(h.packed_size, 16);
        assert_eq!(h.header_len, 2);
    }

    #[test]
    fn reserved_and_invalid_types_are_refused() {
        // type 0
        assert_eq!(
            read_entry_header(&[0b0000_0001], 0, Kind::Sha1),
            Err(PackError::BadType { type_id: 0, at: 0 })
        );
        // type 5 is reserved
        assert_eq!(
            read_entry_header(&[0b0101_0001], 0, Kind::Sha1),
            Err(PackError::BadType { type_id: 5, at: 0 })
        );
    }

    // ── ★ THE BIASED VARINT ──────────────────────────────────────────────
    #[test]
    fn ofs_delta_offset_uses_the_bias_not_plain_leb128() {
        // Two-byte offset: first 0x80|0x01, then 0x02.
        // biased: ((1 + 1) << 7) + 2 = 258.  plain LEB128 would give 0x101=257.
        // type 6 (OFS_DELTA), size 0, no size continuation -> 0b0110_0000.
        let d = [0b0110_0000, 0x81, 0x02];
        let h = read_entry_header(&d, 0, Kind::Sha1).unwrap();
        assert_eq!(
            h.kind,
            EntryKind::OfsDelta { back: 258 },
            "the +1 bias before each shift is the whole difference from LEB128, \
             and getting it wrong points at a plausible WRONG object"
        );
    }

    #[test]
    fn ref_delta_carries_a_full_object_id() {
        // type 7 (REF_DELTA), size 1, no size continuation -> 0b0111_0001.
        let mut d = vec![0b0111_0001];
        d.extend_from_slice(&[0xabu8; 20]);
        let h = read_entry_header(&d, 0, Kind::Sha1).unwrap();
        match h.kind {
            EntryKind::RefDelta { base } => {
                assert_eq!(base.as_bytes(), &[0xabu8; 20]);
            }
            other => panic!("expected RefDelta, got {other:?}"),
        }
        assert_eq!(h.header_len, 21);
    }

    #[test]
    fn a_size_over_the_ceiling_is_refused_before_allocating() {
        // Attacker-controlled varint claiming an enormous object.
        let d = [0b1001_1111, 0xff, 0xff, 0xff, 0xff, 0x7f];
        assert!(matches!(
            read_entry_header(&d, 0, Kind::Sha1),
            Err(PackError::TooLarge { .. })
        ));
    }

    // ── delta application ────────────────────────────────────────────────

    fn leb(mut v: u64) -> Vec<u8> {
        let mut o = Vec::new();
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                o.push(b);
                return o;
            }
            o.push(b | 0x80);
        }
    }

    #[test]
    fn insert_and_copy_reconstruct_the_object() {
        let base = b"hello wonderful world".to_vec();
        let mut d = leb(base.len() as u64);
        d.extend(leb(11));
        // insert "HELLO " (6)
        d.push(6);
        d.extend_from_slice(b"HELLO ");
        // copy 5 bytes from offset 16 ("world")
        d.push(0x80 | 0x01 | 0x10);
        d.push(16);
        d.push(5);
        let out = apply_delta(&base, &d, 0).unwrap();
        assert_eq!(out, b"HELLO world");
    }

    #[test]
    fn a_zero_copy_size_means_65536() {
        let base = vec![7u8; 0x10000];
        let mut d = leb(base.len() as u64);
        d.extend(leb(0x10000));
        // copy with offset byte 0 present, NO size bytes → size 0 → 0x10000
        d.push(0x80 | 0x01);
        d.push(0);
        let out = apply_delta(&base, &d, 0).unwrap();
        assert_eq!(
            out.len(),
            0x10000,
            "size 0 means 65536; reading it as 0 silently truncates the object"
        );
    }

    #[test]
    fn opcode_zero_is_reserved_and_refused() {
        let base = b"x".to_vec();
        let mut d = leb(1);
        d.extend(leb(0));
        d.push(0);
        assert!(matches!(
            apply_delta(&base, &d, 0),
            Err(PackError::BadDelta { .. })
        ));
    }

    #[test]
    fn a_copy_past_the_end_of_the_base_is_refused() {
        let base = b"short".to_vec();
        let mut d = leb(base.len() as u64);
        d.extend(leb(100));
        d.push(0x80 | 0x01 | 0x10);
        d.push(0);
        d.push(100); // 100 bytes from a 5-byte base
        assert!(matches!(
            apply_delta(&base, &d, 0),
            Err(PackError::BadDelta {
                reason: "copy range exceeds the base object",
                ..
            })
        ));
    }

    #[test]
    fn a_wrong_base_size_is_caught_before_any_instruction_runs() {
        // The delta states the size it was built against; a mismatch means we
        // resolved the wrong base, and applying anyway would produce
        // plausible garbage.
        let base = b"12345".to_vec();
        let mut d = leb(99);
        d.extend(leb(1));
        d.push(1);
        d.push(b'x');
        assert!(matches!(
            apply_delta(&base, &d, 0),
            Err(PackError::BadDelta {
                reason: "delta base size does not match the resolved base",
                ..
            })
        ));
    }

    #[test]
    fn a_short_result_is_refused_rather_than_returned() {
        let base = b"abc".to_vec();
        let mut d = leb(3);
        d.extend(leb(50)); // promise 50
        d.push(1);
        d.push(b'z'); // deliver 1
        assert!(matches!(
            apply_delta(&base, &d, 0),
            Err(PackError::BadDelta {
                reason: "delta produced a different size than it promised",
                ..
            })
        ));
    }

    #[test]
    fn object_header_matches_gits_hash_preimage() {
        assert_eq!(header_for(EntryKind::Commit, 216), b"commit 216\0");
        assert_eq!(header_for(EntryKind::Blob, 0), b"blob 0\0");
        assert_eq!(header_for(EntryKind::Tree, 42), b"tree 42\0");
    }
}
