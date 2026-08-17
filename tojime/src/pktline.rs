//! pkt-line — git's wire framing.
//!
//! Reference: `Documentation/gitprotocol-common.adoc` in git.git.
//!
//! ```text
//! pkt-line     =  data-pkt / flush-pkt / delim-pkt / response-end-pkt
//! data-pkt     =  pkt-len pkt-payload
//! pkt-len      =  4*(HEXDIG)          ; ASCII hex, and it INCLUDES ITSELF
//! flush-pkt    =  "0000"
//! delim-pkt    =  "0001"
//! resp-end-pkt =  "0002"
//! ```

/// The largest payload a single data-pkt may carry.
///
/// Spec: *"The maximum length of a pkt-line's data component is 65516 bytes."*
pub const MAX_DATA_LEN: usize = 65516;

/// The largest total on-the-wire length of a pkt-line, header included.
///
/// Spec: *"Implementations MUST NOT send pkt-line whose length exceeds 65520."*
pub const MAX_LINE_LEN: usize = 65520;

/// The four bytes that prefix a remote-side error payload.
const ERR_PREFIX: &[u8] = b"ERR ";

/// Lowercase hex digits for the 4-byte length header.
///
/// Module scope rather than per-function: it was written twice, and the fleet
/// rule is to solve a thing once, in one place. Emitters must produce
/// lowercase; [`parse_hex4`] accepts either case on read.
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Write `n` as the 4-digit lowercase hex length header.
///
/// Hand-rolled rather than `format!("{n:04x}")`: the fleet bans `format!()`
/// outside a `Display` impl (★★ TYPED EMISSION), and this runs on every line
/// of every request.
fn push_len(n: usize, out: &mut Vec<u8>) {
    out.push(HEX[(n >> 12) & 0xf]);
    out.push(HEX[(n >> 8) & 0xf]);
    out.push(HEX[(n >> 4) & 0xf]);
    out.push(HEX[n & 0xf]);
}

/// One framed unit on the wire.
///
/// ── ★ FOUR VARIANTS, AND THE FOURTH IS NOT AN `Option` ─────────────────
/// The spec is explicit that flush and empty are different things:
///
/// > *"A pkt-line with a length field of 0 ('0000'), called a flush-pkt, is a
/// > special case and MUST be handled differently than an empty pkt-line
/// > ('0004')."*
///
/// Modelling this as `Option<&[u8]>` collapses `0000` and `0004` onto the same
/// value, and modelling it as `&[u8]` collapses all three control packets onto
/// the empty slice. Protocol-v2 responses are *section-delimited by* `0001` and
/// *terminated by* `0000`, so a decoder that cannot tell them apart cannot
/// parse a `fetch` response at all. The distinction is load-bearing, so it is
/// a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packet<'a> {
    /// `0000` — ends a section or the whole response.
    Flush,
    /// `0001` — separates a v2 command's capabilities from its arguments, and
    /// separates response sections from one another.
    Delimiter,
    /// `0002` — ends a response inside a multiplexed stateful stream.
    ResponseEnd,
    /// A payload. May legitimately be empty (`0004`) on read.
    Data(&'a [u8]),
}

impl<'a> Packet<'a> {
    /// The payload, if this is a data packet.
    #[must_use]
    pub fn data(&self) -> Option<&'a [u8]> {
        match self {
            Packet::Data(d) => Some(d),
            _ => None,
        }
    }

    /// The payload as text with at most one trailing `LF` removed.
    ///
    /// Every *textual* line in the protocol conventionally ends `LF`, and
    /// receivers are expected to tolerate its absence. Exactly one byte is
    /// stripped — never a run — because a payload of `"\n\n"` is a line whose
    /// text is `"\n"`.
    #[must_use]
    pub fn text(&self) -> Option<&'a [u8]> {
        self.data().map(|d| match d.split_last() {
            Some((b'\n', rest)) => rest,
            _ => d,
        })
    }

    /// The remote's error message, if this packet is an `ERR ` line.
    ///
    /// A server reports a protocol-level failure in-band rather than by
    /// closing the connection, so a decoder that ignores this reports EOF for
    /// what was actually a stated reason.
    #[must_use]
    pub fn err(&self) -> Option<&'a [u8]> {
        self.data()
            .and_then(|d| d.strip_prefix(ERR_PREFIX))
            .map(|m| match m.split_last() {
                Some((b'\n', rest)) => rest,
                _ => m,
            })
    }
}

/// Why a byte stream is not a valid pkt-line stream.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// Fewer than 4 bytes remain, so the length header is truncated.
    #[error("truncated pkt-line header: {available} byte(s) available, 4 required")]
    TruncatedHeader {
        /// How many bytes were actually available.
        available: usize,
    },
    /// The 4 header bytes are not ASCII hex.
    #[error("pkt-line length is not 4 hex digits")]
    NotHex,
    /// `0003` — reserved and carries no meaning.
    #[error("pkt-line length 0003 is reserved and invalid")]
    ReservedLength,
    /// The declared length exceeds the protocol maximum.
    #[error("pkt-line declares {declared} bytes, exceeding the {MAX_LINE_LEN}-byte maximum")]
    TooLong {
        /// The length the header declared.
        declared: usize,
    },
    /// The declared length runs past the end of the available bytes.
    #[error("pkt-line declares {declared} bytes but only {available} are available")]
    TruncatedPayload {
        /// The length the header declared.
        declared: usize,
        /// How many bytes were actually available, header included.
        available: usize,
    },
}

/// Decode one packet from the front of `input`.
///
/// On success returns the packet and the number of bytes it consumed, so a
/// caller can advance without re-deriving the length.
///
/// # Errors
///
/// See [`DecodeError`]. Every arm names what was expected and what was found —
/// a bare "parse error" on a binary protocol is not actionable.
pub fn decode(input: &[u8]) -> Result<(Packet<'_>, usize), DecodeError> {
    if input.len() < 4 {
        return Err(DecodeError::TruncatedHeader {
            available: input.len(),
        });
    }

    // ── The control packets are matched LITERALLY, before hex-decoding ────
    // Not an optimisation: it keeps the three magic values from ever being
    // reachable through the data path, so a future edit to the length maths
    // cannot turn a flush into a zero-length payload.
    match &input[..4] {
        b"0000" => return Ok((Packet::Flush, 4)),
        b"0001" => return Ok((Packet::Delimiter, 4)),
        b"0002" => return Ok((Packet::ResponseEnd, 4)),
        b"0003" => return Err(DecodeError::ReservedLength),
        _ => {}
    }

    let declared = parse_hex4(&input[..4]).ok_or(DecodeError::NotHex)?;

    if declared > MAX_LINE_LEN {
        return Err(DecodeError::TooLong { declared });
    }
    // `0004` is a legal empty payload. The spec says senders SHOULD NOT emit
    // one; it says nothing about receivers, and a receiver that rejects it
    // fails against a peer that is merely impolite rather than wrong.
    if declared < 4 {
        return Err(DecodeError::NotHex);
    }
    if input.len() < declared {
        return Err(DecodeError::TruncatedPayload {
            declared,
            available: input.len(),
        });
    }

    Ok((Packet::Data(&input[4..declared]), declared))
}

/// Parse exactly 4 ASCII hex digits, upper or lower case.
///
/// Emitters must produce lowercase (see [`encode_into`]); readers accept both,
/// because the protocol never promised us case and a peer is not wrong to
/// send `00A5`.
fn parse_hex4(b: &[u8]) -> Option<usize> {
    let mut n = 0usize;
    for &c in b {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        n = n * 16 + d as usize;
    }
    Some(n)
}

/// Why a payload cannot be framed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EncodeError {
    /// The payload exceeds [`MAX_DATA_LEN`].
    #[error("payload of {len} bytes exceeds the {MAX_DATA_LEN}-byte pkt-line maximum")]
    TooLong {
        /// The payload length that was rejected.
        len: usize,
    },
    /// An empty payload was offered.
    ///
    /// This is refused rather than encoded as `0004`, because the spec says
    /// senders SHOULD NOT emit one and because the caller almost always meant
    /// [`encode_flush_into`].
    #[error("refusing to emit an empty pkt-line (0004); use a flush-pkt if that was the intent")]
    EmptyPayload,
}

/// Frame `payload` as a data-pkt, appending to `out`.
///
/// # Errors
///
/// [`EncodeError::TooLong`] past [`MAX_DATA_LEN`], [`EncodeError::EmptyPayload`]
/// for an empty payload.
pub fn encode_into(payload: &[u8], out: &mut Vec<u8>) -> Result<(), EncodeError> {
    if payload.is_empty() {
        return Err(EncodeError::EmptyPayload);
    }
    if payload.len() > MAX_DATA_LEN {
        return Err(EncodeError::TooLong { len: payload.len() });
    }
    push_len(payload.len() + 4, out);
    out.extend_from_slice(payload);
    Ok(())
}

/// Frame `line` as a data-pkt with a trailing `LF`, appending to `out`.
///
/// Every textual command and argument we emit is `LF`-terminated, so this is
/// the form nearly every call site wants.
///
/// # Errors
///
/// As [`encode_into`]; the `LF` counts toward the length bound.
pub fn encode_line_into(line: &[u8], out: &mut Vec<u8>) -> Result<(), EncodeError> {
    if line.len() + 1 > MAX_DATA_LEN {
        return Err(EncodeError::TooLong { len: line.len() + 1 });
    }
    push_len(line.len() + 1 + 4, out);
    out.extend_from_slice(line);
    out.push(b'\n');
    Ok(())
}

/// Append a flush-pkt (`0000`).
pub fn encode_flush_into(out: &mut Vec<u8>) {
    out.extend_from_slice(b"0000");
}

/// Append a delim-pkt (`0001`).
pub fn encode_delim_into(out: &mut Vec<u8>) {
    out.extend_from_slice(b"0001");
}

/// A borrowing iterator over a complete pkt-line stream.
///
/// Yields `Err` once and then stops; a malformed stream has no safe
/// resynchronisation point, because the framing IS the length.
pub struct Packets<'a> {
    rest: &'a [u8],
    done: bool,
}

impl<'a> Packets<'a> {
    /// Iterate the packets in `input`.
    #[must_use]
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            rest: input,
            done: false,
        }
    }

    /// The bytes not yet consumed.
    #[must_use]
    pub fn remainder(&self) -> &'a [u8] {
        self.rest
    }
}

impl<'a> Iterator for Packets<'a> {
    type Item = Result<Packet<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.rest.is_empty() {
            return None;
        }
        match decode(self.rest) {
            Ok((pkt, used)) => {
                self.rest = &self.rest[used..];
                Some(Ok(pkt))
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// The sideband channel a packet arrived on, inside a `packfile` section.
///
/// Spec: `packfile = PKT-LINE("packfile" LF) *PKT-LINE(%x01-03 *%x00-ff)` —
/// the first payload byte is the band id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Band {
    /// Band 1 — pack data.
    Pack,
    /// Band 2 — human-readable progress. Never pack bytes.
    Progress,
    /// Band 3 — a fatal error message. The transfer is over.
    Error,
}

/// Split a sideband-framed payload into its band and its content.
///
/// Returns `None` for an empty payload or an unknown band id. Routing band 2
/// into the pack sink corrupts the pack silently, so the caller is made to
/// match rather than being handed a default.
#[must_use]
pub fn split_band(payload: &[u8]) -> Option<(Band, &[u8])> {
    match payload.split_first() {
        Some((1, rest)) => Some((Band::Pack, rest)),
        Some((2, rest)) => Some((Band::Progress, rest)),
        Some((3, rest)) => Some((Band::Error, rest)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── The canonical examples from gitprotocol-common.adoc ───────────────
    #[test]
    fn spec_examples_decode_exactly() {
        for (raw, want) in [
            (&b"0006a\n"[..], &b"a\n"[..]),
            (&b"0005a"[..], &b"a"[..]),
            (&b"000bfoobar\n"[..], &b"foobar\n"[..]),
            (&b"0004"[..], &b""[..]),
        ] {
            let (pkt, used) = decode(raw).expect("spec example must decode");
            assert_eq!(pkt, Packet::Data(want), "payload for {raw:?}");
            assert_eq!(used, raw.len(), "must consume the whole line for {raw:?}");
        }
    }

    // ── ★ THE DISTINCTION THE TYPE EXISTS TO PRESERVE ────────────────────
    // If this test can be made to pass with `Option<&[u8]>`, the type is wrong.
    #[test]
    fn flush_and_empty_and_delim_are_three_different_values() {
        let flush = decode(b"0000").unwrap().0;
        let empty = decode(b"0004").unwrap().0;
        let delim = decode(b"0001").unwrap().0;
        let end = decode(b"0002").unwrap().0;

        assert_eq!(flush, Packet::Flush);
        assert_eq!(empty, Packet::Data(b""));
        assert_eq!(delim, Packet::Delimiter);
        assert_eq!(end, Packet::ResponseEnd);

        assert_ne!(flush, empty, "0000 and 0004 MUST NOT compare equal");
        assert_ne!(flush, delim, "0000 and 0001 MUST NOT compare equal");
        assert_ne!(delim, end, "0001 and 0002 MUST NOT compare equal");

        // And the control packets carry no payload at all.
        assert_eq!(flush.data(), None);
        assert_eq!(delim.data(), None);
        assert_eq!(end.data(), None);
        assert_eq!(empty.data(), Some(&b""[..]));
    }

    #[test]
    fn reserved_0003_is_rejected() {
        assert_eq!(decode(b"0003"), Err(DecodeError::ReservedLength));
    }

    #[test]
    fn length_includes_its_own_four_bytes() {
        // "0006" declares SIX total, so the payload is TWO.
        let (pkt, used) = decode(b"0006ab").unwrap();
        assert_eq!(pkt, Packet::Data(b"ab"));
        assert_eq!(used, 6);
    }

    #[test]
    fn truncated_header_and_payload_are_distinguished() {
        assert_eq!(
            decode(b"00"),
            Err(DecodeError::TruncatedHeader { available: 2 })
        );
        assert_eq!(
            decode(b"0010abc"),
            Err(DecodeError::TruncatedPayload {
                declared: 16,
                available: 7
            })
        );
    }

    #[test]
    fn non_hex_and_overlong_are_rejected() {
        assert_eq!(decode(b"zzzz"), Err(DecodeError::NotHex));
        // 0xFFFF = 65535 > MAX_LINE_LEN (65520)
        let mut buf = b"ffff".to_vec();
        buf.resize(70000, 0);
        assert_eq!(decode(&buf), Err(DecodeError::TooLong { declared: 65535 }));
    }

    #[test]
    fn mixed_case_hex_is_accepted_on_read() {
        let (pkt, _) = decode(b"000Aabcdef").unwrap();
        assert_eq!(pkt, Packet::Data(b"abcdef"));
    }

    #[test]
    fn encode_emits_lowercase_and_round_trips() {
        let mut out = Vec::new();
        encode_into(b"abcdef", &mut out).unwrap();
        assert_eq!(out, b"000aabcdef", "length must be lowercase hex");
        let (pkt, used) = decode(&out).unwrap();
        assert_eq!(pkt, Packet::Data(b"abcdef"));
        assert_eq!(used, out.len());
    }

    #[test]
    fn encode_line_appends_exactly_one_lf() {
        let mut out = Vec::new();
        encode_line_into(b"command=ls-refs", &mut out).unwrap();
        assert_eq!(out, b"0014command=ls-refs\n");
        let (pkt, _) = decode(&out).unwrap();
        assert_eq!(pkt.text(), Some(&b"command=ls-refs"[..]));
    }

    #[test]
    fn encoder_refuses_the_empty_line_it_could_have_emitted() {
        let mut out = Vec::new();
        assert_eq!(
            encode_into(b"", &mut out),
            Err(EncodeError::EmptyPayload),
            "0004 is legal to receive and impolite to send"
        );
        assert!(out.is_empty(), "a refused encode must not write bytes");
    }

    #[test]
    fn encoder_enforces_the_payload_ceiling() {
        let mut out = Vec::new();
        let big = vec![b'x'; MAX_DATA_LEN + 1];
        assert_eq!(
            encode_into(&big, &mut out),
            Err(EncodeError::TooLong {
                len: MAX_DATA_LEN + 1
            })
        );
        // Exactly at the bound is legal, and lands on MAX_LINE_LEN total.
        let ok = vec![b'x'; MAX_DATA_LEN];
        let mut out2 = Vec::new();
        encode_into(&ok, &mut out2).unwrap();
        assert_eq!(out2.len(), MAX_LINE_LEN);
    }

    #[test]
    fn text_strips_one_lf_not_a_run() {
        assert_eq!(Packet::Data(b"a\n").text(), Some(&b"a"[..]));
        assert_eq!(Packet::Data(b"a\n\n").text(), Some(&b"a\n"[..]));
        assert_eq!(Packet::Data(b"a").text(), Some(&b"a"[..]));
    }

    #[test]
    fn err_lines_are_recognised_and_unwrapped() {
        let p = Packet::Data(b"ERR upload-pack: not our ref\n");
        assert_eq!(p.err(), Some(&b"upload-pack: not our ref"[..]));
        assert_eq!(Packet::Data(b"not an error").err(), None);
        assert_eq!(Packet::Flush.err(), None);
    }

    #[test]
    fn iterator_walks_a_real_v2_advertisement() {
        // Byte-for-byte what github.com sent for `git/git` on 2026-08-17.
        let adv: &[u8] = b"001e# service=git-upload-pack\n\
                           0000\
                           000eversion 2\n\
                           0013ls-refs=unborn\n\
                           0027fetch=shallow wait-for-done filter\n\
                           0012server-option\n\
                           0017object-format=sha1\n\
                           0000";
        let got: Vec<_> = Packets::new(adv).map(Result::unwrap).collect();
        assert_eq!(got.len(), 8);
        assert_eq!(got[0].text(), Some(&b"# service=git-upload-pack"[..]));
        assert_eq!(got[1], Packet::Flush);
        assert_eq!(got[2].text(), Some(&b"version 2"[..]));
        assert_eq!(
            got[4].text(),
            Some(&b"fetch=shallow wait-for-done filter"[..]),
            "the `filter` feature is the whole reason this engine exists"
        );
        assert_eq!(got[7], Packet::Flush);
    }

    #[test]
    fn iterator_stops_after_the_first_error() {
        let mut it = Packets::new(b"0006ab\x00\x00");
        assert_eq!(it.next().unwrap().unwrap(), Packet::Data(b"ab"));
        assert!(it.next().unwrap().is_err(), "malformed tail must error");
        assert!(
            it.next().is_none(),
            "there is no resync point in a length-framed protocol"
        );
    }

    #[test]
    fn sideband_split_routes_three_bands_and_refuses_the_rest() {
        assert_eq!(split_band(&[1, b'P', b'A']), Some((Band::Pack, &b"PA"[..])));
        assert_eq!(
            split_band(&[2, b'h', b'i']),
            Some((Band::Progress, &b"hi"[..]))
        );
        assert_eq!(split_band(&[3, b'!']), Some((Band::Error, &b"!"[..])));
        assert_eq!(split_band(&[4, b'?']), None, "unknown band is not data");
        assert_eq!(split_band(&[]), None);
    }
}
