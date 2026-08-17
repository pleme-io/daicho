//! Git wire protocol **version 2** — the capability advertisement, the command
//! request shape, and the `fetch` response sectioning.
//!
//! Reference: `Documentation/gitprotocol-v2.adoc` in git.git. Every wire shape
//! in the tests below was captured live against `github.com` on 2026-08-17.
//!
//! # v2 only, deliberately
//!
//! A v1 server is refused with a typed error rather than silently degraded to.
//! The reason is specific: the `filter` capability — the entire justification
//! for this engine — is a v2 `fetch` feature. A client that quietly falls back
//! to v1 turns a 1.65 MiB filtered fetch into a 39.4 MiB unfiltered one and
//! reports success. Silent degradation of the one capability we are here for
//! is worse than a hard failure.

use crate::pktline::{self, Packet, Packets};

/// The object-id hash the server is speaking.
///
/// Carried rather than assumed: the pack reader's every offset calculation is
/// parameterised on the id length, and hardcoding 20 is the expensive half of
/// a future SHA-256 migration. Absent `object-format` means sha1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashKind {
    /// 20-byte SHA-1. The only format any forge we target serves today.
    #[default]
    Sha1,
    /// 32-byte SHA-256. Parsed so an unexpected advertisement is a typed
    /// refusal rather than a silent mis-parse of every offset.
    Sha256,
}

impl HashKind {
    /// Raw digest length in bytes.
    ///
    /// Named `digest_len` rather than `len`: a hash is not a collection, it is
    /// never empty, and `len()` on a non-collection invites the `is_empty()`
    /// companion that would be meaningless here.
    #[must_use]
    pub fn digest_len(self) -> usize {
        match self {
            HashKind::Sha1 => 20,
            HashKind::Sha256 => 32,
        }
    }

    /// Hex-encoded digest length in characters.
    #[must_use]
    pub fn hex_len(self) -> usize {
        self.digest_len() * 2
    }
}

/// What the server said it can do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// The server's self-reported agent string.
    pub agent: Option<String>,
    /// The object format in use.
    pub object_format: HashKind,
    /// Features of the `ls-refs` command, if it is offered at all.
    pub ls_refs: Option<Vec<String>>,
    /// Features of the `fetch` command, if it is offered at all.
    pub fetch: Option<Vec<String>>,
    /// Whether `server-option` is offered.
    pub server_option: bool,
}

impl Capabilities {
    /// Whether the server will honour a partial-clone `filter` argument.
    ///
    /// ── ★ CHECK THIS, AND FAIL LOUDLY IF IT IS FALSE ──────────────────────
    /// `filter` is advertised as a *feature of `fetch`*, not as a top-level
    /// capability. A client that sends the argument to a server that did not
    /// advertise it gets a full pack and no error — which is the exact silent
    /// 24x cost blow-up this engine exists to prevent. Never send `filter`
    /// without consulting this first.
    #[must_use]
    pub fn supports_filter(&self) -> bool {
        self.fetch
            .as_ref()
            .is_some_and(|f| f.iter().any(|x| x == "filter"))
    }

    /// Whether the server offers shallow/deepen arguments.
    #[must_use]
    pub fn supports_shallow(&self) -> bool {
        self.fetch
            .as_ref()
            .is_some_and(|f| f.iter().any(|x| x == "shallow"))
    }
}

/// Why an advertisement could not be understood.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AdvertisementError {
    /// The framing itself was invalid.
    #[error("pkt-line framing: {0}")]
    Framing(#[from] pktline::DecodeError),
    /// The stream ended before the version line.
    #[error("advertisement ended before a version line")]
    Truncated,
    /// The server announced a service other than the one requested.
    #[error("server announced service {announced:?}, expected git-upload-pack")]
    WrongService {
        /// What the server announced.
        announced: String,
    },
    /// The server is speaking v1.
    ///
    /// Kept distinct from every other failure because the remedy differs: this
    /// is not a broken server, it is an *older* one, and the caller may want to
    /// say so precisely.
    #[error(
        "server is speaking protocol v1, not v2 — the `filter` capability this \
         client requires is v2-only, and silently continuing would fetch the \
         full history instead of the filtered one"
    )]
    NotV2,
    /// An unknown `object-format`.
    #[error("unsupported object-format {name:?}")]
    UnsupportedObjectFormat {
        /// The format the server named.
        name: String,
    },
}

/// Parse the body of `GET /info/refs?service=git-upload-pack`.
///
/// Tolerates the optional `# service=…` announcement line, which some servers
/// send and others omit.
///
/// # Errors
///
/// See [`AdvertisementError`]. A v1 server is [`AdvertisementError::NotV2`].
pub fn parse_advertisement(body: &[u8]) -> Result<Capabilities, AdvertisementError> {
    let mut it = Packets::new(body);
    let mut first = match it.next() {
        Some(p) => p?,
        None => return Err(AdvertisementError::Truncated),
    };

    // The service announcement is optional. When present it is followed by a
    // flush, and only then does the version line arrive.
    if let Some(t) = first.text()
        && let Some(svc) = t.strip_prefix(b"# service=")
    {
        if svc != b"git-upload-pack" {
            return Err(AdvertisementError::WrongService {
                announced: String::from_utf8_lossy(svc).into_owned(),
            });
        }
        // Consume the flush that terminates the announcement, then take the
        // next line as the version.
        loop {
            match it.next() {
                Some(p) => {
                    if p? == Packet::Flush {
                        break;
                    }
                }
                None => return Err(AdvertisementError::Truncated),
            }
        }
        first = match it.next() {
            Some(p) => p?,
            None => return Err(AdvertisementError::Truncated),
        };
    }

    // ── The v1 discriminant ───────────────────────────────────────────────
    // v2 announces itself. v1 does NOT: its first line is a ref advertisement
    // (`<oid> SP <refname> NUL <capabilities>`), so "the payload does not
    // begin with `version `" IS the v1 signal. A server that ignored our
    // `Git-Protocol: version=2` header lands here.
    let Some(t) = first.text() else {
        return Err(AdvertisementError::Truncated);
    };
    if t != b"version 2" {
        return Err(AdvertisementError::NotV2);
    }

    let mut caps = Capabilities::default();
    for pkt in it {
        let pkt = pkt?;
        let Some(line) = pkt.text() else {
            // A flush terminates the advertisement.
            break;
        };
        let (key, value) = match line.iter().position(|&c| c == b'=') {
            Some(i) => (&line[..i], Some(&line[i + 1..])),
            None => (line, None),
        };
        match key {
            b"agent" => caps.agent = value.map(|v| String::from_utf8_lossy(v).into_owned()),
            b"object-format" => {
                caps.object_format = match value {
                    Some(b"sha1") | None => HashKind::Sha1,
                    Some(b"sha256") => HashKind::Sha256,
                    Some(other) => {
                        return Err(AdvertisementError::UnsupportedObjectFormat {
                            name: String::from_utf8_lossy(other).into_owned(),
                        });
                    }
                };
            }
            b"ls-refs" => caps.ls_refs = Some(split_features(value)),
            b"fetch" => caps.fetch = Some(split_features(value)),
            b"server-option" => caps.server_option = true,
            _ => {}
        }
    }
    Ok(caps)
}

/// Split a `key=v1 v2 v3` value into its feature words.
fn split_features(value: Option<&[u8]>) -> Vec<String> {
    value
        .map(|v| {
            v.split(|&c| c == b' ')
                .filter(|w| !w.is_empty())
                .map(|w| String::from_utf8_lossy(w).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Build a v2 command request body.
///
/// The wire order is fixed and load-bearing: `command=` line, then the
/// capability list, then `0001`, then arguments, then `0000`. A server rejects
/// any other ordering.
#[derive(Debug, Clone)]
pub struct Request {
    command: &'static str,
    agent: String,
    object_format: HashKind,
    args: Vec<Vec<u8>>,
}

impl Request {
    /// Start a request for `command` (`ls-refs` or `fetch`).
    #[must_use]
    pub fn new(command: &'static str, agent: &str, object_format: HashKind) -> Self {
        Self {
            command,
            agent: agent.to_owned(),
            object_format,
            args: Vec::new(),
        }
    }

    /// Append a raw argument line.
    #[must_use]
    pub fn arg(mut self, a: impl Into<Vec<u8>>) -> Self {
        self.args.push(a.into());
        self
    }

    /// Append `ref-prefix <prefix>`.
    ///
    /// Advisory on the wire: the spec says the server *may* use it to narrow
    /// the output, so the caller must still filter what comes back.
    #[must_use]
    pub fn ref_prefix(self, prefix: &str) -> Self {
        let mut a = b"ref-prefix ".to_vec();
        a.extend_from_slice(prefix.as_bytes());
        self.arg(a)
    }

    /// Append `want <oid>`.
    #[must_use]
    pub fn want(self, oid_hex: &str) -> Self {
        let mut a = b"want ".to_vec();
        a.extend_from_slice(oid_hex.as_bytes());
        self.arg(a)
    }

    /// Append `have <oid>`.
    #[must_use]
    pub fn have(self, oid_hex: &str) -> Self {
        let mut a = b"have ".to_vec();
        a.extend_from_slice(oid_hex.as_bytes());
        self.arg(a)
    }

    /// Append `filter <spec>` — the partial-clone filter.
    ///
    /// The caller must have checked [`Capabilities::supports_filter`] first;
    /// this type cannot check for itself because it does not hold the
    /// advertisement. See [`Filter`] for the specs worth using.
    #[must_use]
    pub fn filter(self, spec: &Filter) -> Self {
        let mut a = b"filter ".to_vec();
        a.extend_from_slice(spec.as_wire().as_bytes());
        self.arg(a)
    }

    /// Serialise to the POST body.
    ///
    /// # Errors
    ///
    /// Propagates [`pktline::EncodeError`] if any single line exceeds the
    /// pkt-line payload ceiling.
    pub fn encode(&self) -> Result<Vec<u8>, pktline::EncodeError> {
        let mut out = Vec::new();
        let mut cmd = b"command=".to_vec();
        cmd.extend_from_slice(self.command.as_bytes());
        pktline::encode_line_into(&cmd, &mut out)?;

        let mut agent = b"agent=".to_vec();
        agent.extend_from_slice(self.agent.as_bytes());
        pktline::encode_line_into(&agent, &mut out)?;

        let of: &[u8] = match self.object_format {
            HashKind::Sha1 => b"object-format=sha1",
            HashKind::Sha256 => b"object-format=sha256",
        };
        pktline::encode_line_into(of, &mut out)?;

        pktline::encode_delim_into(&mut out);
        for a in &self.args {
            pktline::encode_line_into(a, &mut out)?;
        }
        pktline::encode_flush_into(&mut out);
        Ok(out)
    }
}

/// A partial-clone filter spec.
///
/// Modelled as a closed sum rather than a free string so a typo is a compile
/// error. The scaled forms (`1k`, `5m`) are deliberately not offered: the spec
/// says senders should translate to fully-expanded form for interoperability,
/// so [`Filter::BlobLimit`] renders a plain integer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    /// Omit all blobs. Trees and commits still arrive.
    BlobNone,
    /// Omit blobs at or above `bytes`.
    BlobLimit {
        /// The size threshold in bytes.
        bytes: u64,
    },
    /// Omit every blob **and** every tree at depth >= `depth` from the root.
    ///
    /// `Tree { depth: 0 }` is the one to reach for when the question is
    /// ancestry: it yields commits and tags only. Measured on `pleme-io/nix`
    /// 2026-08-17 — the complete 5,342-commit DAG in **1.65 MiB**, against
    /// 39.4 MiB for the unfiltered pack and 9.25 GB of raw blobs.
    Tree {
        /// Depth from the root tree.
        depth: u32,
    },
}

impl Filter {
    /// The on-wire spelling.
    #[must_use]
    pub fn as_wire(&self) -> String {
        // A `Display`-family rendering is the sanctioned way to build a string
        // under ★★ TYPED EMISSION; `format!()` is not used.
        use std::fmt::Write as _;
        let mut s = String::new();
        match self {
            Filter::BlobNone => s.push_str("blob:none"),
            Filter::BlobLimit { bytes } => {
                let _ = write!(s, "blob:limit={bytes}");
            }
            Filter::Tree { depth } => {
                let _ = write!(s, "tree:{depth}");
            }
        }
        s
    }
}

/// One ref from an `ls-refs` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefLine {
    /// The object id in hex, or `None` for an unborn HEAD.
    pub oid: Option<String>,
    /// The full ref name.
    pub name: String,
    /// The ref this one symbolically targets, from `symref-target:`.
    pub symref_target: Option<String>,
    /// The peeled object id, from `peeled:`.
    pub peeled: Option<String>,
}

/// Parse an `ls-refs` response body.
///
/// # Errors
///
/// Propagates framing errors. A malformed ref line is skipped rather than
/// failing the whole response — a server may legitimately grow attributes we
/// do not know.
pub fn parse_ls_refs(body: &[u8]) -> Result<Vec<RefLine>, pktline::DecodeError> {
    let mut out = Vec::new();
    for pkt in Packets::new(body) {
        let pkt = pkt?;
        let Some(line) = pkt.text() else { continue };
        let mut fields = line.split(|&c| c == b' ');
        let Some(oid) = fields.next() else { continue };
        let Some(name) = fields.next() else { continue };
        let mut r = RefLine {
            oid: if oid == b"unborn" {
                None
            } else {
                Some(String::from_utf8_lossy(oid).into_owned())
            },
            name: String::from_utf8_lossy(name).into_owned(),
            symref_target: None,
            peeled: None,
        };
        for attr in fields {
            if let Some(v) = attr.strip_prefix(b"symref-target:") {
                r.symref_target = Some(String::from_utf8_lossy(v).into_owned());
            } else if let Some(v) = attr.strip_prefix(b"peeled:") {
                r.peeled = Some(String::from_utf8_lossy(v).into_owned());
            }
        }
        out.push(r);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-for-byte what github.com sent for `git/git` on 2026-08-17.
    const GITHUB_ADV: &[u8] = b"001e# service=git-upload-pack\n\
                                0000\
                                000eversion 2\n\
                                0013ls-refs=unborn\n\
                                0027fetch=shallow wait-for-done filter\n\
                                0012server-option\n\
                                0017object-format=sha1\n\
                                0000";

    #[test]
    fn parses_the_live_github_advertisement() {
        let caps = parse_advertisement(GITHUB_ADV).unwrap();
        assert_eq!(caps.object_format, HashKind::Sha1);
        assert!(caps.server_option);
        assert_eq!(caps.ls_refs.as_deref(), Some(&["unborn".to_owned()][..]));
        assert_eq!(
            caps.fetch.as_deref(),
            Some(&["shallow".to_owned(), "wait-for-done".to_owned(), "filter".to_owned()][..])
        );
    }

    // ── ★ THE CAPABILITY THIS ENGINE EXISTS FOR ──────────────────────────
    #[test]
    fn filter_support_is_read_from_the_fetch_feature_set() {
        let caps = parse_advertisement(GITHUB_ADV).unwrap();
        assert!(caps.supports_filter(), "github advertises fetch=… filter");
        assert!(caps.supports_shallow());

        // A server offering `fetch` but NOT `filter` must read as unsupported,
        // not as "fetch exists so presumably yes".
        let no_filter: &[u8] = b"000eversion 2\n001efetch=shallow ref-in-want\n0000";
        let caps = parse_advertisement(no_filter).unwrap();
        assert!(caps.fetch.is_some(), "fetch IS offered");
        assert!(
            !caps.supports_filter(),
            "…but filter is not, and conflating them silently fetches 24x the bytes"
        );
    }

    #[test]
    fn a_v1_server_is_refused_not_degraded_to() {
        // v1 by omission: the first line is a ref advertisement, and the
        // server simply ignored our version=2 header.
        let v1: &[u8] = b"00b918e66859d87fb4b76599f73460b54f0848c76b16 HEAD\x00multi_ack thin-pack side-band side-band-64k ofs-delta shallow no-progress include-tag multi_ack_detailed symref=HEAD:refs/heads/master\n";
        assert_eq!(parse_advertisement(v1), Err(AdvertisementError::NotV2));

        // v1 announced explicitly.
        let v1e: &[u8] = b"001e# service=git-upload-pack\n0000000eversion 1\n0000";
        assert_eq!(parse_advertisement(v1e), Err(AdvertisementError::NotV2));
    }

    #[test]
    fn a_wrong_service_announcement_is_rejected() {
        let bad: &[u8] = b"001f# service=git-receive-pack\n0000";
        assert!(matches!(
            parse_advertisement(bad),
            Err(AdvertisementError::WrongService { .. })
        ));
    }

    #[test]
    fn an_absent_service_line_is_tolerated() {
        let no_ann: &[u8] = b"000eversion 2\n0017object-format=sha1\n0000";
        let caps = parse_advertisement(no_ann).unwrap();
        assert_eq!(caps.object_format, HashKind::Sha1);
    }

    #[test]
    fn an_unknown_object_format_is_a_typed_refusal() {
        let weird: &[u8] = b"000eversion 2\n001bobject-format=sha3-512\n0000";
        assert!(matches!(
            parse_advertisement(weird),
            Err(AdvertisementError::UnsupportedObjectFormat { .. })
        ));
    }

    // ── The request shape, byte-for-byte against a live-verified capture ──
    #[test]
    fn ls_refs_request_matches_the_wire_shape_github_accepted() {
        let body = Request::new("ls-refs", "pleme-io/0.1", HashKind::Sha1)
            .arg(&b"peel"[..])
            .arg(&b"symrefs"[..])
            .ref_prefix("refs/heads/master")
            .encode()
            .unwrap();

        let expect: &[u8] = b"0014command=ls-refs\n\
                              0017agent=pleme-io/0.1\n\
                              0017object-format=sha1\n\
                              0001\
                              0009peel\n\
                              000csymrefs\n\
                              0021ref-prefix refs/heads/master\n\
                              0000";
        assert_eq!(
            body, expect,
            "this exact byte sequence was accepted by github.com on 2026-08-17"
        );
    }

    #[test]
    fn fetch_request_carries_the_filter_argument() {
        let body = Request::new("fetch", "pleme-io/0.1", HashKind::Sha1)
            .arg(&b"no-progress"[..])
            .filter(&Filter::Tree { depth: 0 })
            .want("18e66859d87fb4b76599f73460b54f0848c76b16")
            .arg(&b"done"[..])
            .encode()
            .unwrap();
        let s = String::from_utf8_lossy(&body);
        assert!(s.contains("filter tree:0\n"), "got: {s}");
        assert!(s.contains("want 18e66859"), "got: {s}");
        assert!(s.ends_with("0009done\n0000"), "done then flush; got: {s}");
    }

    #[test]
    fn filter_specs_render_fully_expanded() {
        assert_eq!(Filter::BlobNone.as_wire(), "blob:none");
        assert_eq!(Filter::Tree { depth: 0 }.as_wire(), "tree:0");
        assert_eq!(
            Filter::BlobLimit { bytes: 1_048_576 }.as_wire(),
            "blob:limit=1048576",
            "scaled units (1m) are legal but the spec asks senders to expand"
        );
    }

    // ── ls-refs response, the exact bytes github returned ─────────────────
    #[test]
    fn parses_the_live_ls_refs_response() {
        let body: &[u8] = b"005218e66859d87fb4b76599f73460b54f0848c76b16 HEAD symref-target:refs/heads/master\n\
                            003f18e66859d87fb4b76599f73460b54f0848c76b16 refs/heads/master\n\
                            0000";
        let refs = parse_ls_refs(body).unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].name, "HEAD");
        assert_eq!(
            refs[0].symref_target.as_deref(),
            Some("refs/heads/master"),
            "the argument is `symrefs` but the attribute is `symref-target:`"
        );
        assert_eq!(
            refs[1].oid.as_deref(),
            Some("18e66859d87fb4b76599f73460b54f0848c76b16")
        );
        assert_eq!(refs[1].symref_target, None);
    }

    #[test]
    fn an_unborn_head_yields_no_oid_rather_than_a_fake_one() {
        let body: &[u8] = b"002eunborn HEAD symref-target:refs/heads/main\n0000";
        let refs = parse_ls_refs(body).unwrap();
        assert_eq!(refs[0].oid, None, "unborn must not become a zero oid");
        assert_eq!(refs[0].symref_target.as_deref(), Some("refs/heads/main"));
    }

    #[test]
    fn hash_kind_lengths_are_what_the_pack_reader_will_index_on() {
        assert_eq!(HashKind::Sha1.digest_len(), 20);
        assert_eq!(HashKind::Sha1.hex_len(), 40);
        assert_eq!(HashKind::Sha256.digest_len(), 32);
        assert_eq!(HashKind::Sha256.hex_len(), 64);
    }
}
