//! Commit objects — specifically, the parent edges an ancestry walk needs.
//!
//! ── ★ WHY THIS PARSES ALMOST NOTHING, DELIBERATELY ─────────────────────
//! An ancestry answer needs `parent` lines and nothing else. It never reads
//! the tree oid, never opens a tree, never touches a blob. Parsing the full
//! commit — author/committer signatures, timezones, `encoding`, `gpgsig`,
//! `mergetag` — would be several hundred lines of grammar in service of
//! fields no caller reads, and every one of them is a way to reject a commit
//! that git accepts.
//!
//! So this scans for `parent ` at column 0 and skips everything else. That is
//! sound, and the reason is the folding rule rather than luck: a multi-line
//! header value is folded by prefixing EVERY continuation line with one space
//! (`gitformat-commit-object`). A continuation line therefore never begins
//! with `parent` at column 0, so a base64 `gpgsig` body or a `mergetag`'s
//! embedded commit — which really does contain lines like `parent <oid>` —
//! cannot be mistaken for a real parent edge. That is the single trap in this
//! format and it is closed by construction, not by a heuristic.

use crate::oid::{Kind, ObjectId};

/// The parent edges of one commit, in order.
///
/// First-parent order is significant to git and is preserved.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Parents {
    /// Parent object ids, in the order the commit lists them.
    pub ids: Vec<ObjectId>,
}

/// Why a commit's parents could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CommitError {
    /// A `parent` line whose payload is not a well-formed object id.
    #[error("commit: malformed parent id: {0}")]
    BadParent(#[from] crate::oid::OidError),
    /// The object has no `tree` line, so it is not a commit at all.
    ///
    /// Checked because mistaking a tag or a blob for a commit yields an empty
    /// parent list, which an ancestry walk would read as "a root commit" —
    /// a wrong answer rather than an error.
    #[error("commit: no `tree` header; this is not a commit object")]
    NotACommit,
}

/// Read the parent edges out of a commit object's content.
///
/// `content` is the object body WITHOUT the `commit <len>\0` header — that
/// header is a storage/hashing envelope, not part of the object's grammar.
///
/// # Errors
///
/// See [`CommitError`].
pub fn parents(content: &[u8], kind: Kind) -> Result<Parents, CommitError> {
    let mut ids = Vec::new();
    let mut saw_tree = false;

    for line in header_lines(content) {
        // A continuation line (leading space) is part of the PREVIOUS header's
        // folded value. Skipping it here is what makes a `gpgsig` body or an
        // embedded `mergetag` unable to forge a parent edge.
        if line.first() == Some(&b' ') {
            continue;
        }
        if line.starts_with(b"tree ") {
            saw_tree = true;
        } else if let Some(rest) = line.strip_prefix(b"parent ") {
            // Take exactly the id width; git writes nothing after it, and a
            // trailing-garbage line should fail loudly rather than truncate.
            ids.push(ObjectId::parse_hex(kind, rest)?);
        }
    }

    if !saw_tree {
        return Err(CommitError::NotACommit);
    }
    Ok(Parents { ids })
}

/// The header block's lines: everything up to the first EMPTY line.
///
/// The blank line at column 0 terminates the headers; everything after it is
/// the commit message, verbatim and unparsed. A folded value never produces
/// an empty line (each of its continuations carries a leading space), so this
/// terminator cannot fire early.
fn header_lines(content: &[u8]) -> impl Iterator<Item = &[u8]> {
    content
        .split(|&b| b == b'\n')
        .take_while(|line| !line.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "18e66859d87fb4b76599f73460b54f0848c76b16";
    const B: &str = "7fd33221240a3ab97781a066c5efe0124979527f";
    const T: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

    fn commit(headers: &str, message: &str) -> Vec<u8> {
        [headers, "\n", message].concat().into_bytes()
    }

    #[test]
    fn a_root_commit_has_no_parents() {
        let c = commit(
            &["tree ", T, "\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n"].concat(),
            "root\n",
        );
        assert_eq!(parents(&c, Kind::Sha1).unwrap().ids, vec![]);
    }

    #[test]
    fn a_merge_keeps_parent_order() {
        let c = commit(
            &[
                "tree ", T, "\nparent ", A, "\nparent ", B,
                "\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n",
            ]
            .concat(),
            "merge\n",
        );
        let p = parents(&c, Kind::Sha1).unwrap();
        assert_eq!(p.ids.len(), 2);
        assert_eq!(p.ids[0].to_string(), A, "first-parent order is significant");
        assert_eq!(p.ids[1].to_string(), B);
    }

    // ── ★ THE TRAP THE FOLDING RULE CLOSES ───────────────────────────────
    #[test]
    fn a_folded_gpgsig_cannot_forge_a_parent_edge() {
        // Every continuation line carries ONE leading space — including the
        // one that looks exactly like a parent header.
        let c = commit(
            &[
                "tree ", T, "\nparent ", A,
                "\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000",
                "\ngpgsig -----BEGIN PGP SIGNATURE-----",
                "\n ",
                "\n parent ", B,
                "\n -----END PGP SIGNATURE-----\n",
            ]
            .concat(),
            "signed\n",
        );
        let p = parents(&c, Kind::Sha1).unwrap();
        assert_eq!(
            p.ids.len(),
            1,
            "the folded `parent` line is signature payload, not an edge"
        );
        assert_eq!(p.ids[0].to_string(), A);
    }

    #[test]
    fn an_embedded_mergetag_cannot_forge_a_parent_edge() {
        // A mergetag's folded body is a whole tag object, and a signed merge
        // legitimately contains lines reading `parent <oid>`.
        let c = commit(
            &[
                "tree ", T, "\nparent ", A,
                "\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000",
                "\nmergetag object ", B,
                "\n type commit",
                "\n tag v1.0",
                "\n parent ", B,
                "\n tagger A <a@x> 1 +0000\n",
            ]
            .concat(),
            "merge tag\n",
        );
        assert_eq!(parents(&c, Kind::Sha1).unwrap().ids.len(), 1);
    }

    #[test]
    fn the_message_is_never_scanned_for_headers() {
        // A commit message may contain anything, including a line that looks
        // exactly like a header. The blank line ended the block.
        let c = commit(
            &["tree ", T, "\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n"].concat(),
            &["fix: revert\n\nparent ", B, "\n"].concat(),
        );
        assert_eq!(
            parents(&c, Kind::Sha1).unwrap().ids,
            vec![],
            "a `parent` line in the MESSAGE is prose"
        );
    }

    #[test]
    fn a_non_commit_is_an_error_not_an_empty_parent_list() {
        // Reading a tag as a commit must not look like a root commit — that
        // would silently terminate an ancestry walk with a wrong answer.
        let tag = commit(
            &["object ", A, "\ntype commit\ntag v1\ntagger A <a@x> 1 +0000\n"].concat(),
            "a tag\n",
        );
        assert_eq!(parents(&tag, Kind::Sha1), Err(CommitError::NotACommit));
        assert_eq!(parents(b"", Kind::Sha1), Err(CommitError::NotACommit));
    }

    #[test]
    fn a_malformed_parent_id_fails_loudly() {
        let c = commit(&["tree ", T, "\nparent deadbeef\n"].concat(), "x\n");
        assert!(matches!(
            parents(&c, Kind::Sha1),
            Err(CommitError::BadParent(_))
        ));
    }

    #[test]
    fn unknown_headers_are_ignored_not_rejected() {
        // git accepts arbitrary headers; a parser that rejects them rejects
        // commits git created.
        let c = commit(
            &[
                "tree ", T, "\nparent ", A,
                "\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000",
                "\nencoding ISO-8859-1\nsomething-from-the-future yes\n",
            ]
            .concat(),
            "x\n",
        );
        assert_eq!(parents(&c, Kind::Sha1).unwrap().ids.len(), 1);
    }
}
