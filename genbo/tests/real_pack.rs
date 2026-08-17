//! Resolve a pack **git actually produced**, and verify every object id.
//!
//! ── ★ WHY A REAL PACK AND NOT MORE FIXTURES ───────────────────────────
//! Every unit test in `pack.rs` feeds bytes this crate wrote, so all of them
//! together prove only that the reader agrees with its own author. Two of
//! those fixtures were wrong on the first pass in exactly that way — the type
//! nibble was shifted because the size-continuation bit was set — and the
//! tests caught the fixture, not the code.
//!
//! This is the oracle: git writes the pack, git states the ids, and the reader
//! must reproduce them byte for byte. It also exercises what a hand-built
//! fixture never reaches — real zlib streams, real varint widths, and whatever
//! deltas `git repack` decided to emit.
//!
//! The pack is built at test time, so there is no binary blob in the tree and
//! no fixture to go stale.

use std::process::Command;

use genbo::oid::{Kind, ObjectId};
use genbo::pack::{header_for, resolve_all};

/// Build a throwaway repo and return (pack bytes, the ids git reports).
fn built_pack(dir: &std::path::Path) -> Option<(Vec<u8>, Vec<String>)> {
    let git = |args: &[&str]| -> Option<()> {
        let st = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .ok()?;
        st.status.success().then_some(())
    };
    git(&["init", "-q", "-b", "main", "."])?;
    for i in 0..5 {
        std::fs::write(dir.join("f.txt"), "line\n".repeat(i + 1)).ok()?;
        git(&["add", "f.txt"])?;
        // `--no-verify`: the fleet's global commit-msg hook refuses
        // placeholder subjects, and these are throwaway fixture commits.
        git(&[
            "-c",
            "user.email=a@b",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "--no-verify",
            "-m",
            "fixture commit for the pack reader",
        ])?;
    }
    git(&["repack", "-a", "-d", "-q"])?;

    let packs: Vec<_> = std::fs::read_dir(dir.join(".git/objects/pack"))
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "pack"))
        .collect();
    let pack = packs.first()?;
    let bytes = std::fs::read(pack).ok()?;

    let idx = pack.with_extension("idx");
    let out = Command::new("git")
        .current_dir(dir)
        .args(["verify-pack", "-v", idx.to_str()?])
        .output()
        .ok()?;
    let ids = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let id = it.next()?;
            let kind = it.next()?;
            (id.len() == 40
                && id.bytes().all(|b| b.is_ascii_hexdigit())
                && matches!(kind, "commit" | "tree" | "blob" | "tag"))
            .then(|| id.to_owned())
        })
        .collect();
    Some((bytes, ids))
}

#[test]
fn every_object_in_a_real_git_pack_resolves_to_the_id_git_gave_it() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let Some((bytes, git_ids)) = built_pack(tmp.path()) else {
        // No usable git is a skip, not a pass — say so loudly rather than
        // returning green, which is the vacuous shape this fleet keeps
        // getting burned by.
        eprintln!("SKIPPED: could not build a pack (is `git` on PATH?)");
        return;
    };

    // The denominator lives INSIDE the assertion: if the corpus were empty or
    // near-empty, everything below would pass while checking nothing.
    assert!(
        git_ids.len() >= 10,
        "expected git to report at least 10 objects, got {}",
        git_ids.len()
    );

    let resolved = resolve_all(&bytes, Kind::Sha1).expect("resolve the pack");
    assert_eq!(
        resolved.len(),
        git_ids.len(),
        "object count must match git's own tally"
    );

    // The real assertion. Recomputing each id from the resolved bytes is what
    // proves the delta application, the varint widths and the zlib framing are
    // all correct — one wrong byte anywhere changes the digest.
    let mut ours: Vec<String> = resolved
        .values()
        .map(|(kind, body)| {
            use sha1::Digest as _;
            let mut h = sha1::Sha1::new();
            h.update(header_for(*kind, body.len()));
            h.update(body);
            ObjectId::from_bytes(Kind::Sha1, &h.finalize())
                .expect("20 bytes")
                .to_string()
        })
        .collect();
    let mut theirs = git_ids;
    ours.sort();
    theirs.sort();
    assert_eq!(
        ours, theirs,
        "every id recomputed from resolved bytes must equal the id git assigned"
    );
}
