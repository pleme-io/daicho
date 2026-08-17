//! **Tojime** (綴じ目) — *the stitch where gathered leaves are sewn into one
//! volume*. Git's wire layer: pkt-line framing and the protocol-v2 command
//! surface.
//!
//! Member of The Record 録 family, seeded by `daicho` (台帳). See
//! `theory/DAICHO.md`.
//!
//! # Name status
//!
//! **RATIFIED 2026-08-17 by operator decision.** The Law 4 corpus sweep is
//! complete on every axis — org repo dirs, `theory/`, `VOCABULARY.md`, and
//! crates.io (checked 2026-08-17: `tojime` returns 404, i.e. free), the axis an
//! on-disk sweep structurally cannot see and the one that has burnt this fleet
//! twice.
//!
//! Recorded near-miss so nobody re-litigates it: `todojimari` (戸締り, blue's
//! artifact contract) shares a romaji run and collides on nothing — 綴じる
//! *bind* and 締める *fasten* are different verbs with different kanji, the
//! glosses and families differ, and three syllables against five is not the
//! `shinsa`/`shinka` shape.
//!
//! # Scope
//!
//! This crate owns the wire and **nothing below it**. Object formats,
//! packfiles, delta resolution and the object database belong to `genbo`
//! (原簿); the typed git operations belong to `daicho`. The split is a real
//! boundary, not a directory: `tojime` never parses a git object, and `genbo`
//! never opens a socket.
//!
//! # Why this exists rather than a `gix` dependency
//!
//! `gix` can do everything here and one thing it cannot expose. Its
//! `fetch::Arguments::filter` is `pub` but orphaned: `fetch::Options` carries
//! no filter field and no escape hatch, and `gix_protocol::fetch()` builds the
//! `Arguments` internally and never yields them. So the **partial-clone
//! filter** — the difference between 1.65 MiB and 39.4 MiB for one repo's
//! commit DAG — is unreachable from the API a consumer actually calls.
//! `theory/NATURALIZE-GIT-GH.md` §10 names that exact situation as the
//! falsifier for its own "compose, don't rebuild" verdict.
//!
//! Tier-honest: that is the *first* clause of the documented re-entry
//! condition. The second — *"that upstream refuses"* — is **UNTESTED**; no
//! issue has been filed. This crate exists because the operator accepted the
//! rebuild price with that gap stated, not because upstream said no.

#![forbid(unsafe_code)]

pub mod pktline;
pub mod v2;

pub use pktline::{Band, DecodeError, EncodeError, Packet, Packets};
pub use v2::{Capabilities, Filter, HashKind, RefLine, Request};
