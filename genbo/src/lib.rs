//! **Genbo** (原簿) — *the original register*. Git's object layer: the object
//! model, commit parsing, and the commit-graph walk that answers ancestry.
//!
//! Member of The Record 録 family, seeded by `daicho` (台帳). Sibling of
//! `tojime` (綴じ目), which owns the wire and never parses an object; this
//! crate parses objects and never opens a socket.
//!
//! # Scope, and why it is this small
//!
//! The question this layer exists to answer is *"is commit A an ancestor of
//! commit B?"* — the no-downgrade guard of a `GitOps` reconciler. Measured on
//! `pleme-io/nix` (2026-08-17): the complete 5,342-commit DAG arrives in
//! **1.65 MiB** under `--filter=tree:0`, against 39.4 MiB for an unfiltered
//! pack and 9.25 GB of raw blobs. Trees and blobs are pure waste for this
//! question, so nothing here reads one.
//!
//! Two invariants carry the crate, and both are types rather than comments:
//!
//! - [`graph::Verdict`] has three arms. A shallow walk that runs out of graph
//!   has not proven absence, and a `bool` would force that into `false` —
//!   which a reconciler reads as a force-push and acts on.
//! - [`graph::WalkError`] has no `NeedsFetch` arm. Under a full-depth
//!   `tree:0` fetch every reachable commit is present, so a missing one is
//!   corruption, not a promisor gap.
//!
//! Still to land: the packfile v2 reader and delta resolution, which is how
//! commits actually arrive over the wire. Note the measurement that says it
//! cannot be skipped — 86 of 5,003 commit entries in this repo's real packs
//! are deltified, so "commits are always full objects" is false.

#![forbid(unsafe_code)]

pub mod commit;
pub mod graph;
pub mod oid;
pub mod pack;

pub use commit::{parents, CommitError, Parents};
pub use graph::{Verdict, WalkError, Walker};
pub use oid::{Kind, ObjectId, OidError};
pub use pack::{EntryHeader, EntryKind, PackError};
