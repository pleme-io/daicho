//! Commit-graph traversal — "is A an ancestor of B?".
//!
//! This is the question a `GitOps` reconciler asks before it activates a build:
//! *is the rev I deployed still on the branch I track?* Getting it wrong in
//! the optimistic direction deploys a rev that was force-pushed away.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::oid::ObjectId;

/// The answer to an ancestry question.
///
/// ── ★ THREE ARMS, AND THE THIRD IS THE WHOLE POINT ────────────────────
/// A shallow clone stores commits whose `parent` lines name objects it does
/// not have — git installs graft points so `log` stops there and `fsck` stays
/// quiet. A walk that exhausts against such a boundary has NOT proven
/// `A ∉ ancestors(B)`; it has only proven "not within what I hold".
///
/// A two-valued `bool` forces that case into `false`, and `false` means
/// *"the deployed rev is not on this branch"* — which a reconciler reads as a
/// force-push and reacts to. So the unsound answer is not merely imprecise,
/// it is actionable. [`Verdict::Unknown`] exists so that state has a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A is reachable from B. Sound under every fetch shape.
    Yes,
    /// A is NOT reachable from B, and the walk closed its frontier with no
    /// boundary in sight — see [`Walker::is_ancestor`] for what guarantees it.
    No,
    /// The walk ran out of graph at a shallow boundary before deciding.
    Unknown {
        /// The boundary commits it stopped at, for diagnostics.
        hit_boundary: Vec<ObjectId>,
    },
}

/// Why a walk could not complete.
///
/// ── ★ THERE IS DELIBERATELY NO `NeedsFetch` VARIANT ───────────────────
/// Under a `--filter=tree:0` full-depth fetch, EVERY reachable commit is
/// present: the filter omits trees and blobs, and the walk reads neither. So
/// a commit that is missing is corruption or a programming error, never a
/// promisor gap to lazily fill. Giving that state a variant would invite a
/// lazy-fetch path into a function whose entire value is being answerable
/// offline.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WalkError {
    /// A commit reachable from the walk's frontier is absent from the store,
    /// and it is NOT a declared shallow boundary.
    #[error(
        "commit {missing} is reachable but absent, and is not a shallow \
         boundary — under a full-depth tree:0 fetch every reachable commit is \
         present, so this is corruption, not a promisor gap"
    )]
    MissingCommit {
        /// The absent commit.
        missing: ObjectId,
    },
    /// A commit object failed to parse.
    #[error("commit {at}: {source}")]
    Malformed {
        /// Which commit.
        at: ObjectId,
        /// The parse failure.
        #[source]
        source: crate::commit::CommitError,
    },
}

/// The commit DAG, as parent edges.
///
/// Deliberately not an object store: ancestry needs edges, and holding only
/// edges is what makes the persisted form ~228 KB for a repo whose full clone
/// is 39 MB.
#[derive(Debug, Clone, Default)]
pub struct Walker {
    edges: HashMap<ObjectId, Vec<ObjectId>>,
    shallow: HashSet<ObjectId>,
}

impl Walker {
    /// An empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a commit's parent edges.
    pub fn insert(&mut self, id: ObjectId, parents: Vec<ObjectId>) {
        self.edges.insert(id, parents);
    }

    /// Declare a shallow boundary — a commit whose parents we do not hold.
    ///
    /// From the wire these arrive as protocol-v2 `shallow <oid>` lines. A
    /// caller that fetches shallowly and forgets to declare the boundary gets
    /// [`Verdict::No`] where [`Verdict::Unknown`] was correct, so this is the
    /// one input the soundness of `No` depends on.
    pub fn mark_shallow(&mut self, id: ObjectId) {
        self.shallow.insert(id);
    }

    /// How many commits the graph holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.edges.len()
    }

    /// Whether the graph holds no commits.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// Is `ancestor` reachable from `descendant` by following parent edges?
    ///
    /// A commit is its own ancestor, matching `git merge-base --is-ancestor`.
    ///
    /// Termination is guaranteed by the visited set alone: the DAG is finite
    /// and every node is expanded at most once. No depth limit is needed, and
    /// none is imposed — a depth limit would reintroduce the unsound `No`
    /// that [`Verdict::Unknown`] exists to prevent.
    ///
    /// # Errors
    ///
    /// [`WalkError::MissingCommit`] when a reachable commit is absent and not
    /// a declared boundary; [`WalkError::Malformed`] is produced by the
    /// caller's parse step, not here.
    pub fn is_ancestor(
        &self,
        ancestor: &ObjectId,
        descendant: &ObjectId,
    ) -> Result<Verdict, WalkError> {
        if ancestor == descendant {
            return Ok(Verdict::Yes);
        }

        let mut seen: HashSet<ObjectId> = HashSet::new();
        let mut queue: VecDeque<ObjectId> = VecDeque::new();
        let mut boundary: Vec<ObjectId> = Vec::new();

        queue.push_back(*descendant);

        while let Some(cur) = queue.pop_front() {
            if !seen.insert(cur) {
                continue;
            }
            let Some(parents) = self.edges.get(&cur) else {
                // Absent. Two very different reasons, and conflating them is
                // the bug this whole type exists to prevent.
                if self.shallow.contains(&cur) {
                    boundary.push(cur);
                    continue;
                }
                return Err(WalkError::MissingCommit { missing: cur });
            };
            for p in parents {
                if p == ancestor {
                    return Ok(Verdict::Yes);
                }
                if !seen.contains(p) {
                    queue.push_back(*p);
                }
            }
        }

        // The frontier closed. `No` is sound ONLY if nothing was cut off.
        if boundary.is_empty() {
            Ok(Verdict::No)
        } else {
            Ok(Verdict::Unknown {
                hit_boundary: boundary,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid::Kind;

    fn oid(n: u8) -> ObjectId {
        let mut b = [0u8; 20];
        b[0] = n;
        ObjectId::from_bytes(Kind::Sha1, &b).unwrap()
    }

    /// linear: 1 <- 2 <- 3 <- 4   (4 is newest)
    fn linear() -> Walker {
        let mut w = Walker::new();
        w.insert(oid(1), vec![]);
        w.insert(oid(2), vec![oid(1)]);
        w.insert(oid(3), vec![oid(2)]);
        w.insert(oid(4), vec![oid(3)]);
        w
    }

    #[test]
    fn a_commit_is_its_own_ancestor() {
        assert_eq!(linear().is_ancestor(&oid(3), &oid(3)).unwrap(), Verdict::Yes);
    }

    #[test]
    fn forward_yes_and_reverse_no() {
        let w = linear();
        assert_eq!(w.is_ancestor(&oid(1), &oid(4)).unwrap(), Verdict::Yes);
        assert_eq!(w.is_ancestor(&oid(2), &oid(3)).unwrap(), Verdict::Yes);
        // The direction that matters: a NEWER rev is not an ancestor of an
        // older one, and answering Yes here would activate a rollback.
        assert_eq!(w.is_ancestor(&oid(4), &oid(1)).unwrap(), Verdict::No);
    }

    #[test]
    fn diverged_branches_are_no_in_both_directions() {
        //   1 <- 2 <- 3
        //         \-- 5
        let mut w = Walker::new();
        w.insert(oid(1), vec![]);
        w.insert(oid(2), vec![oid(1)]);
        w.insert(oid(3), vec![oid(2)]);
        w.insert(oid(5), vec![oid(2)]);
        assert_eq!(w.is_ancestor(&oid(3), &oid(5)).unwrap(), Verdict::No);
        assert_eq!(w.is_ancestor(&oid(5), &oid(3)).unwrap(), Verdict::No);
        // …but their common base is an ancestor of both.
        assert_eq!(w.is_ancestor(&oid(2), &oid(5)).unwrap(), Verdict::Yes);
    }

    #[test]
    fn a_merge_is_walked_through_both_parents() {
        //   1 <- 2 --\
        //   1 <- 3 ---> 4
        let mut w = Walker::new();
        w.insert(oid(1), vec![]);
        w.insert(oid(2), vec![oid(1)]);
        w.insert(oid(3), vec![oid(1)]);
        w.insert(oid(4), vec![oid(2), oid(3)]);
        assert_eq!(w.is_ancestor(&oid(2), &oid(4)).unwrap(), Verdict::Yes);
        assert_eq!(w.is_ancestor(&oid(3), &oid(4)).unwrap(), Verdict::Yes);
    }

    // ── ★ THE SHALLOW CASE — the reason Verdict has three arms ───────────
    #[test]
    fn a_shallow_boundary_yields_unknown_not_no() {
        // We hold 3 <- 4 and know 3's parents exist but are not here.
        let mut w = Walker::new();
        w.insert(oid(4), vec![oid(3)]);
        w.insert(oid(3), vec![oid(2)]);
        w.mark_shallow(oid(2));

        match w.is_ancestor(&oid(1), &oid(4)).unwrap() {
            Verdict::Unknown { hit_boundary } => {
                assert_eq!(hit_boundary, vec![oid(2)]);
            }
            other => panic!(
                "a shallow walk that ran out of graph must NOT claim No — got {other:?}. \
                 A reconciler reads No as a force-push and reacts to it."
            ),
        }

        // Reaching the answer BEFORE the boundary is still a sound Yes.
        assert_eq!(w.is_ancestor(&oid(3), &oid(4)).unwrap(), Verdict::Yes);
    }

    #[test]
    fn an_undeclared_missing_commit_is_an_error_not_a_verdict() {
        // Same graph, boundary NOT declared. Silence here would be the
        // unsound `No` wearing a different hat.
        let mut w = Walker::new();
        w.insert(oid(4), vec![oid(3)]);
        w.insert(oid(3), vec![oid(2)]);
        assert_eq!(
            w.is_ancestor(&oid(1), &oid(4)),
            Err(WalkError::MissingCommit { missing: oid(2) })
        );
    }

    #[test]
    fn a_cycle_cannot_hang_the_walk() {
        // Not producible by git, but a corrupt or hostile pack can encode it,
        // and this runs in a 24x7 daemon.
        let mut w = Walker::new();
        w.insert(oid(1), vec![oid(2)]);
        w.insert(oid(2), vec![oid(1)]);
        assert_eq!(w.is_ancestor(&oid(9), &oid(1)).unwrap(), Verdict::No);
    }

    #[test]
    fn a_wide_diamond_visits_each_node_once() {
        // 200 commits fanning into one merge; the visited set is what keeps
        // this linear instead of exponential.
        let mut w = Walker::new();
        w.insert(oid(1), vec![]);
        let mut tips = Vec::new();
        for n in 10..200u8 {
            w.insert(oid(n), vec![oid(1)]);
            tips.push(oid(n));
        }
        w.insert(oid(250), tips);
        assert_eq!(w.is_ancestor(&oid(1), &oid(250)).unwrap(), Verdict::Yes);
        // 190 tips (10..200) + the root + the merge.
        assert_eq!(w.len(), 192);
    }
}
