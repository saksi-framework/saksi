#!/usr/bin/env python3
"""Reference implementation of the Saksi synthetic-vote selection rules.

A line-for-line Python translation of the selection code in
`packages/saksi-auditor/src/fixtures.rs`. It exists so the rules can be read,
run, and checked without a Rust toolchain — and so anyone can independently
reproduce a published ground-truth table.

Run it to regenerate any tier:

    python reference_generator.py --voters 1000 --positions 3 --candidates 12 \
        --distribution realistic

Verified byte-identical to the Rust generator's output.

Three profiles:

  uniform     round-robin; divides the electorate evenly, so it ties at rank one
  skewed      candidate 1 takes half; the rest split the remainder evenly
  realistic   skewed, plus a reserved slice spread down the ranks to break ties

Only `realistic` can decide an election outright. The other two are kept
because the manuscript's performance comparisons are stated in terms of them.
"""

import argparse
import sys
from collections import Counter


def select_candidate(profile: str, voter_idx: int, p: int, candidates: int) -> int:
    """Which candidate voter `voter_idx` picks, for the position-independent profiles.

    Returns a 0-based candidate index. `profile` is "uniform" or "skewed".

    Deterministic: the same voter and position always give the same vote, with
    no seed and no state. That is what lets a population be reproduced from its
    four parameters alone, and what makes the two generator paths agree.

    KNOWN LIMIT: both are round-robins, so every position ends up with the same
    multiset of totals — permutations of one another. A component that confused
    one contest for another would still satisfy E = 0. The "realistic" profile
    does not have this weakness; these two do.
    """
    if candidates <= 1:
        return 0

    if profile == "uniform":
        # Walk the candidate list; the +p offset rotates the assignment per
        # position so the positions are not literally identical.
        return (voter_idx + p) % candidates

    # Skewed: half the voters pick candidate 0; the rest spread over 1..C.
    if voter_idx % 2 == 0:
        return 0
    return 1 + ((voter_idx // 2 + p) % (candidates - 1))


def realistic_quotas(voters: int, candidates: int, p: int):
    """Per-position vote quotas for the "realistic" profile.

    Returns `candidates` counts summing to EXACTLY `voters`, with a clear winner
    always and every rank distinct once the electorate can afford it.

    The shape stays deliberately close to "skewed", because the only thing wrong
    with skewed was the ties. Most of the electorate votes by that same rule,
    unchanged; a reserved slice is then apportioned by a simple descending
    weight w_k = C - k, which separates the candidates the round-robin had left
    level with one another.

    The reserved share widens with the position (10%, 15%, 20%), so the three
    races usually come out with different spreads. That is NOT guaranteed —
    see the note in the module docstring.

    All integer arithmetic, so the result does not depend on the machine.
    """
    c = candidates
    if c == 0:
        return []

    # The reserved slice must be at least C(C+1) — two per adjacent rank — or
    # the spread would be finer than the round-robin's own one-vote wobble and
    # could leave two candidates level anyway.
    pct = 10 + 5 * (p % 3)
    reserve = min(max(voters * pct // 100, c * (c + 1)), voters)
    base_voters = voters - reserve

    # Everyone outside the reserved slice votes by the existing skewed rule,
    # untouched — this is what keeps the distribution recognisably the old one.
    q = [0] * c
    for v in range(base_voters):
        q[select_candidate("skewed", v, p, c)] += 1

    # Apportion the reserved slice down the ranks.
    w = [c - k for k in range(c)]
    total = sum(w)
    a = [reserve * x // total for x in w]
    for k in range(reserve - sum(a)):
        a[k % c] += 1
    for k in range(c):
        q[k] += a[k]

    # A race must produce a winner even when the electorate is too small for the
    # apportionment to separate the top two.
    if c > 1 and q[0] <= q[1]:
        for k in range(c - 1, 0, -1):
            if q[k] > 0:
                q[k] -= 1
                q[0] += 1
                break
    return q


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _interleave_stride(voters: int) -> int:
    """A stride coprime to the voter count, so multiplying permutes the voters.

    Without it the quota brackets would hand the first block of voters to
    candidate 0, the next block to candidate 1, and the exported table would
    read as sorted runs instead of an electorate. Coprimality is what keeps the
    multiply a permutation, and therefore leaves the counts exactly intact.
    """
    if voters <= 2:
        return 1
    # Golden-ratio stride: consecutive voters land far apart across the range.
    s = max(voters * 61803 // 100000, 1)
    tries = 0
    while _gcd(s, voters) != 1 and tries <= voters:
        s += 1
        if s >= voters:
            s = 1
        tries += 1
    return max(s, 1)


class SelectionPlan:
    """Precomputed selection state, built once per generation run.

    "realistic" needs a whole position's quotas before it can place a single
    voter, so recomputing them per voter would be O(V*C log C) — untenable at
    the 3.5M tier. Quotas are computed once and each voter answered by a
    bisect over the cumulative brackets.
    """

    def __init__(self, profile: str, voters: int, positions: int, candidates: int):
        self.profile = profile
        self.voters = voters
        self.candidates = candidates
        self.cum = []
        if profile == "realistic" and candidates > 1:
            for p in range(positions):
                running, cum = 0, []
                for n in realistic_quotas(voters, candidates, p):
                    running += n
                    cum.append(running)
                self.cum.append(cum)
        self.stride = _interleave_stride(voters)

    def select(self, voter_idx: int, p: int) -> int:
        """Which candidate voter `voter_idx` picks for position `p`."""
        if self.candidates <= 1:
            return 0
        if self.profile != "realistic":
            return select_candidate(self.profile, voter_idx, p, self.candidates)
        cum = self.cum[p % len(self.cum)]
        r = (voter_idx * self.stride + p) % self.voters
        # The first bracket strictly greater than r owns this voter.
        lo, hi = 0, len(cum)
        while lo < hi:
            mid = (lo + hi) // 2
            if cum[mid] <= r:
                lo = mid + 1
            else:
                hi = mid
        return min(lo, self.candidates - 1)


# ---------------------------------------------------------------------------
# Everything below is presentation: labels and file layout, matching the CSVs
# the Rust generator writes.
# ---------------------------------------------------------------------------

def position_name(p: int) -> str:
    """Column header for position `p` (uppercased, underscored)."""
    return {0: "PRESIDENT", 1: "VICE_PRESIDENT", 2: "SENATOR"}.get(p, f"POSITION_{p}")


def candidate_label(p: int, k: int) -> str:
    """Candidate label as it appears in both CSVs, e.g. CAND_PRES_01.

    `k` is the 0-based index; labels are 1-based so they read as ballot
    positions rather than array offsets.
    """
    prefix = {0: "PRES", 1: "VICE", 2: "SEN"}.get(p, f"POS{p}")
    return f"CAND_{prefix}_{k + 1:02d}"


def generate(voters: int, positions: int, candidates: int, distribution: str):
    """Yield each voter's row and accumulate the tally, in one pass."""
    counts = [Counter() for _ in range(positions)]
    complexity = "single" if positions == 1 else "multi"
    plan = SelectionPlan(distribution, voters, positions, candidates)

    for voter_idx in range(voters):
        picks = []
        for p in range(positions):
            k = plan.select(voter_idx, p)
            counts[p][k] += 1
            picks.append(candidate_label(p, k))
        yield [f"V-{voter_idx + 1:06d}", str(voters), complexity] + picks, counts


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--voters", type=int, required=True)
    ap.add_argument("--positions", type=int, default=3)
    ap.add_argument("--candidates", type=int, default=4)
    ap.add_argument("--distribution", choices=["uniform", "skewed", "realistic"],
                    default="uniform")
    ap.add_argument("--out-dir", default=None,
                    help="write the two CSVs here; omit to print the tally only")
    args = ap.parse_args()

    header = ["voter_id", "scale_group", "ballot_complexity"] + \
             [position_name(p) for p in range(args.positions)]

    rows_out = None
    if args.out_dir:
        import os
        os.makedirs(args.out_dir, exist_ok=True)
        rows_out = open(os.path.join(args.out_dir, "ground-truth-ballots.csv"),
                        "w", newline="", encoding="utf-8")
        rows_out.write(",".join(header) + "\n")

    counts = None
    for row, counts in generate(args.voters, args.positions, args.candidates,
                               args.distribution):
        if rows_out:
            rows_out.write(",".join(row) + "\n")
    if rows_out:
        rows_out.close()

    summary = ["position,candidate,ground_truth_count"]
    for p in range(args.positions):
        for k in range(args.candidates):
            summary.append(f"{position_name(p)},{candidate_label(p, k)},{counts[p][k]}")

    if args.out_dir:
        import os
        with open(os.path.join(args.out_dir, "ground-truth-summary.csv"),
                  "w", newline="", encoding="utf-8") as f:
            f.write("\n".join(summary) + "\n")
        print(f"wrote both tables to {args.out_dir}", file=sys.stderr)
    else:
        print("\n".join(summary))

    # Every position must total the voter count: one selection per voter, per
    # position, no abstention modelled.
    for p in range(args.positions):
        total = sum(counts[p].values())
        assert total == args.voters, f"position {p} totals {total}, expected {args.voters}"
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
