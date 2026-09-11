package campaign

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// The ledger audit.
//
// Everything a run publishes about itself is written by the console: it
// generated the ballots, it submitted them, and it audits the directory it
// wrote. That proves the crypto is sound; it proves nothing about the CHAIN,
// which is the thing a reader is being asked to trust. So an on-chain run
// re-derives the whole record from the ledger — ListNullifiers, GetBallot per
// nullifier, GetElection/DKG/partials/tally — audits THAT directory with the
// same auditor, and reports whether the two agree.
//
// The dump is streamed: one nullifier page at a time, one page of ballots
// fetched at a time, each line written out before the next page is asked for.
// Nothing here holds the population.

// LedgerDir is the run-folder-relative directory holding the chain's own copy
// of a run: the ballots GetBallot returned, plus a header rebuilt from the
// on-chain election parameters, DKG transcript, partial decryptions and tally.
//
// The two files inside are named header.json and ballots.ndjson — not
// ledger-header.json / ledger-ballots.ndjson — because saksi-auditor hard-codes
// those names (HEADER_FILE / BALLOTS_FILE in saksi-auditor/src/stream.rs) and
// `audit-stream <dir>` has to accept this directory. The "ledger" half of the
// name lives in the directory instead.
const LedgerDir = "ledger"

// headerFile is the stream header both the console-written run folder and the
// ledger dump use. Fixed by saksi-auditor's reader.
const headerFile = "header.json"

// ledgerReader is everything the ledger audit needs from the chain: the
// committed nullifier set, the ballot behind each one, and the election's
// published artifacts. *clientsdk.BulletinClient satisfies it.
type ledgerReader interface {
	nullifierLister
	GetBallot(electionID, nullifier string) (string, error)
	// GetBallots is the batched form: the ballots for a page of nullifiers, in
	// the order given, absent ones as empty strings. Chaincode older than this
	// function reports it as unknown, which the dump falls back from.
	GetBallots(electionID string, nullifiers []string) ([]string, error)
	GetElection(electionID string) (string, error)
	GetDKGTranscript(electionID string) (string, error)
	GetPartialDecryption(electionID, contestID, trusteeID string) (string, error)
	GetTally(electionID string) (string, error)
}

var _ ledgerReader = (*clientsdk.BulletinClient)(nil)

// ledgerCheck is the ledger audit's outcome, threaded into correctness.csv and
// run.end. A nil *ledgerCheck means there was no chain to audit at all (an
// offline run, or no reachable network) — distinct from status "not run",
// which means there WAS one and the dump failed.
type ledgerCheck struct {
	status  string      // "ok" | "not run"
	audit   StreamAudit // the chain's own audit; only meaningful when status == "ok"
	matches string      // "true" | "false"; empty unless the comparison ran
}

// dumpLedger writes the chain's own record of electionID into
// <runDir>/ledger/ and returns how many ballots it holds and which read path
// served them (see dumpLedgerBallots).
//
// Ballots are fetched a page at a time, in the order ListNullifiers returns
// them, and each page is written out before the next is asked for. A read
// failure aborts the dump on the spot: a partial ledger directory audited as if
// it were complete would report a false mismatch, which is worse than no
// answer.
func dumpLedger(runDir, electionID string, r ledgerReader) (int, string, error) {
	dir := filepath.Join(runDir, LedgerDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, "", fmt.Errorf("create %s: %w", dir, err)
	}
	n, path, err := dumpLedgerBallots(dir, electionID, r)
	if err == nil {
		err = writeLedgerHeader(runDir, dir, electionID, n, r)
	}
	if err != nil {
		// Leave no half-dump behind: a prefix of the chain's ballots sitting
		// next to an earlier run's header is an artifact that would audit, and
		// lie. "not run" has to mean nothing is there.
		_ = os.RemoveAll(dir)
		return 0, "", err
	}
	return n, path, nil
}

// The two read paths dumpLedgerBallots can take, journalled so a reader of a
// run folder can tell which one produced it.
const (
	ledgerReadBatched   = "batched"
	ledgerReadPerBallot = "per-ballot"
)

// dumpLedgerBallots writes the chain's ballots, in ListNullifiers order, and
// reports the count and the read path it used.
//
// The read is batched: each ListNullifiers page is fetched in GetBallots pages
// of clientsdk.BallotBatchSize, which is one gateway round trip per 500 ballots
// instead of one per ballot. That per-ballot round trip measured ~3.3 ms end to
// end — about half of Verify's whole per-ballot cost, and hours of it at the
// large tiers — and it buys nothing: the dump already knows every nullifier it
// wants before it asks for the first ballot.
//
// Chaincode older than GetBallots reports the function as unknown, and the dump
// then falls back to GetBallot for the rest of the run and says so in its
// return. The two paths are byte-identical by construction: same nullifier
// order, same hex, same one-line-per-ballot framing.
func dumpLedgerBallots(dir, electionID string, r ledgerReader) (int, string, error) {
	f, err := os.Create(filepath.Join(dir, BallotsFile))
	if err != nil {
		return 0, "", fmt.Errorf("create ledger ballots: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	n := 0
	bookmark := ""
	batched := true
	for {
		page, err := r.ListNullifiers(electionID, nullifierPageSize, bookmark)
		if err != nil {
			return 0, "", fmt.Errorf("list committed nullifiers: %w", err)
		}
		for rest := page.Nullifiers; len(rest) > 0; {
			take := len(rest)
			if batched && take > clientsdk.BallotBatchSize {
				take = clientsdk.BallotBatchSize
			}
			chunk := rest[:take]

			var lines []string
			if batched {
				lines, err = r.GetBallots(electionID, chunk)
				if clientsdk.UnknownChaincodeFunction(err) {
					// Older chaincode. Redo this chunk one ballot at a time and
					// stay on that path for the rest of the dump.
					batched, err = false, nil
					continue
				}
				if err != nil {
					return 0, "", fmt.Errorf("get ballots: %w", err)
				}
			} else {
				lines = make([]string, len(chunk))
				for i, nul := range chunk {
					if lines[i], err = r.GetBallot(electionID, nul); err != nil {
						return 0, "", fmt.Errorf("get ballot %s: %w", nul, err)
					}
				}
			}

			for i, line := range lines {
				// The batched read marks an absent ballot with an empty entry.
				// Here that is a fault, not a tolerable gap: every nullifier in
				// this chunk was reported committed moments ago, so a missing
				// ballot means the chain and its own index disagree — the same
				// condition GetBallot fails on, reported the same way.
				if line == "" {
					return 0, "", fmt.Errorf(
						"get ballot %s: the chain holds no ballot for a nullifier it lists as committed", chunk[i])
				}
				if _, err := w.WriteString(line + "\n"); err != nil {
					return 0, "", fmt.Errorf("write ledger ballot: %w", err)
				}
				n++
			}
			rest = rest[take:]
		}
		// A repeated bookmark would page forever; the empty one ends the walk.
		if page.NextBookmark == "" || page.NextBookmark == bookmark {
			break
		}
		bookmark = page.NextBookmark
	}
	if err := w.Flush(); err != nil {
		return 0, "", fmt.Errorf("write ledger ballots: %w", err)
	}
	if batched {
		return n, ledgerReadBatched, nil
	}
	return n, ledgerReadPerBallot, nil
}

// writeLedgerHeader builds the ledger dump's header.json: the run's own header
// with every field the chain publishes replaced by what the chain actually
// holds.
//
// The fields left as the console wrote them are the ones that are NOT on the
// chain and never could be: ground_truth (the seeded plaintext totals — the
// whole point of the audit is that they are secret from the ledger),
// issuer_pk, binding_context, and the display names. Copying those is what lets
// the same auditor score the chain's ballots; it is also the reason a ledger
// audit checks the CHAIN's ciphertexts against the console's ground truth, not
// the chain's ground truth against itself.
//
// voter_ids is the one such field that cannot simply be copied: the chain
// publishes none, and the auditor requires one per ballot. See ledgerVoterIDs.
func writeLedgerHeader(runDir, dir, electionID string, n int, r ledgerReader) error {
	var h map[string]any
	if err := readJSON(filepath.Join(runDir, headerFile), &h); err != nil {
		return fmt.Errorf("read %s to build the ledger header: %w", headerFile, err)
	}
	params, err := r.GetElection(electionID)
	if err != nil {
		return fmt.Errorf("get election: %w", err)
	}
	dkg, err := r.GetDKGTranscript(electionID)
	if err != nil {
		return fmt.Errorf("get DKG transcript: %w", err)
	}
	tally, err := r.GetTally(electionID)
	if err != nil {
		return fmt.Errorf("get tally: %w", err)
	}
	partials, err := chainPartials(electionID, params, r)
	if err != nil {
		return err
	}
	h["election_id"] = electionID
	h["params"] = params
	h["dkg"] = dkg
	h["tally"] = tally
	h["partial_decryptions"] = partials
	h["n"] = n
	h["voter_ids"] = ledgerVoterIDs(h["voter_ids"], n)
	return writeJSON(filepath.Join(dir, headerFile), h)
}

// ledgerVoterIDs resizes the console's voter-id list to exactly n entries, n
// being the CHAIN's ballot count.
//
// The chain publishes no voter ids at all — they are off-wire generation
// metadata, deliberately absent so on-chain unlinkability holds — so there is
// nothing to copy from it and nothing to check against. What there is instead
// is the v1 header contract: voter_ids holds one entry per ballot, which
// saksi-auditor's stream.rs verify_stream enforces and rejects a header for.
// The console's list is sized to the population it GENERATED, which is exactly
// not the chain's count in the two cases that matter — a chain holding a
// different number of ballots (the divergence this audit exists to catch) and
// any time-bounded window (the normal state of every sweep step). Copying it
// unresized therefore writes a dump whose header claims voter ids for ballots
// the directory does not contain.
//
// `audit-stream` reads the header without calling verify_stream today, so the
// mis-sized list is not yet load-bearing on that path. It is written correctly
// anyway: the dump is a published artifact that claims to be a v1 stream
// directory, and any reader that does enforce the contract — verify_stream
// itself, or the auditor's own population gates — would reject it.
//
// So the list is truncated to n, or padded with placeholders naming what they
// are. The ids are labels here: the ledger audit compares nullifier sets and
// aggregate ciphertexts, never voter ids, and the chain's ballots come back in
// the chain's order anyway, so a positional id would be meaningless even if one
// existed. Placeholders are distinct so no per-voter uniqueness check can be
// tripped by the padding itself.
func ledgerVoterIDs(local any, n int) []string {
	out := make([]string, 0, n)
	if ids, ok := local.([]any); ok {
		for _, id := range ids {
			if len(out) == n {
				break
			}
			s, _ := id.(string)
			out = append(out, s)
		}
	}
	for len(out) < n {
		out = append(out, fmt.Sprintf("chain-publishes-none-%d", len(out)))
	}
	return out
}

// chainPartials collects the published partial decryptions by asking for every
// (contest, trustee) pair the election parameters declare. The chaincode has no
// list query for them.
//
// A pair the chain does not hold is skipped: a threshold election is expected
// to be missing some, and that is the one absence that is not a fault. On-chain
// parameters that do not decode ARE a fault — without them there is no list of
// pairs to ask about, so the header would silently claim the election published
// no partial decryptions at all.
func chainPartials(electionID, paramsHex string, r ledgerReader) ([]string, error) {
	raw, err := hex.DecodeString(paramsHex)
	if err != nil {
		return nil, fmt.Errorf("on-chain election parameters are not hex: %w", err)
	}
	var p pb.ElectionParameters
	if err := proto.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("decode on-chain election parameters: %w", err)
	}
	out := []string{}
	for _, contest := range p.GetContestIds() {
		for _, trustee := range p.GetTrusteeIds() {
			if pd, err := r.GetPartialDecryption(electionID, contest, trustee); err == nil && pd != "" {
				out = append(out, pd)
			}
		}
	}
	return out, nil
}

// compareLedger reports whether the chain's record and the console's are the
// same election: the same set of ballots (by nullifier) and the same recovered
// per-contest aggregate ciphertexts.
//
// Both halves are order-independent by construction — the chain returns
// nullifiers in its own order, and contests come back in whatever order the
// auditor emits them — so each side is sorted before it is digested.
func compareLedger(runDir string, local, ledger StreamAudit) (bool, error) {
	localNulls, err := nullifierSetDigest(runDir)
	if err != nil {
		return false, err
	}
	ledgerNulls, err := nullifierSetDigest(filepath.Join(runDir, LedgerDir))
	if err != nil {
		return false, err
	}
	return localNulls == ledgerNulls && aggregateDigest(local) == aggregateDigest(ledger), nil
}

// nullifierSetDigest identifies a stream directory's nullifier set, independent
// of the order the ballots happen to be written in.
//
// Sorting would need the whole set resident — at 1M ballots that is tens of
// megabytes held only to be thrown away — so the combination is commutative
// instead: each nullifier is hashed to a 256-bit value and those are ADDED
// modulo 2^256. Addition does not care what order it sees its terms in, so one
// running total and a count is the entire state, whatever the population size.
// The count is folded into the final hash so that a set and a differently-sized
// set that happens to sum the same cannot collide.
//
// Duplicate nullifiers are not this function's job: the auditor's
// nullifier.unique check is what rejects a double vote, on both directories.
func nullifierSetDigest(dir string) (string, error) {
	sum := new(big.Int)
	count := uint64(0)
	err := scanBallotLines(dir, func(i int, line string) error {
		raw, err := hex.DecodeString(line)
		if err != nil {
			return fmt.Errorf("ballot %d is not hex: %w", i, err)
		}
		var b pb.Ballot
		if err := proto.Unmarshal(raw, &b); err != nil {
			return fmt.Errorf("decode ballot %d: %w", i, err)
		}
		term := sha256.Sum256(b.GetCredentialPresentation().GetNullifier().GetValue())
		sum.Add(sum, new(big.Int).SetBytes(term[:]))
		count++
		return nil
	})
	if err != nil {
		return "", err
	}
	// Reduce to exactly 32 bytes: the running total can carry past 2^256, and a
	// digest that changed width with the population would not be comparable.
	var total [32]byte
	sum.Mod(sum, twoTo256).FillBytes(total[:])

	h := sha256.New()
	_ = binary.Write(h, binary.LittleEndian, count)
	h.Write(total[:])
	return hex.EncodeToString(h.Sum(nil)), nil
}

// twoTo256 is the modulus the nullifier sum is reduced by, so the accumulator
// stays a fixed 32 bytes however many ballots it has seen.
var twoTo256 = new(big.Int).Lsh(big.NewInt(1), 256)

// aggregateDigest is the SHA-256 of an audit's per-contest aggregate
// ciphertexts — the homomorphic sum the tally was decrypted from, which is what
// binds the audit's verdict to the ballots it read.
func aggregateDigest(sa StreamAudit) string {
	rows := make([]string, 0, len(sa.Contests))
	for _, c := range sa.Contests {
		rows = append(rows, c.Contest+"="+c.AggregateCiphertext)
	}
	sort.Strings(rows)
	return sha256Hex([]byte(strings.Join(rows, "\n")))
}
