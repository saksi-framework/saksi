package campaign

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
// The dump is streamed: one nullifier page at a time, one GetBallot at a time,
// one line written out before the next is fetched. Nothing here holds the
// population.

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
// <runDir>/ledger/ and returns how many ballots it holds.
//
// Ballots are fetched one at a time, in the order ListNullifiers returns them,
// and each is written out before the next is asked for. A GetBallot failure
// aborts the dump on the spot: a partial ledger directory audited as if it were
// complete would report a false mismatch, which is worse than no answer.
func dumpLedger(runDir, electionID string, r ledgerReader) (int, error) {
	dir := filepath.Join(runDir, LedgerDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("create %s: %w", dir, err)
	}
	n, err := dumpLedgerBallots(dir, electionID, r)
	if err == nil {
		err = writeLedgerHeader(runDir, dir, electionID, n, r)
	}
	if err != nil {
		// Leave no half-dump behind: a prefix of the chain's ballots sitting
		// next to an earlier run's header is an artifact that would audit, and
		// lie. "not run" has to mean nothing is there.
		_ = os.RemoveAll(dir)
		return 0, err
	}
	return n, nil
}

func dumpLedgerBallots(dir, electionID string, r ledgerReader) (int, error) {
	f, err := os.Create(filepath.Join(dir, BallotsFile))
	if err != nil {
		return 0, fmt.Errorf("create ledger ballots: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	n := 0
	bookmark := ""
	for {
		page, err := r.ListNullifiers(electionID, nullifierPageSize, bookmark)
		if err != nil {
			return 0, fmt.Errorf("list committed nullifiers: %w", err)
		}
		for _, nul := range page.Nullifiers {
			line, err := r.GetBallot(electionID, nul)
			if err != nil {
				return 0, fmt.Errorf("get ballot %s: %w", nul, err)
			}
			if _, err := w.WriteString(line + "\n"); err != nil {
				return 0, fmt.Errorf("write ledger ballot: %w", err)
			}
			n++
		}
		// A repeated bookmark would page forever; the empty one ends the walk.
		if page.NextBookmark == "" || page.NextBookmark == bookmark {
			break
		}
		bookmark = page.NextBookmark
	}
	if err := w.Flush(); err != nil {
		return 0, fmt.Errorf("write ledger ballots: %w", err)
	}
	return n, nil
}

// writeLedgerHeader builds the ledger dump's header.json: the run's own header
// with every field the chain publishes replaced by what the chain actually
// holds.
//
// The fields left as the console wrote them are the ones that are NOT on the
// chain and never could be: ground_truth (the seeded plaintext totals — the
// whole point of the audit is that they are secret from the ledger), voter_ids
// (off-wire generation metadata, deliberately absent so on-chain unlinkability
// holds), issuer_pk, binding_context, and the display names. Copying those is
// what lets the same auditor score the chain's ballots; it is also the reason a
// ledger audit checks the CHAIN's ciphertexts against the console's ground
// truth, not the chain's ground truth against itself.
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
	h["election_id"] = electionID
	h["params"] = params
	h["dkg"] = dkg
	h["tally"] = tally
	h["partial_decryptions"] = chainPartials(electionID, params, r)
	h["n"] = n
	return writeJSON(filepath.Join(dir, headerFile), h)
}

// chainPartials collects the published partial decryptions by asking for every
// (contest, trustee) pair the election parameters declare. The chaincode has no
// list query for them, and a threshold election is expected to be missing
// some — so a pair the chain does not hold is skipped, not an error.
func chainPartials(electionID, paramsHex string, r ledgerReader) []string {
	var p pb.ElectionParameters
	raw, err := hex.DecodeString(paramsHex)
	if err != nil || proto.Unmarshal(raw, &p) != nil {
		return []string{}
	}
	out := []string{}
	for _, contest := range p.GetContestIds() {
		for _, trustee := range p.GetTrusteeIds() {
			if pd, err := r.GetPartialDecryption(electionID, contest, trustee); err == nil && pd != "" {
				out = append(out, pd)
			}
		}
	}
	return out
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

// nullifierSetDigest is the SHA-256 of a stream directory's nullifier set.
//
// Ballot lines are streamed one at a time; only the nullifiers are held, which
// is the same set the resume path already builds (nullifierIndex) and the
// smallest thing that can identify "the same ballots" across two orderings.
func nullifierSetDigest(dir string) (string, error) {
	var nulls []string
	err := scanBallotLines(dir, func(i int, line string) error {
		raw, err := hex.DecodeString(line)
		if err != nil {
			return fmt.Errorf("ballot %d is not hex: %w", i, err)
		}
		var b pb.Ballot
		if err := proto.Unmarshal(raw, &b); err != nil {
			return fmt.Errorf("decode ballot %d: %w", i, err)
		}
		nulls = append(nulls, hex.EncodeToString(b.GetCredentialPresentation().GetNullifier().GetValue()))
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(nulls)
	h := sha256.New()
	for _, n := range nulls {
		fmt.Fprintln(h, n)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

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
