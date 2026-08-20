package campaign

import (
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// Derived CSV exports, written after Generate so every artifact a researcher
// downloads is a proper spreadsheet (the raw header.json + ballots.ndjson stay
// for the auditor / re-audit, but the study data is CSV).
const (
	BallotsCSV  = "ballots.csv"
	ElectionCSV = "election.csv"
)

// writeDerivedCSVs flattens the generated stream (header.json + ballots.ndjson)
// into ballots.csv + election.csv.
func writeDerivedCSVs(dir string, c ElectionConfig) error {
	if err := writeBallotsCSV(dir); err != nil {
		return err
	}
	return writeElectionCSV(dir, c)
}

// writeBallotsCSV decodes each ballot (hex protobuf) and writes one row per
// ballot: the fields that make a ballot auditable in a spreadsheet (position,
// nullifier, commitment, and the ciphertext/proof counts). The raw encrypted
// bytes stay in ballots.ndjson — they are opaque without keys, so a CSV of them
// would not be analyzable.
func writeBallotsCSV(dir string) error {
	lines, err := readBallotLines(dir)
	if err != nil {
		return fmt.Errorf("read ballots: %w", err)
	}
	f, err := os.Create(filepath.Join(dir, BallotsCSV))
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write([]string{
		"index", "election_id", "position_id",
		"voter_credential_commitment", "nullifier",
		"num_ciphertexts", "num_wellformedness_proofs",
	}); err != nil {
		return err
	}
	for i, line := range lines {
		raw, err := hex.DecodeString(line)
		if err != nil {
			return fmt.Errorf("ballot %d not hex: %w", i, err)
		}
		var b pb.Ballot
		if err := proto.Unmarshal(raw, &b); err != nil {
			return fmt.Errorf("decode ballot %d: %w", i, err)
		}
		nullifier := ""
		if b.CredentialPresentation != nil && b.CredentialPresentation.Nullifier != nil {
			nullifier = hex.EncodeToString(b.CredentialPresentation.Nullifier.Value)
		}
		if err := w.Write([]string{
			strconv.Itoa(i),
			b.ElectionId,
			b.PositionId,
			hex.EncodeToString(b.VoterCredentialCommitment),
			nullifier,
			strconv.Itoa(len(b.Ciphertexts)),
			strconv.Itoa(len(b.WellFormednessProofs)),
		}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

// electionHeader is the subset of header.json election.csv needs.
type electionHeader struct {
	ElectionID         string   `json:"election_id"`
	ElectionName       string   `json:"election_name"`
	TrusteeNames       []string `json:"trustee_names"`
	PartialDecryptions []string `json:"partial_decryptions"`
	GroundTruth        []uint64 `json:"ground_truth"`
	Positions          int      `json:"positions"`
	Candidates         int      `json:"candidates"`
	N                  int      `json:"n"`
}

// writeElectionCSV writes a single-row summary of the election — the shape a
// researcher aggregates across runs. Config is authoritative for t-of-n and
// voters; the header supplies the generated counts.
func writeElectionCSV(dir string, c ElectionConfig) error {
	var h electionHeader
	if err := readJSON(filepath.Join(dir, "header.json"), &h); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	var gtTotal uint64
	for _, v := range h.GroundTruth {
		gtTotal += v
	}

	f, err := os.Create(filepath.Join(dir, ElectionCSV))
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write([]string{
		"election_id", "election_name", "trustees", "threshold",
		"positions", "candidates", "voters", "num_ballots",
		"num_partial_decryptions", "ground_truth_total", "distribution", "mode", "trustee_names",
	}); err != nil {
		return err
	}
	if err := w.Write([]string{
		h.ElectionID,
		h.ElectionName,
		strconv.Itoa(len(c.Trustees)),
		strconv.Itoa(c.Threshold),
		strconv.Itoa(c.Positions),
		strconv.Itoa(c.Candidates),
		strconv.Itoa(c.Voters),
		strconv.Itoa(h.N),
		strconv.Itoa(len(h.PartialDecryptions)),
		strconv.FormatUint(gtTotal, 10),
		c.Distribution,
		c.Mode,
		strings.Join(h.TrusteeNames, "; "),
	}); err != nil {
		return err
	}
	w.Flush()
	return w.Error()
}
