package campaign

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// jsonMarshal renders a protobuf message to compact JSON (bytes fields as
// base64) — the "actual value JSON" evidence embedded per ballot.
var jsonMarshal = protojson.MarshalOptions{UseProtoNames: true}

// sha256Hex returns the hex SHA-256 of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

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
		"ballot_sha256", "ballot_json",
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
		// ballot_json carries the ACTUAL encrypted values (ciphertext pad/data,
		// CDS proof branches, nullifier, commitment) so the row is self-verifying
		// evidence, not a summary. ballot_sha256 is the wire-byte fingerprint.
		bjson, err := jsonMarshal.Marshal(&b)
		if err != nil {
			return fmt.Errorf("json ballot %d: %w", i, err)
		}
		if err := w.Write([]string{
			strconv.Itoa(i),
			b.ElectionId,
			b.PositionId,
			hex.EncodeToString(b.VoterCredentialCommitment),
			nullifier,
			strconv.Itoa(len(b.Ciphertexts)),
			strconv.Itoa(len(b.WellFormednessProofs)),
			sha256Hex(raw),
			string(bjson),
		}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

// ballotsDigest returns a single SHA-256 over every ballot's wire bytes in
// order — a fingerprint of the whole ballot set for provenance.
func ballotsDigest(dir string) (string, error) {
	lines, err := readBallotLines(dir)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for i, line := range lines {
		raw, err := hex.DecodeString(line)
		if err != nil {
			return "", fmt.Errorf("ballot %d not hex: %w", i, err)
		}
		h.Write(raw)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
	Dkg                string   `json:"dkg"`             // hex DKGTranscript
	Tally              string   `json:"tally"`           // hex TallyResult
	IssuerPk           string   `json:"issuer_pk"`       // hex compressed point
	BindingContext     string   `json:"binding_context"` // hex NIZK domain
}

// runDigests returns the SHA-256 of the DKG transcript, the tally, and the
// whole ballot set for a run — the provenance hashes the correctness CSV carries
// so each row is bound to specific cryptographic artifacts. Best-effort: a
// missing header/ballots yields empty hashes rather than failing the phase.
func runDigests(dir string) (dkgHash, tallyHash, ballotsHash string) {
	var h electionHeader
	if readJSON(filepath.Join(dir, "header.json"), &h) == nil {
		dkgHash = hexDigest(h.Dkg)
		tallyHash = hexDigest(h.Tally)
	}
	if bh, err := ballotsDigest(dir); err == nil {
		ballotsHash = bh
	}
	return
}

// hexDigest returns the SHA-256 of the bytes a hex string decodes to (empty
// string in / empty hash out is fine for a missing field).
func hexDigest(hexStr string) string {
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return ""
	}
	return sha256Hex(raw)
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
	ballotsRoot, err := ballotsDigest(dir)
	if err != nil {
		return err
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
		// Provenance evidence: the cryptographic artifacts this run is bound to.
		"issuer_public_key", "binding_context", "dkg_sha256", "tally_sha256", "ballots_sha256",
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
		h.IssuerPk,
		h.BindingContext,
		hexDigest(h.Dkg),
		hexDigest(h.Tally),
		ballotsRoot,
	}); err != nil {
		return err
	}
	w.Flush()
	return w.Error()
}
