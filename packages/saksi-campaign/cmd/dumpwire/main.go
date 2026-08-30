// dumpwire decodes a run's on-the-wire artifacts and prints every field with
// its real value, so documentation can show what is actually in a blob rather
// than describing the schema. Read-only; it never writes to the run folder.
//
//	go run ./cmd/dumpwire <run-dir>
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// short renders a long hex string as head…tail so a 32-byte point stays
// recognisable without flooding the page.
func short(b []byte, keep int) string {
	h := hex.EncodeToString(b)
	if len(h) <= keep*2+3 {
		return h
	}
	return h[:keep] + "…" + h[len(h)-keep:]
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dumpwire <run-dir>")
		os.Exit(2)
	}
	dir := os.Args[1]

	raw, err := os.ReadFile(filepath.Join(dir, "header.json"))
	must(err)
	var h struct {
		ElectionID         string   `json:"election_id"`
		Params             string   `json:"params"`
		DKG                string   `json:"dkg"`
		IssuerPK           string   `json:"issuer_pk"`
		BindingContext     string   `json:"binding_context"`
		PartialDecryptions []string `json:"partial_decryptions"`
		Tally              string   `json:"tally"`
		GroundTruth        []uint64 `json:"ground_truth"`
		VoterIDs           []string `json:"voter_ids"`
		N                  int      `json:"n"`
	}
	must(json.Unmarshal(raw, &h))

	out := map[string]any{}

	// --- election parameters ------------------------------------------------
	pRaw, err := hex.DecodeString(h.Params)
	must(err)
	var params pb.ElectionParameters
	must(proto.Unmarshal(pRaw, &params))
	out["params"] = map[string]any{
		"hex_len":     len(h.Params),
		"hex_preview": short(pRaw, 24),
		"version":     params.GetVersion(),
		"election_id": params.GetElectionId(),
		"contest_ids": params.GetContestIds()[:min(4, len(params.GetContestIds()))],
		"contest_n":   len(params.GetContestIds()),
		"trustee_ids": params.GetTrusteeIds(),
		"threshold":   params.GetThreshold(),
	}

	// --- DKG transcript -----------------------------------------------------
	dRaw, err := hex.DecodeString(h.DKG)
	must(err)
	var dkg pb.DKGTranscript
	must(proto.Unmarshal(dRaw, &dkg))
	tc := []map[string]any{}
	for _, t := range dkg.GetTrusteeCommitments() {
		cc := []string{}
		for _, c := range t.GetCoefficientCommitments() {
			cc = append(cc, short(c, 16))
		}
		tc = append(tc, map[string]any{
			"trustee_id": t.GetTrusteeId(),
			"coeffs":     cc,
			"coeff_n":    len(t.GetCoefficientCommitments()),
			"coeff_len":  len(t.GetCoefficientCommitments()[0]),
		})
	}
	out["dkg"] = map[string]any{
		"hex_len":     len(h.DKG),
		"version":     dkg.GetVersion(),
		"election_id": dkg.GetElectionId(),
		"threshold":   dkg.GetThreshold(),
		"trustees":    tc,
		"complaints":  len(dkg.GetComplaints()),
	}

	// --- first ballot -------------------------------------------------------
	bRaw, err := os.ReadFile(filepath.Join(dir, "ballots.ndjson"))
	must(err)
	lines := strings.Split(strings.TrimSpace(string(bRaw)), "\n")
	b0, err := hex.DecodeString(strings.TrimSpace(lines[0]))
	must(err)
	var ballot pb.Ballot
	must(proto.Unmarshal(b0, &ballot))

	cts := []map[string]any{}
	for i, c := range ballot.GetCiphertexts() {
		cts = append(cts, map[string]any{
			"i":       i,
			"pad":     short(c.GetPad(), 16),
			"data":    short(c.GetData(), 16),
			"pad_len": len(c.GetPad()),
		})
	}
	pr := ballot.GetWellFormednessProofs()[0]
	branches := []map[string]any{}
	for i, br := range pr.GetBranches() {
		branches = append(branches, map[string]any{
			"i":            i,
			"commitment_a": short(br.GetCommitmentA(), 12),
			"commitment_b": short(br.GetCommitmentB(), 12),
			"challenge":    short(br.GetChallenge(), 12),
			"response":     short(br.GetResponse(), 12),
		})
	}
	cp := ballot.GetCredentialPresentation()
	out["ballot"] = map[string]any{
		"line_1_hex_len":  len(lines[0]),
		"total_lines":     len(lines),
		"version":         ballot.GetVersion(),
		"election_id":     ballot.GetElectionId(),
		"position_id":     ballot.GetPositionId(),
		"ciphertext_n":    len(ballot.GetCiphertexts()),
		"ciphertexts":     cts[:min(3, len(cts))],
		"proof_n":         len(ballot.GetWellFormednessProofs()),
		"proof_branches":  branches,
		"cred_commitment": short(cp.GetCredentialCommitment(), 16),
		"issuer_pk":       short(cp.GetIssuerPublicKey(), 16),
		"pres_proof_len":  len(cp.GetPresentationProof()),
		"pres_proof":      short(cp.GetPresentationProof(), 16),
		"nullifier":       hex.EncodeToString(cp.GetNullifier().GetValue()),
		"nullifier_len":   len(cp.GetNullifier().GetValue()),
	}

	// second ballot's nullifier + position, to show they differ
	if len(lines) > 1 {
		b1, err := hex.DecodeString(strings.TrimSpace(lines[1]))
		must(err)
		var ballot1 pb.Ballot
		must(proto.Unmarshal(b1, &ballot1))
		out["ballot_2"] = map[string]any{
			"position_id": ballot1.GetPositionId(),
			"nullifier":   hex.EncodeToString(ballot1.GetCredentialPresentation().GetNullifier().GetValue()),
		}
	}

	// --- partial decryption -------------------------------------------------
	pdRaw, err := hex.DecodeString(h.PartialDecryptions[0])
	must(err)
	var pd pb.PartialDecryption
	must(proto.Unmarshal(pdRaw, &pd))
	out["partial"] = map[string]any{
		"count":        len(h.PartialDecryptions),
		"version":      pd.GetVersion(),
		"trustee_id":   pd.GetTrusteeId(),
		"contest_id":   pd.GetContestId(),
		"share":        short(pd.GetShare(), 16),
		"share_len":    len(pd.GetShare()),
		"cp_a":         short(pd.GetProof().GetCommitmentA(), 12),
		"cp_b":         short(pd.GetProof().GetCommitmentB(), 12),
		"cp_challenge": short(pd.GetProof().GetChallenge(), 12),
		"cp_response":  short(pd.GetProof().GetResponse(), 12),
	}

	// --- tally --------------------------------------------------------------
	tRaw, err := hex.DecodeString(h.Tally)
	must(err)
	var tally pb.TallyResult
	must(proto.Unmarshal(tRaw, &tally))
	out["tally"] = map[string]any{
		"hex_len":     len(h.Tally),
		"version":     tally.GetVersion(),
		"election_id": tally.GetElectionId(),
		"totals_n":    len(tally.GetTotals()),
		"totals_head": tally.GetTotals()[:min(12, len(tally.GetTotals()))],
		"partials_n":  len(tally.GetPartialDecryptions()),
	}

	out["header"] = map[string]any{
		"issuer_pk":       short(mustHex(h.IssuerPK), 16),
		"binding_context": string(mustHex(h.BindingContext)),
		"n":               h.N,
		"voter_ids_head":  h.VoterIDs[:min(3, len(h.VoterIDs))],
		"ground_truth":    h.GroundTruth[:min(12, len(h.GroundTruth))],
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	must(enc.Encode(out))
}

func mustHex(s string) []byte { b, err := hex.DecodeString(s); must(err); return b }

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
