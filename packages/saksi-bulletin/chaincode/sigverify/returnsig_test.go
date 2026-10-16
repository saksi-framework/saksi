package sigverify

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// returnJSON is the return.json shape written by saksi-demo sign-return.
type returnJSON struct {
	ElectionID   string `json:"election_id"`
	PrecinctID   string `json:"precinct_id"`
	CloseBlock   uint64 `json:"close_block"`
	CloseTipHash string `json:"close_tip_hash"`
	RecordCount  uint64 `json:"record_count"`
	LedgerDigest string `json:"ledger_digest"`
	Contests     []struct {
		ContestID string `json:"contest_id"`
		SumC1     string `json:"sum_c1"`
		SumC2     string `json:"sum_c2"`
	} `json:"contests"`
	Signature string `json:"signature"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}

func (r returnJSON) message(t *testing.T) []byte {
	t.Helper()
	var cs []ReturnContest
	for _, c := range r.Contests {
		cs = append(cs, ReturnContest{c.ContestID, mustHex(t, c.SumC1), mustHex(t, c.SumC2)})
	}
	msg, err := ReturnSigMessage(r.ElectionID, r.PrecinctID, r.CloseBlock, mustHex(t, r.CloseTipHash),
		r.RecordCount, mustHex(t, r.LedgerDigest), cs)
	if err != nil {
		t.Fatalf("ReturnSigMessage: %v", err)
	}
	return msg
}

// TestReturnSigGoldenVector reads er-sig-v1.hex (written by saksi-auditor's
// return_signature_golden_vector): 1 secret, 2 public key, 3 return JSON,
// 4 message hex. The Go message must equal the Rust bytes and the signature
// must verify; the attack mutations must not.
func TestReturnSigGoldenVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "saksi-protocol", "test-vectors", "er-sig-v1.hex"))
	if err != nil {
		t.Fatalf("read golden vector: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(string(raw), "\r\n", "\n")), "\n")
	if len(lines) != 4 {
		t.Fatalf("golden vector has %d lines, want 4", len(lines))
	}
	pub := mustHex(t, lines[1])
	var r returnJSON
	if err := json.Unmarshal([]byte(lines[2]), &r); err != nil {
		t.Fatalf("parse return JSON: %v", err)
	}
	sig := mustHex(t, r.Signature)

	msg := r.message(t)
	if !bytes.Equal(msg, mustHex(t, lines[3])) {
		t.Fatalf("Go message differs from Rust:\n go   %x\n rust %s", msg, lines[3])
	}
	if err := VerifyReturnSig(msg, sig, pub); err != nil {
		t.Fatalf("golden signature must verify: %v", err)
	}

	mutations := map[string]func(*returnJSON){
		"T9 aggregate byte flipped": func(m *returnJSON) {
			b := mustHex(t, m.Contests[1].SumC2)
			b[0] ^= 1
			m.Contests[1].SumC2 = hex.EncodeToString(b)
		},
		"T12 precinct relabeled":  func(m *returnJSON) { m.PrecinctID = "p04" },
		"T14 election id changed": func(m *returnJSON) { m.ElectionID = "election-2025-p03" },
		"close block changed":     func(m *returnJSON) { m.CloseBlock++ },
	}
	for name, mutate := range mutations {
		m := r
		m.Contests = append(m.Contests[:0:0], r.Contests...)
		mutate(&m)
		if VerifyReturnSig(m.message(t), sig, pub) == nil {
			t.Errorf("%s: signature must not verify", name)
		}
	}
	// T21: the right message under another key (the basepoint G, i.e. secret 1).
	g := mustHex(t, "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76")
	if VerifyReturnSig(msg, sig, g) == nil {
		t.Error("T21: signature must not verify under another key")
	}
}
