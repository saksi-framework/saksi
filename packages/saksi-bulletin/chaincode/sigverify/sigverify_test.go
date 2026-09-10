package sigverify

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	saksiprotocolv1 "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// vectorEntry is one `trustee_id,verification_key_hex,signature_hex` line.
type vectorEntry struct {
	trusteeID       string
	verificationKey []byte
	signature       []byte
}

// tallyVector is the parsed cross-language tally-signature golden vector,
// written by the Rust saksi-auditor test `tally_signature_golden_vector`.
//
// Layout (see saksi-auditor/src/fixtures.rs, module `tally_signature_vector`):
//
//	1      dkg_transcript, hex of the canonical protobuf encoding
//	2      election_id, hex of its UTF-8 bytes
//	3      trustee_ids, comma-separated, in ElectionParameters order
//	4      totals, comma-separated decimal, in contest order
//	5      threshold, decimal
//	6..10  trustee_id,verification_key_hex,signature_hex  (trustee order)
//	11     negative,trustee_id,verification_key_hex,signature_hex
type tallyVector struct {
	transcript *saksiprotocolv1.DKGTranscript
	electionID string
	trusteeIDs []string
	totals     []uint64
	threshold  int
	entries    []vectorEntry
	negative   vectorEntry
}

// loadVector reads tally-sig-v1.hex the way credverify_test.go's loadVector
// reads credential-sig-v1.hex: straight off disk, no Rust involved.
func loadVector(t *testing.T) tallyVector {
	t.Helper()
	f, err := os.Open(filepath.Join(
		"..", "..", "..", "saksi-protocol", "test-vectors", "tally-sig-v1.hex",
	))
	if err != nil {
		t.Fatalf("read golden vector: %v", err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20) // the transcript line is long
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read golden vector: %v", err)
	}
	if len(lines) != 11 {
		t.Fatalf("golden vector has %d lines, want 11", len(lines))
	}

	unhex := func(s string) []byte {
		t.Helper()
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("decode hex %q: %v", s, err)
		}
		return b
	}

	var transcript saksiprotocolv1.DKGTranscript
	if err := proto.Unmarshal(unhex(lines[0]), &transcript); err != nil {
		t.Fatalf("decode DKG transcript: %v", err)
	}

	v := tallyVector{
		transcript: &transcript,
		electionID: string(unhex(lines[1])),
		trusteeIDs: strings.Split(lines[2], ","),
	}
	for _, field := range strings.Split(lines[3], ",") {
		n, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			t.Fatalf("parse total %q: %v", field, err)
		}
		v.totals = append(v.totals, n)
	}
	if v.threshold, err = strconv.Atoi(lines[4]); err != nil {
		t.Fatalf("parse threshold: %v", err)
	}

	entry := func(fields []string) vectorEntry {
		t.Helper()
		if len(fields) != 3 {
			t.Fatalf("entry line has %d fields, want 3", len(fields))
		}
		return vectorEntry{trusteeID: fields[0], verificationKey: unhex(fields[1]), signature: unhex(fields[2])}
	}
	for _, line := range lines[5:10] {
		v.entries = append(v.entries, entry(strings.Split(line, ",")))
	}
	negFields := strings.Split(lines[10], ",")
	if negFields[0] != "negative" {
		t.Fatalf("last line is %q, want a negative line", negFields[0])
	}
	v.negative = entry(negFields[1:])
	return v
}

// The vector's ids are opaque: a port that derived the share index by parsing
// the trustee id, or by sorting, would pass on numeric ids and break on real
// ones. Asserting the shape here keeps that hole closed if the vector is ever
// regenerated.
func TestVectorTrusteeIDsAreOpaque(t *testing.T) {
	v := loadVector(t)
	for _, id := range v.trusteeIDs {
		if _, err := strconv.ParseUint(id, 10, 64); err == nil {
			t.Fatalf("trustee id %q is numeric; the vector must not let an index-from-id port pass", id)
		}
	}
	if sorted := append([]string(nil), v.trusteeIDs...); isSorted(sorted) {
		t.Fatal("trustee ids are in sorted order; the vector must not let a sort-based port pass")
	}
}

func isSorted(ids []string) bool {
	for i := 1; i < len(ids); i++ {
		if ids[i-1] > ids[i] {
			return false
		}
	}
	return true
}

func TestTallySigContextMatchesRust(t *testing.T) {
	v := loadVector(t)
	want := []byte("saksi.tally.sig.v1")
	want = append(want, []byte(v.electionID)...)
	for _, total := range v.totals {
		var le [8]byte
		binary.LittleEndian.PutUint64(le[:], total)
		want = append(want, le[:]...)
	}
	if got := TallySigContext(v.electionID, v.totals); !bytes.Equal(got, want) {
		t.Fatalf("context = %x, want %x", got, want)
	}
}

func TestDeriveVerificationKeyMatchesVector(t *testing.T) {
	v := loadVector(t)
	for _, e := range v.entries {
		got, err := DeriveVerificationKey(v.transcript, v.trusteeIDs, e.trusteeID)
		if err != nil {
			t.Fatalf("derive key for %s: %v", e.trusteeID, err)
		}
		if !bytes.Equal(got, e.verificationKey) {
			t.Fatalf("verification key for %s = %x, want %x", e.trusteeID, got, e.verificationKey)
		}
	}
}

func TestDeriveVerificationKeyRejectsUnknownTrustee(t *testing.T) {
	v := loadVector(t)
	if _, err := DeriveVerificationKey(v.transcript, v.trusteeIDs, "trustee-zzz"); err == nil {
		t.Fatal("an id absent from trustee_ids must be rejected, not indexed")
	}
}

func TestDeriveVerificationKeyRejectsMalformedCommitment(t *testing.T) {
	v := loadVector(t)
	broken := proto.Clone(v.transcript).(*saksiprotocolv1.DKGTranscript)
	broken.TrusteeCommitments[0].CoefficientCommitments[0] = bytes.Repeat([]byte{0xff}, 32)
	if _, err := DeriveVerificationKey(broken, v.trusteeIDs, v.trusteeIDs[0]); err == nil {
		t.Fatal("a non-canonical coefficient commitment must be rejected")
	}
	short := proto.Clone(v.transcript).(*saksiprotocolv1.DKGTranscript)
	short.TrusteeCommitments[0].CoefficientCommitments[0] = []byte{1, 2, 3}
	if _, err := DeriveVerificationKey(short, v.trusteeIDs, v.trusteeIDs[0]); err == nil {
		t.Fatal("a short coefficient commitment must be rejected")
	}
}

func TestDeriveVerificationKeyRejectsEmptyTranscript(t *testing.T) {
	v := loadVector(t)
	empty := &saksiprotocolv1.DKGTranscript{ElectionId: v.electionID}
	if _, err := DeriveVerificationKey(empty, v.trusteeIDs, v.trusteeIDs[0]); err == nil {
		t.Fatal("a transcript with no trustee commitments must be rejected")
	}
}

// The whole point of the package: Go must agree with Rust byte for byte.
func TestVerifySchnorrAcceptsVectorSignatures(t *testing.T) {
	v := loadVector(t)
	ctx := TallySigContext(v.electionID, v.totals)
	for _, e := range v.entries {
		if err := VerifySchnorr(e.verificationKey, ctx, e.signature); err != nil {
			t.Fatalf("signature of %s must verify (Go must agree with Rust): %v", e.trusteeID, err)
		}
	}
}

// The negative line is a real signature by the same trustee over DIFFERENT
// totals: rejecting it is what proves the totals are actually bound.
func TestVerifySchnorrRejectsSignatureOverOtherTotals(t *testing.T) {
	v := loadVector(t)
	ctx := TallySigContext(v.electionID, v.totals)
	if err := VerifySchnorr(v.negative.verificationKey, ctx, v.negative.signature); err == nil {
		t.Fatal("a signature over other totals must not verify under the published totals")
	}
}

func TestVerifySchnorrRejectsWrongElectionID(t *testing.T) {
	v := loadVector(t)
	other := TallySigContext(v.electionID+"x", v.totals)
	if err := VerifySchnorr(v.entries[0].verificationKey, other, v.entries[0].signature); err == nil {
		t.Fatal("a different election id must not verify")
	}
}

func TestVerifySchnorrRejectsWrongKey(t *testing.T) {
	v := loadVector(t)
	ctx := TallySigContext(v.electionID, v.totals)
	if err := VerifySchnorr(v.entries[1].verificationKey, ctx, v.entries[0].signature); err == nil {
		t.Fatal("a signature must not verify under another trustee's key")
	}
}

func TestVerifySchnorrRejectsMalformedInput(t *testing.T) {
	v := loadVector(t)
	ctx := TallySigContext(v.electionID, v.totals)
	e := v.entries[0]

	tamperedCommitment := append([]byte(nil), e.signature...)
	tamperedCommitment[0] ^= 0x01
	tamperedResponse := append([]byte(nil), e.signature...)
	tamperedResponse[32] ^= 0x01

	cases := []struct {
		name   string
		key    []byte
		sig    []byte
		reason string
	}{
		{"short signature", e.verificationKey, e.signature[:63], "63 bytes"},
		{"long signature", e.verificationKey, append(append([]byte(nil), e.signature...), 0), "65 bytes"},
		{"short key", e.verificationKey[:31], e.signature, "31-byte key"},
		{"non-canonical key", bytes.Repeat([]byte{0xff}, 32), e.signature, "0xff key"},
		{"tampered commitment", e.verificationKey, tamperedCommitment, "flipped commitment bit"},
		{"tampered response", e.verificationKey, tamperedResponse, "flipped response bit"},
		{"non-canonical response", e.verificationKey, append(append([]byte(nil), e.signature[:32]...), bytes.Repeat([]byte{0xff}, 32)...), "0xff scalar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifySchnorr(tc.key, ctx, tc.sig); err == nil {
				t.Fatalf("%s must be rejected", tc.reason)
			}
		})
	}
}
