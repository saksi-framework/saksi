package selectionverify

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// vector is the Rust-produced golden vector (saksi-crypto
// `selection_golden_vector`); see that test for the layout.
type vector struct {
	electionID, positionID string
	nullifier, pk          []byte
	pads, datas            [][]byte
	proof                  Proof
	overPads, overDatas    [][]byte
}

func loadVector(t testing.TB) vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "saksi-protocol", "test-vectors", "selection-proof-v1.hex"))
	if err != nil {
		t.Fatalf("read golden vector: %v", err)
	}
	buf, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		t.Fatalf("decode golden vector: %v", err)
	}
	off := 0
	next := func(n int) []byte { s := buf[off : off+n]; off += n; return s }
	readLP := func() []byte { return next(int(binary.BigEndian.Uint64(next(8)))) }
	var v vector
	v.electionID = string(readLP())
	v.positionID = string(readLP())
	v.nullifier = next(32)
	v.pk = next(32)
	n := int(next(1)[0])
	records := func() (pads, datas [][]byte) {
		for k := 0; k < n; k++ {
			pads = append(pads, next(32))
			datas = append(datas, next(32))
			next(2 * 128) // CDS branches: used by the chaincode tests
		}
		return
	}
	v.pads, v.datas = records()
	v.proof = Proof{next(32), next(32), next(32), next(32)}
	v.overPads, v.overDatas = records()
	if off != len(buf) {
		t.Fatalf("golden vector has %d trailing bytes", len(buf)-off)
	}
	return v
}

func TestGoldenVectorVerifies(t *testing.T) {
	v := loadVector(t)
	if err := Verify(v.electionID, v.positionID, v.nullifier, v.pk, v.pads, v.datas, v.proof); err != nil {
		t.Fatalf("golden vector must verify (Go must agree byte-for-byte with Rust): %v", err)
	}
}

func TestOvervoteFails(t *testing.T) {
	v := loadVector(t)
	if err := Verify(v.electionID, v.positionID, v.nullifier, v.pk, v.overPads, v.overDatas, v.proof); err == nil {
		t.Fatal("an overvote record must not verify under the honest proof")
	}
}

func TestWrongContextFails(t *testing.T) {
	v := loadVector(t)
	if err := Verify(v.electionID, "p1", v.nullifier, v.pk, v.pads, v.datas, v.proof); err == nil {
		t.Fatal("a proof bound to another position must not verify")
	}
}

func TestTamperFails(t *testing.T) {
	v := loadVector(t)
	for i, field := range [][]byte{v.proof.CommitmentA, v.proof.CommitmentB, v.proof.Challenge, v.proof.Response} {
		orig := field[0]
		field[0] ^= 0x01
		if err := Verify(v.electionID, v.positionID, v.nullifier, v.pk, v.pads, v.datas, v.proof); err == nil {
			t.Errorf("tampered field %d still verifies", i)
		}
		field[0] = orig
	}
	if err := Verify(v.electionID, v.positionID, v.nullifier, v.pk, nil, nil, v.proof); err == nil {
		t.Error("an empty record must not verify")
	}
}

// BenchmarkVerify measures the per-record cost the selection gate adds.
func BenchmarkVerify(b *testing.B) {
	v := loadVector(b)
	for i := 0; i < b.N; i++ {
		if err := Verify(v.electionID, v.positionID, v.nullifier, v.pk, v.pads, v.datas, v.proof); err != nil {
			b.Fatal(err)
		}
	}
}
