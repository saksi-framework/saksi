package cdsverify

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// goldenVector is the parsed cross-language CDS golden vector produced by the
// Rust saksi-crypto test `cds_golden_vector`.
type goldenVector struct {
	electionID string
	contestID  string
	nullifier  []byte
	pk         []byte
	pad        []byte
	data       []byte
	branches   []Branch
}

func loadVector(t *testing.T) goldenVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(
		"..", "..", "..", "saksi-protocol", "test-vectors", "cds-proof-v1.hex",
	))
	if err != nil {
		t.Fatalf("read golden vector: %v", err)
	}
	buf, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		t.Fatalf("decode golden vector hex: %v", err)
	}

	off := 0
	readLP := func() []byte {
		n := int(binary.BigEndian.Uint64(buf[off : off+8]))
		off += 8
		s := buf[off : off+n]
		off += n
		return s
	}
	next := func(n int) []byte {
		s := buf[off : off+n]
		off += n
		return s
	}

	var gv goldenVector
	gv.electionID = string(readLP())
	gv.contestID = string(readLP())
	gv.nullifier = next(32)
	gv.pk = next(32)
	gv.pad = next(32)
	gv.data = next(32)
	numBranches := int(buf[off])
	off++
	for i := 0; i < numBranches; i++ {
		gv.branches = append(gv.branches, Branch{
			CommitmentA: next(32),
			CommitmentB: next(32),
			Challenge:   next(32),
			Response:    next(32),
		})
	}
	if off != len(buf) {
		t.Fatalf("golden vector has %d trailing bytes", len(buf)-off)
	}
	return gv
}

func TestVerifyBinaryCDSAcceptsGoldenVector(t *testing.T) {
	gv := loadVector(t)
	if err := VerifyBinaryCDS(gv.electionID, gv.contestID, gv.nullifier, gv.pk, gv.pad, gv.data, gv.branches); err != nil {
		t.Fatalf("golden vector must verify (Go must agree byte-for-byte with Rust): %v", err)
	}
}

func TestVerifyBinaryCDSRejectsTamper(t *testing.T) {
	base := loadVector(t)

	run := func(name string, mutate func(g *goldenVector)) {
		t.Run(name, func(t *testing.T) {
			g := loadVector(t) // fresh copy
			mutate(&g)
			if err := VerifyBinaryCDS(g.electionID, g.contestID, g.nullifier, g.pk, g.pad, g.data, g.branches); err == nil {
				t.Fatalf("%s must be rejected", name)
			}
		})
	}

	run("tampered pk", func(g *goldenVector) { g.pk = flip(g.pk) })
	run("tampered pad", func(g *goldenVector) { g.pad = flip(g.pad) })
	run("tampered data", func(g *goldenVector) { g.data = flip(g.data) })
	run("tampered nullifier", func(g *goldenVector) { g.nullifier = flip(g.nullifier) })
	run("wrong contest_id", func(g *goldenVector) { g.contestID = "contest-2" })
	run("wrong election_id", func(g *goldenVector) { g.electionID = "election-2027" })
	run("tampered branch commitment_a", func(g *goldenVector) { g.branches[0].CommitmentA = flip(g.branches[0].CommitmentA) })
	run("tampered branch challenge", func(g *goldenVector) { g.branches[0].Challenge = flip(g.branches[0].Challenge) })
	run("tampered branch response", func(g *goldenVector) { g.branches[1].Response = flip(g.branches[1].Response) })
	run("swapped branches", func(g *goldenVector) { g.branches[0], g.branches[1] = g.branches[1], g.branches[0] })

	_ = base
}

func TestVerifyBinaryCDSRejectsNonCanonical(t *testing.T) {
	gv := loadVector(t)
	// 0xff*32 is not a canonical ristretto255 point/scalar; the decoder must
	// reject it deterministically (no panic, returns error).
	bad := bytes.Repeat([]byte{0xff}, 32)
	gv.pad = bad
	if err := VerifyBinaryCDS(gv.electionID, gv.contestID, gv.nullifier, gv.pk, gv.pad, gv.data, gv.branches); err == nil {
		t.Fatal("non-canonical ciphertext pad must be rejected")
	}
}

func TestVerifyBinaryCDSRejectsWrongBranchCount(t *testing.T) {
	gv := loadVector(t)
	if err := VerifyBinaryCDS(gv.electionID, gv.contestID, gv.nullifier, gv.pk, gv.pad, gv.data, gv.branches[:1]); err == nil {
		t.Fatal("a proof with != 2 branches must be rejected")
	}
}

func flip(b []byte) []byte {
	out := append([]byte(nil), b...)
	out[0] ^= 0x01
	return out
}
