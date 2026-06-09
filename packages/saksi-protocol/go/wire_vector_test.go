package saksiprotocol_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestBallotVectorUsesStableFieldLayout(t *testing.T) {
	rawHex, err := os.ReadFile(filepath.Join("..", "test-vectors", "ballot-v1.hex"))
	if err != nil {
		t.Fatalf("read test vector: %v", err)
	}

	wire, err := hex.DecodeString(string(bytes.TrimSpace(rawHex)))
	if err != nil {
		t.Fatalf("decode hex vector: %v", err)
	}

	fields := map[protowire.Number]protowire.Type{}
	for len(wire) > 0 {
		number, typ, n := protowire.ConsumeTag(wire)
		if n < 0 {
			t.Fatalf("consume tag: %v", protowire.ParseError(n))
		}
		wire = wire[n:]
		valueLen := protowire.ConsumeFieldValue(number, typ, wire)
		if valueLen < 0 {
			t.Fatalf("consume field %d: %v", number, protowire.ParseError(valueLen))
		}
		fields[number] = typ
		wire = wire[valueLen:]
	}

	want := map[protowire.Number]protowire.Type{
		1: protowire.VarintType,
		2: protowire.BytesType,
		3: protowire.BytesType,
		4: protowire.BytesType,
		5: protowire.BytesType,
		6: protowire.BytesType,
	}

	for number, typ := range want {
		if fields[number] != typ {
			t.Fatalf("field %d type = %v, want %v", number, fields[number], typ)
		}
	}
}
