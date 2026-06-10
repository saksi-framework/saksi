package saksiprotocol

// Hand-written Go mirror of the saksi.protocol.v1 wire messages.
//
// ADR-0003 calls for protoc-gen-go output, but the toolchain to regenerate is
// not yet wired into the build, so this file provides a focused, dependency-free
// encoder/decoder for the messages the bulletin board needs today. It encodes
// the same canonical proto3 bytes as the Rust `prost` types — the golden vector
// round-trip test (wire_golden_test.go) pins that equivalence against
// ../test-vectors/ballot-v1.hex. When protoc-gen-go is wired up, the generated
// types supersede this file.

import "google.golang.org/protobuf/encoding/protowire"

// WireVersion is the current wire-format version. Every message that crosses
// the trust boundary carries a version field initialized to this constant.
const WireVersion uint32 = 1

// Ciphertext mirrors saksi.protocol.v1.Ciphertext.
type Ciphertext struct {
	Version uint32
	Pad     []byte
	Data    []byte
}

// CDSProofBranch mirrors saksi.protocol.v1.CDSProofBranch.
type CDSProofBranch struct {
	CommitmentA []byte
	CommitmentB []byte
	Challenge   []byte
	Response    []byte
}

// CDSProof mirrors saksi.protocol.v1.CDSProof.
type CDSProof struct {
	Version  uint32
	Branches []*CDSProofBranch
}

// Nullifier mirrors saksi.protocol.v1.Nullifier.
type Nullifier struct {
	Version uint32
	Value   []byte
}

// CredentialPresentation mirrors saksi.protocol.v1.CredentialPresentation.
type CredentialPresentation struct {
	Version              uint32
	CredentialCommitment []byte
	IssuerPublicKey      []byte
	PresentationProof    []byte
	Nullifier            *Nullifier
}

// Ballot mirrors saksi.protocol.v1.Ballot.
type Ballot struct {
	Version                   uint32
	ElectionID                string
	VoterCredentialCommitment []byte
	Ciphertexts               []*Ciphertext
	WellFormednessProofs      []*CDSProof
	CredentialPresentation    *CredentialPresentation
}

// --- encoding helpers (proto3 canonical: omit zero/empty scalar fields) ---

func appendVarintField(b []byte, num protowire.Number, v uint64) []byte {
	if v == 0 {
		return b
	}
	b = protowire.AppendTag(b, num, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}

func appendBytesField(b []byte, num protowire.Number, v []byte) []byte {
	if len(v) == 0 {
		return b
	}
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}

func appendStringField(b []byte, num protowire.Number, v string) []byte {
	if len(v) == 0 {
		return b
	}
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendString(b, v)
}

func appendMessageField(b []byte, num protowire.Number, sub []byte) []byte {
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendBytes(b, sub)
}

// --- Marshal ---

// Marshal returns the canonical proto3 encoding of the Ciphertext.
func (m *Ciphertext) Marshal() []byte {
	var b []byte
	b = appendVarintField(b, 1, uint64(m.Version))
	b = appendBytesField(b, 2, m.Pad)
	b = appendBytesField(b, 3, m.Data)
	return b
}

// Marshal returns the canonical proto3 encoding of the CDSProofBranch.
func (m *CDSProofBranch) Marshal() []byte {
	var b []byte
	b = appendBytesField(b, 1, m.CommitmentA)
	b = appendBytesField(b, 2, m.CommitmentB)
	b = appendBytesField(b, 3, m.Challenge)
	b = appendBytesField(b, 4, m.Response)
	return b
}

// Marshal returns the canonical proto3 encoding of the CDSProof.
func (m *CDSProof) Marshal() []byte {
	var b []byte
	b = appendVarintField(b, 1, uint64(m.Version))
	for _, branch := range m.Branches {
		b = appendMessageField(b, 2, branch.Marshal())
	}
	return b
}

// Marshal returns the canonical proto3 encoding of the Nullifier.
func (m *Nullifier) Marshal() []byte {
	var b []byte
	b = appendVarintField(b, 1, uint64(m.Version))
	b = appendBytesField(b, 2, m.Value)
	return b
}

// Marshal returns the canonical proto3 encoding of the CredentialPresentation.
func (m *CredentialPresentation) Marshal() []byte {
	var b []byte
	b = appendVarintField(b, 1, uint64(m.Version))
	b = appendBytesField(b, 2, m.CredentialCommitment)
	b = appendBytesField(b, 3, m.IssuerPublicKey)
	b = appendBytesField(b, 4, m.PresentationProof)
	if m.Nullifier != nil {
		b = appendMessageField(b, 5, m.Nullifier.Marshal())
	}
	return b
}

// Marshal returns the canonical proto3 encoding of the Ballot.
func (m *Ballot) Marshal() []byte {
	var b []byte
	b = appendVarintField(b, 1, uint64(m.Version))
	b = appendStringField(b, 2, m.ElectionID)
	b = appendBytesField(b, 3, m.VoterCredentialCommitment)
	for _, ciphertext := range m.Ciphertexts {
		b = appendMessageField(b, 4, ciphertext.Marshal())
	}
	for _, proof := range m.WellFormednessProofs {
		b = appendMessageField(b, 5, proof.Marshal())
	}
	if m.CredentialPresentation != nil {
		b = appendMessageField(b, 6, m.CredentialPresentation.Marshal())
	}
	return b
}

// --- Unmarshal ---

func copyBytes(v []byte) []byte {
	out := make([]byte, len(v))
	copy(out, v)
	return out
}

// consumeField consumes the tag plus value at the front of data, returning the
// field number, wire type, the raw value bytes for length-delimited fields, the
// varint value for varint fields, and the number of bytes consumed.
func consumeField(data []byte) (num protowire.Number, typ protowire.Type, val []byte, varint uint64, consumed int, err error) {
	num, typ, n := protowire.ConsumeTag(data)
	if n < 0 {
		return 0, 0, nil, 0, 0, protowire.ParseError(n)
	}
	total := n
	rest := data[n:]
	switch typ {
	case protowire.VarintType:
		v, m := protowire.ConsumeVarint(rest)
		if m < 0 {
			return 0, 0, nil, 0, 0, protowire.ParseError(m)
		}
		return num, typ, nil, v, total + m, nil
	case protowire.BytesType:
		v, m := protowire.ConsumeBytes(rest)
		if m < 0 {
			return 0, 0, nil, 0, 0, protowire.ParseError(m)
		}
		return num, typ, v, 0, total + m, nil
	default:
		m := protowire.ConsumeFieldValue(num, typ, rest)
		if m < 0 {
			return 0, 0, nil, 0, 0, protowire.ParseError(m)
		}
		return num, typ, nil, 0, total + m, nil
	}
}

// UnmarshalCiphertext decodes a Ciphertext from canonical proto3 bytes.
func UnmarshalCiphertext(data []byte) (*Ciphertext, error) {
	m := &Ciphertext{}
	for len(data) > 0 {
		num, _, val, varint, n, err := consumeField(data)
		if err != nil {
			return nil, err
		}
		switch num {
		case 1:
			m.Version = uint32(varint)
		case 2:
			m.Pad = copyBytes(val)
		case 3:
			m.Data = copyBytes(val)
		}
		data = data[n:]
	}
	return m, nil
}

// UnmarshalCDSProofBranch decodes a CDSProofBranch from canonical proto3 bytes.
func UnmarshalCDSProofBranch(data []byte) (*CDSProofBranch, error) {
	m := &CDSProofBranch{}
	for len(data) > 0 {
		num, _, val, _, n, err := consumeField(data)
		if err != nil {
			return nil, err
		}
		switch num {
		case 1:
			m.CommitmentA = copyBytes(val)
		case 2:
			m.CommitmentB = copyBytes(val)
		case 3:
			m.Challenge = copyBytes(val)
		case 4:
			m.Response = copyBytes(val)
		}
		data = data[n:]
	}
	return m, nil
}

// UnmarshalCDSProof decodes a CDSProof from canonical proto3 bytes.
func UnmarshalCDSProof(data []byte) (*CDSProof, error) {
	m := &CDSProof{}
	for len(data) > 0 {
		num, _, val, varint, n, err := consumeField(data)
		if err != nil {
			return nil, err
		}
		switch num {
		case 1:
			m.Version = uint32(varint)
		case 2:
			branch, err := UnmarshalCDSProofBranch(val)
			if err != nil {
				return nil, err
			}
			m.Branches = append(m.Branches, branch)
		}
		data = data[n:]
	}
	return m, nil
}

// UnmarshalNullifier decodes a Nullifier from canonical proto3 bytes.
func UnmarshalNullifier(data []byte) (*Nullifier, error) {
	m := &Nullifier{}
	for len(data) > 0 {
		num, _, val, varint, n, err := consumeField(data)
		if err != nil {
			return nil, err
		}
		switch num {
		case 1:
			m.Version = uint32(varint)
		case 2:
			m.Value = copyBytes(val)
		}
		data = data[n:]
	}
	return m, nil
}

// UnmarshalCredentialPresentation decodes a CredentialPresentation.
func UnmarshalCredentialPresentation(data []byte) (*CredentialPresentation, error) {
	m := &CredentialPresentation{}
	for len(data) > 0 {
		num, _, val, varint, n, err := consumeField(data)
		if err != nil {
			return nil, err
		}
		switch num {
		case 1:
			m.Version = uint32(varint)
		case 2:
			m.CredentialCommitment = copyBytes(val)
		case 3:
			m.IssuerPublicKey = copyBytes(val)
		case 4:
			m.PresentationProof = copyBytes(val)
		case 5:
			nullifier, err := UnmarshalNullifier(val)
			if err != nil {
				return nil, err
			}
			m.Nullifier = nullifier
		}
		data = data[n:]
	}
	return m, nil
}

// UnmarshalBallot decodes a Ballot from canonical proto3 bytes.
func UnmarshalBallot(data []byte) (*Ballot, error) {
	m := &Ballot{}
	for len(data) > 0 {
		num, _, val, varint, n, err := consumeField(data)
		if err != nil {
			return nil, err
		}
		switch num {
		case 1:
			m.Version = uint32(varint)
		case 2:
			m.ElectionID = string(val)
		case 3:
			m.VoterCredentialCommitment = copyBytes(val)
		case 4:
			ciphertext, err := UnmarshalCiphertext(val)
			if err != nil {
				return nil, err
			}
			m.Ciphertexts = append(m.Ciphertexts, ciphertext)
		case 5:
			proof, err := UnmarshalCDSProof(val)
			if err != nil {
				return nil, err
			}
			m.WellFormednessProofs = append(m.WellFormednessProofs, proof)
		case 6:
			presentation, err := UnmarshalCredentialPresentation(val)
			if err != nil {
				return nil, err
			}
			m.CredentialPresentation = presentation
		}
		data = data[n:]
	}
	return m, nil
}
