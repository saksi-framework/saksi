// Deep, full-text decode of one Fabric block, for the ledger samples: every
// envelope, argument, read, write and endorsement, decoded from the block's
// own bytes and labelled with what it represents. Nothing here summarizes or
// elides a value — the annotated JSON this writes carries every byte the
// chain actually stored.
package main

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset/kvrwset"
	"github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// BlockDecode is the full-text, annotated decode of one Fabric block.
type BlockDecode struct {
	Number       uint64 `json:"number"`
	PreviousHash string `json:"previous_hash"`
	DataHash     string `json:"data_hash"`
	// HeaderHash is this block's own recomputed header hash (SHA-256 over the
	// ASN.1-DER header, the same computation client-sdk's blockHeaderHash and
	// the auditor's chain check use) — what the NEXT block's previous_hash
	// must equal for the chain to be unbroken. Fabric stores no block hash
	// field; every reader recomputes it the same way.
	HeaderHash   string     `json:"header_hash"`
	Transactions []TxDecode `json:"transactions"`
}

// TxDecode is one envelope in a block's Data, decoded as far as its type
// allows. A config or _lifecycle envelope decodes only the fields common to
// every envelope; DecodeNote says why the rest is absent.
type TxDecode struct {
	Index          int    `json:"index"`
	TxID           string `json:"tx_id"`
	Type           string `json:"type"` // common.HeaderType name: ENDORSER_TRANSACTION, CONFIG, CONFIG_UPDATE, ...
	Channel        string `json:"channel"`
	Timestamp      string `json:"timestamp,omitempty"`
	CreatorMSP     string `json:"creator_msp,omitempty"`
	CreatorCert    string `json:"creator_cert,omitempty"` // PEM: the signer's certificate
	ValidationCode string `json:"validation_code"`        // peer.TxValidationCode name, e.g. VALID
	Valid          bool   `json:"valid"`

	// Present only for an ENDORSER_TRANSACTION this decoder could parse all
	// the way through.
	Function  string           `json:"function,omitempty"`
	Args      []ArgDecode      `json:"args,omitempty"`
	Reads     []ReadDecode     `json:"reads,omitempty"`
	Writes    []WriteDecode    `json:"writes,omitempty"`
	Endorsers []EndorserDecode `json:"endorsers,omitempty"`
	Response  *ResponseDecode  `json:"response,omitempty"`

	DecodeNote string `json:"decode_note,omitempty"`
}

// ArgDecode is one chaincode invocation argument, after the function name
// (which is Function, not an ArgDecode). Index is 0-based among those
// arguments, matching how `peer chaincode invoke`'s Args array is numbered.
type ArgDecode struct {
	Index   int             `json:"index"`
	Raw     string          `json:"raw"` // the argument as submitted: hex when Hex is true, else the plain text
	Hex     bool            `json:"hex"`
	Meaning string          `json:"meaning,omitempty"`
	Decoded json.RawMessage `json:"decoded,omitempty"` // the saksi protobuf message this argument hex-decodes to, full, if any (bytes fields are base64: standard proto3 JSON)
}

// ReadDecode is one entry of a transaction's read set: a key this
// transaction's simulation read, and the version (block, tx index) it read at
// — not a value, since Fabric's read set never carries one.
type ReadDecode struct {
	Namespace string   `json:"namespace"`
	Key       string   `json:"key"`
	KeyParts  []string `json:"key_parts,omitempty"` // [objectType, attr1, attr2, ...] for a composite key
	BlockNum  uint64   `json:"version_block"`
	TxNum     uint64   `json:"version_tx"`
	Meaning   string   `json:"meaning,omitempty"`
}

// WriteDecode is one entry of a transaction's write set: the key it wrote
// (or deleted) and the value, in full.
type WriteDecode struct {
	Namespace string          `json:"namespace"`
	Key       string          `json:"key"`
	KeyParts  []string        `json:"key_parts,omitempty"`
	IsDelete  bool            `json:"is_delete"`
	ValueHex  string          `json:"value_hex"`
	Meaning   string          `json:"meaning,omitempty"`
	Decoded   json.RawMessage `json:"decoded,omitempty"`
}

// EndorserDecode is one endorsement on the transaction: who signed, not the
// signature bytes themselves (those prove nothing to a reader who cannot also
// recompute the proposal hash they cover).
type EndorserDecode struct {
	MSP  string `json:"msp"`
	Cert string `json:"cert"`
}

// ResponseDecode is the chaincode's own response to the transaction it
// endorsed (status 200 on success; the peer's rejection reason if not, though
// a rejected proposal never reaches a block in the first place — this is the
// ENDORSER's response, which VALID/INVALID at commit time can still overrule).
type ResponseDecode struct {
	Status  int32  `json:"status"`
	Message string `json:"message,omitempty"`
}

// blockHeaderHash mirrors fabric protoutil's ASN.1 block-header encoding —
// the same computation as client-sdk/ledger.go's unexported twin (duplicated
// rather than imported: it is three lines, and cmd/samplechain has no other
// reason to depend on client-sdk's internals).
func blockHeaderHash(number uint64, previousHash, dataHash []byte) []byte {
	der, err := asn1.Marshal(struct {
		Number       *big.Int
		PreviousHash []byte
		DataHash     []byte
	}{new(big.Int).SetUint64(number), previousHash, dataHash})
	if err != nil {
		panic(err) // a struct of int + byte slices cannot fail to marshal
	}
	sum := sha256.Sum256(der)
	return sum[:]
}

// decodeBlock decodes one block. validationCodes is the block's
// TRANSACTIONS_FILTER metadata (block.Metadata.Metadata[TRANSACTIONS_FILTER]),
// one byte per transaction, in the same order as block.Data.Data. ccName is
// the chaincode namespace whose writes get a saksi decode; other namespaces
// (lscc, _lifecycle, the ordering system channel) still show every read and
// write, just without a saksi Meaning/Decoded.
func decodeBlock(block *common.Block, validationCodes []byte, ccName string) BlockDecode {
	h := block.GetHeader()
	bd := BlockDecode{
		Number:       h.GetNumber(),
		PreviousHash: hex.EncodeToString(h.GetPreviousHash()),
		DataHash:     hex.EncodeToString(h.GetDataHash()),
		HeaderHash:   hex.EncodeToString(blockHeaderHash(h.GetNumber(), h.GetPreviousHash(), h.GetDataHash())),
	}
	for i, envBytes := range block.GetData().GetData() {
		code, valid := "UNKNOWN", false
		if i < len(validationCodes) {
			code = peer.TxValidationCode(validationCodes[i]).String()
			valid = peer.TxValidationCode(validationCodes[i]) == peer.TxValidationCode_VALID
		}
		bd.Transactions = append(bd.Transactions, decodeEnvelope(i, envBytes, code, valid, ccName))
	}
	return bd
}

func decodeEnvelope(index int, envBytes []byte, validationCode string, valid bool, ccName string) TxDecode {
	tx := TxDecode{Index: index, ValidationCode: validationCode, Valid: valid}

	var env common.Envelope
	if err := proto.Unmarshal(envBytes, &env); err != nil {
		tx.DecodeNote = fmt.Sprintf("envelope did not decode: %v", err)
		return tx
	}
	var payload common.Payload
	if err := proto.Unmarshal(env.GetPayload(), &payload); err != nil {
		tx.DecodeNote = fmt.Sprintf("payload did not decode: %v", err)
		return tx
	}
	var chdr common.ChannelHeader
	if err := proto.Unmarshal(payload.GetHeader().GetChannelHeader(), &chdr); err != nil {
		tx.DecodeNote = fmt.Sprintf("channel header did not decode: %v", err)
		return tx
	}
	tx.TxID = chdr.GetTxId()
	tx.Channel = chdr.GetChannelId()
	tx.Type = common.HeaderType(chdr.GetType()).String()
	if ts := chdr.GetTimestamp(); ts != nil {
		tx.Timestamp = ts.AsTime().UTC().Format(time.RFC3339Nano)
	}

	var shdr common.SignatureHeader
	if proto.Unmarshal(payload.GetHeader().GetSignatureHeader(), &shdr) == nil {
		var sid msp.SerializedIdentity
		if proto.Unmarshal(shdr.GetCreator(), &sid) == nil {
			tx.CreatorMSP = sid.GetMspid()
			tx.CreatorCert = string(sid.GetIdBytes())
		}
	}

	if common.HeaderType(chdr.GetType()) != common.HeaderType_ENDORSER_TRANSACTION {
		tx.DecodeNote = "not an endorser transaction (config or lifecycle update): only the envelope header is decoded"
		return tx
	}
	var txMsg peer.Transaction
	if err := proto.Unmarshal(payload.GetData(), &txMsg); err != nil {
		tx.DecodeNote = fmt.Sprintf("transaction payload did not decode: %v", err)
		return tx
	}
	for _, action := range txMsg.GetActions() {
		decodeTransactionAction(&tx, action, ccName)
	}
	return tx
}

func decodeTransactionAction(tx *TxDecode, action *peer.TransactionAction, ccName string) {
	var cap peer.ChaincodeActionPayload
	if err := proto.Unmarshal(action.GetPayload(), &cap); err != nil {
		tx.DecodeNote = appendNote(tx.DecodeNote, fmt.Sprintf("chaincode action payload did not decode: %v", err))
		return
	}

	var cpp peer.ChaincodeProposalPayload
	if proto.Unmarshal(cap.GetChaincodeProposalPayload(), &cpp) == nil {
		var cis peer.ChaincodeInvocationSpec
		if proto.Unmarshal(cpp.GetInput(), &cis) == nil {
			args := cis.GetChaincodeSpec().GetInput().GetArgs()
			if len(args) > 0 {
				tx.Function = string(args[0])
				for i, a := range args[1:] {
					tx.Args = append(tx.Args, decodeArg(tx.Function, i, a))
				}
			}
		}
	}

	endorsed := cap.GetAction()
	for _, e := range endorsed.GetEndorsements() {
		ed := EndorserDecode{}
		var sid msp.SerializedIdentity
		if proto.Unmarshal(e.GetEndorser(), &sid) == nil {
			ed.MSP = sid.GetMspid()
			ed.Cert = string(sid.GetIdBytes())
		}
		tx.Endorsers = append(tx.Endorsers, ed)
	}

	var prp peer.ProposalResponsePayload
	if err := proto.Unmarshal(endorsed.GetProposalResponsePayload(), &prp); err != nil {
		tx.DecodeNote = appendNote(tx.DecodeNote, fmt.Sprintf("proposal response payload did not decode: %v", err))
		return
	}
	var ccAction peer.ChaincodeAction
	if err := proto.Unmarshal(prp.GetExtension(), &ccAction); err != nil {
		tx.DecodeNote = appendNote(tx.DecodeNote, fmt.Sprintf("chaincode action did not decode: %v", err))
		return
	}
	if resp := ccAction.GetResponse(); resp != nil {
		tx.Response = &ResponseDecode{Status: resp.GetStatus(), Message: resp.GetMessage()}
	}

	var trws rwset.TxReadWriteSet
	if err := proto.Unmarshal(ccAction.GetResults(), &trws); err != nil {
		tx.DecodeNote = appendNote(tx.DecodeNote, fmt.Sprintf("read-write set did not decode: %v", err))
		return
	}
	for _, ns := range trws.GetNsRwset() {
		var kv kvrwset.KVRWSet
		if err := proto.Unmarshal(ns.GetRwset(), &kv); err != nil {
			tx.DecodeNote = appendNote(tx.DecodeNote, fmt.Sprintf("%s kv read-write set did not decode: %v", ns.GetNamespace(), err))
			continue
		}
		saksi := ns.GetNamespace() == ccName
		for _, r := range kv.GetReads() {
			objType, parts, ok := splitCompositeKey(r.GetKey())
			rd := ReadDecode{
				Namespace: ns.GetNamespace(), Key: r.GetKey(),
				BlockNum: r.GetVersion().GetBlockNum(), TxNum: r.GetVersion().GetTxNum(),
			}
			if ok {
				rd.KeyParts = append([]string{objType}, parts...)
				if saksi {
					rd.Meaning = meaningLabel(objType, parts)
				}
			}
			tx.Reads = append(tx.Reads, rd)
		}
		for _, w := range kv.GetWrites() {
			objType, parts, ok := splitCompositeKey(w.GetKey())
			wd := WriteDecode{
				Namespace: ns.GetNamespace(), Key: w.GetKey(),
				IsDelete: w.GetIsDelete(), ValueHex: hex.EncodeToString(w.GetValue()),
			}
			if ok {
				wd.KeyParts = append([]string{objType}, parts...)
				if saksi {
					wd.Decoded, wd.Meaning = decodeValue(objType, parts, w.GetValue())
				}
			}
			tx.Writes = append(tx.Writes, wd)
		}
	}
}

func appendNote(note, add string) string {
	if note == "" {
		return add
	}
	return note + "; " + add
}

// hexArgKinds says which (function, 0-based-arg-index) pairs carry a
// hex-encoded saksi protobuf message, and which message. Every other argument
// (election ids, trustee ids, contest ids, page sizes, bookmarks) is plain
// text — the chaincode's own argument shapes (contract.go), mirrored here so
// the decode never has to guess from the bytes.
var hexArgKinds = map[string]map[int]string{
	"CreateElection":          {0: "election"},
	"PublishDKGTranscript":    {0: "dkg"},
	"SubmitBallot":            {0: "ballot"},
	"SubmitPartialDecryption": {1: "partialdec"},
	"PublishTally":            {0: "tally"},
}

func decodeArg(function string, index int, raw []byte) ArgDecode {
	ad := ArgDecode{Index: index}
	kind, isHexArg := hexArgKinds[function][index]
	if !isHexArg {
		ad.Raw = string(raw)
		return ad
	}
	ad.Raw = string(raw) // the argument IS the hex string on the wire
	ad.Hex = true
	decoded, label, err := decodeMessage(kind, mustHexDecode(string(raw)))
	ad.Meaning = label
	if err == nil {
		ad.Decoded = decoded
	} else {
		ad.Meaning = fmt.Sprintf("%s (did not decode: %v)", label, err)
	}
	return ad
}

func mustHexDecode(s string) []byte {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil
	}
	return b
}

// decodeMessage unmarshals raw as the named saksi wire message and renders it
// as full protobuf-JSON (field names as declared in wire.proto; bytes fields
// are base64, the proto3 JSON convention — the wire-hex form is what ValueHex
// / Arg.Raw already carry).
func decodeMessage(kind string, raw []byte) (json.RawMessage, string, error) {
	var m proto.Message
	var label string
	switch kind {
	case "election":
		m, label = &pb.ElectionParameters{}, "election parameters"
	case "dkg":
		m, label = &pb.DKGTranscript{}, "DKG transcript"
	case "ballot":
		m, label = &pb.Ballot{}, "ballot"
	case "partialdec":
		m, label = &pb.PartialDecryption{}, "partial decryption"
	case "tally":
		m, label = &pb.TallyResult{}, "tally result"
	default:
		return nil, "", fmt.Errorf("unknown message kind %q", kind)
	}
	if raw == nil {
		return nil, label, fmt.Errorf("not valid hex")
	}
	if err := proto.Unmarshal(raw, m); err != nil {
		return nil, label, err
	}
	j, err := protojson.MarshalOptions{EmitUnpopulated: true, UseProtoNames: true}.Marshal(m)
	if err != nil {
		return nil, label, err
	}
	return j, label, nil
}

// meaningLabel says what a world-state key represents, from its composite-key
// object type and attributes alone (contract.go's electionIndex / statusIndex
// / dkgIndex / ballotIndex / nullifierIndex / partialDecIndex / tallyIndex).
func meaningLabel(objType string, parts []string) string {
	get := func(i int) string {
		if i < len(parts) {
			return parts[i]
		}
		return "?"
	}
	switch objType {
	case "election":
		return fmt.Sprintf("election parameters for election %q", get(0))
	case "status":
		return fmt.Sprintf("election status for election %q", get(0))
	case "dkg":
		return fmt.Sprintf("DKG transcript for election %q", get(0))
	case "ballot":
		return fmt.Sprintf("ballot for election %q, nullifier %s", get(0), get(1))
	case "nullifier":
		return fmt.Sprintf("nullifier-spent marker for election %q, nullifier %s", get(0), get(1))
	case "partialdec":
		return fmt.Sprintf("partial decryption for election %q, contest %q, trustee %q", get(0), get(1), get(2))
	case "tally":
		return fmt.Sprintf("tally result for election %q", get(0))
	default:
		return ""
	}
}

// decodeValue is meaningLabel plus, for the four message-valued keys, the
// value decoded in full. "status" and "nullifier" values are not wire
// messages (a plain string, and a single 0x01 byte) — their meaning says so
// directly rather than attempting a message decode that would only fail.
func decodeValue(objType string, parts []string, value []byte) (json.RawMessage, string) {
	meaning := meaningLabel(objType, parts)
	switch objType {
	case "election", "dkg", "ballot", "partialdec", "tally":
		if j, _, err := decodeMessage(objType, value); err == nil {
			return j, meaning
		}
	case "status":
		return nil, fmt.Sprintf("%s: %q", meaning, string(value))
	case "nullifier":
		return nil, fmt.Sprintf("%s (%d-byte marker)", meaning, len(value))
	}
	return nil, meaning
}

// splitCompositeKey reverses shim.CreateCompositeKey's format
// ("\x00" + objectType + "\x00" + attr1 + "\x00" + attr2 + "\x00..."): every
// saksi world-state key is one of these, so this is the one place the decoder
// needs to know that format. ok is false for a key that is not a composite
// key at all (a plain key from another namespace, e.g. lscc/_lifecycle).
func splitCompositeKey(key string) (objType string, parts []string, ok bool) {
	if len(key) == 0 || key[0] != 0x00 {
		return "", nil, false
	}
	segs := strings.Split(key[1:], "\x00")
	if len(segs) > 0 && segs[len(segs)-1] == "" {
		segs = segs[:len(segs)-1] // the trailing \x00 after the last attribute
	}
	if len(segs) == 0 {
		return "", nil, false
	}
	return segs[0], segs[1:], true
}
