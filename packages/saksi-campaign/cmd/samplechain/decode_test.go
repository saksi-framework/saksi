package main

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset/kvrwset"
	"github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// compositeKey builds a key the same way shim.CreateCompositeKey does
// ("\x00" + objectType + "\x00" + attr1 + "\x00" + ... + "\x00"), so this test
// exercises splitCompositeKey against the real wire format without pulling
// fabric-chaincode-go into this module just to call it.
func compositeKey(objType string, attrs ...string) string {
	k := "\x00" + objType + "\x00"
	for _, a := range attrs {
		k += a + "\x00"
	}
	return k
}

// buildSubmitBallotBlock constructs one block, byte for byte the shape a real
// SubmitBallot commit has: one ENDORSER_TRANSACTION envelope invoking
// SubmitBallot with a hex ballot argument, endorsed once, writing the
// "ballot" and "nullifier" composite keys, valid.
func buildSubmitBallotBlock(t *testing.T) *common.Block {
	t.Helper()

	ballot := &pb.Ballot{Version: 1, ElectionId: "sample-clean", PositionId: "president"}
	ballotRaw, err := proto.Marshal(ballot)
	if err != nil {
		t.Fatalf("marshal ballot: %v", err)
	}
	ballotHex := hex.EncodeToString(ballotRaw)

	chdr, err := proto.Marshal(&common.ChannelHeader{
		Type:      int32(common.HeaderType_ENDORSER_TRANSACTION),
		TxId:      "tx-1",
		ChannelId: "sample-clean",
		Timestamp: timestamppb.New(fixedTime),
	})
	if err != nil {
		t.Fatalf("marshal channel header: %v", err)
	}
	creator, err := proto.Marshal(&msp.SerializedIdentity{Mspid: "Org1MSP", IdBytes: []byte("-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----\n")})
	if err != nil {
		t.Fatalf("marshal creator: %v", err)
	}
	shdr, err := proto.Marshal(&common.SignatureHeader{Creator: creator})
	if err != nil {
		t.Fatalf("marshal signature header: %v", err)
	}

	cis, err := proto.Marshal(&peer.ChaincodeInvocationSpec{
		ChaincodeSpec: &peer.ChaincodeSpec{
			ChaincodeId: &peer.ChaincodeID{Name: "saksi-bulletin"},
			Input:       &peer.ChaincodeInput{Args: [][]byte{[]byte("SubmitBallot"), []byte(ballotHex)}},
		},
	})
	if err != nil {
		t.Fatalf("marshal invocation spec: %v", err)
	}
	cpp, err := proto.Marshal(&peer.ChaincodeProposalPayload{Input: cis})
	if err != nil {
		t.Fatalf("marshal proposal payload: %v", err)
	}

	kvrw, err := proto.Marshal(&kvrwset.KVRWSet{
		Writes: []*kvrwset.KVWrite{
			{Key: compositeKey("ballot", "sample-clean", "aa11bb22"), Value: ballotRaw},
			{Key: compositeKey("nullifier", "sample-clean", "aa11bb22"), Value: []byte{1}},
		},
	})
	if err != nil {
		t.Fatalf("marshal kv rwset: %v", err)
	}
	trws, err := proto.Marshal(&rwset.TxReadWriteSet{
		NsRwset: []*rwset.NsReadWriteSet{{Namespace: "saksi-bulletin", Rwset: kvrw}},
	})
	if err != nil {
		t.Fatalf("marshal tx rwset: %v", err)
	}

	ccAction, err := proto.Marshal(&peer.ChaincodeAction{
		Results:  trws,
		Response: &peer.Response{Status: 200, Message: "OK"},
	})
	if err != nil {
		t.Fatalf("marshal chaincode action: %v", err)
	}
	prp, err := proto.Marshal(&peer.ProposalResponsePayload{Extension: ccAction})
	if err != nil {
		t.Fatalf("marshal proposal response payload: %v", err)
	}

	endorser, err := proto.Marshal(&msp.SerializedIdentity{Mspid: "Org2MSP", IdBytes: []byte("cert-2")})
	if err != nil {
		t.Fatalf("marshal endorser identity: %v", err)
	}
	capPayload, err := proto.Marshal(&peer.ChaincodeActionPayload{
		ChaincodeProposalPayload: cpp,
		Action: &peer.ChaincodeEndorsedAction{
			ProposalResponsePayload: prp,
			Endorsements:            []*peer.Endorsement{{Endorser: endorser, Signature: []byte("sig")}},
		},
	})
	if err != nil {
		t.Fatalf("marshal chaincode action payload: %v", err)
	}

	txMsg, err := proto.Marshal(&peer.Transaction{
		Actions: []*peer.TransactionAction{{Payload: capPayload}},
	})
	if err != nil {
		t.Fatalf("marshal transaction: %v", err)
	}
	payload, err := proto.Marshal(&common.Payload{
		Header: &common.Header{ChannelHeader: chdr, SignatureHeader: shdr},
		Data:   txMsg,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	env, err := proto.Marshal(&common.Envelope{Payload: payload, Signature: []byte("envelope-sig")})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	return &common.Block{
		Header: &common.BlockHeader{Number: 7, PreviousHash: []byte("prev"), DataHash: []byte("data")},
		Data:   &common.BlockData{Data: [][]byte{env}},
		Metadata: &common.BlockMetadata{Metadata: [][]byte{
			{}, {}, {byte(peer.TxValidationCode_VALID)}, {}, {},
		}},
	}
}

func TestDecodeBlockSubmitBallot(t *testing.T) {
	block := buildSubmitBallotBlock(t)
	filter := block.GetMetadata().GetMetadata()[int(common.BlockMetadataIndex_TRANSACTIONS_FILTER)]
	bd := decodeBlock(block, filter, "saksi-bulletin")

	if bd.Number != 7 {
		t.Errorf("Number = %d, want 7", bd.Number)
	}
	if bd.HeaderHash == "" || bd.HeaderHash == bd.PreviousHash {
		t.Errorf("HeaderHash not computed: %q", bd.HeaderHash)
	}
	if len(bd.Transactions) != 1 {
		t.Fatalf("Transactions = %d, want 1", len(bd.Transactions))
	}

	tx := bd.Transactions[0]
	if tx.TxID != "tx-1" {
		t.Errorf("TxID = %q, want tx-1", tx.TxID)
	}
	if tx.Type != "ENDORSER_TRANSACTION" {
		t.Errorf("Type = %q", tx.Type)
	}
	if !tx.Valid || tx.ValidationCode != "VALID" {
		t.Errorf("Valid=%v ValidationCode=%q, want true/VALID", tx.Valid, tx.ValidationCode)
	}
	if tx.CreatorMSP != "Org1MSP" {
		t.Errorf("CreatorMSP = %q", tx.CreatorMSP)
	}
	if tx.Function != "SubmitBallot" {
		t.Errorf("Function = %q, want SubmitBallot", tx.Function)
	}
	if tx.DecodeNote != "" {
		t.Errorf("DecodeNote = %q, want none for a fully-decodable tx", tx.DecodeNote)
	}
	if tx.Response == nil || tx.Response.Status != 200 {
		t.Errorf("Response = %+v, want status 200", tx.Response)
	}

	if len(tx.Args) != 1 || !tx.Args[0].Hex {
		t.Fatalf("Args = %+v, want one hex arg", tx.Args)
	}
	if !bytes.Contains(tx.Args[0].Decoded, []byte(`"election_id":"sample-clean"`)) {
		t.Errorf("arg decoded = %s, missing the ballot's election_id", tx.Args[0].Decoded)
	}

	if len(tx.Writes) != 2 {
		t.Fatalf("Writes = %d, want 2", len(tx.Writes))
	}
	byType := map[string]WriteDecode{}
	for _, w := range tx.Writes {
		if len(w.KeyParts) > 0 {
			byType[w.KeyParts[0]] = w
		}
	}
	ballotW, ok := byType["ballot"]
	if !ok {
		t.Fatalf("no write with key_parts[0]=ballot: %+v", tx.Writes)
	}
	if !strings.Contains(ballotW.Meaning, "sample-clean") || !strings.Contains(ballotW.Meaning, "aa11bb22") {
		t.Errorf("ballot write meaning = %q, missing election id or nullifier", ballotW.Meaning)
	}
	if !bytes.Contains(ballotW.Decoded, []byte(`"position_id":"president"`)) {
		t.Errorf("ballot write decoded = %s, missing position_id", ballotW.Decoded)
	}
	nullW, ok := byType["nullifier"]
	if !ok {
		t.Fatalf("no write with key_parts[0]=nullifier: %+v", tx.Writes)
	}
	if nullW.ValueHex != "01" {
		t.Errorf("nullifier write value_hex = %q, want 01", nullW.ValueHex)
	}

	if len(tx.Endorsers) != 1 || tx.Endorsers[0].MSP != "Org2MSP" {
		t.Errorf("Endorsers = %+v, want one Org2MSP endorsement", tx.Endorsers)
	}
}

func TestDecodeBlockNonEndorserEnvelope(t *testing.T) {
	chdr, err := proto.Marshal(&common.ChannelHeader{Type: int32(common.HeaderType_CONFIG), TxId: "cfg-1", ChannelId: "sample-clean"})
	if err != nil {
		t.Fatalf("marshal channel header: %v", err)
	}
	payload, err := proto.Marshal(&common.Payload{Header: &common.Header{ChannelHeader: chdr}})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	env, err := proto.Marshal(&common.Envelope{Payload: payload})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	block := &common.Block{
		Header: &common.BlockHeader{Number: 0},
		Data:   &common.BlockData{Data: [][]byte{env}},
		Metadata: &common.BlockMetadata{Metadata: [][]byte{
			{}, {}, {byte(peer.TxValidationCode_VALID)}, {}, {},
		}},
	}
	filter := block.GetMetadata().GetMetadata()[int(common.BlockMetadataIndex_TRANSACTIONS_FILTER)]
	bd := decodeBlock(block, filter, "saksi-bulletin")

	if len(bd.Transactions) != 1 {
		t.Fatalf("Transactions = %d, want 1", len(bd.Transactions))
	}
	tx := bd.Transactions[0]
	if tx.Type != "CONFIG" {
		t.Errorf("Type = %q, want CONFIG", tx.Type)
	}
	if tx.DecodeNote == "" {
		t.Errorf("DecodeNote is empty, want a note explaining why a CONFIG envelope has no function/writes")
	}
	if tx.Function != "" || len(tx.Writes) != 0 {
		t.Errorf("a CONFIG envelope must not decode a function or writes: %+v", tx)
	}
}

func TestSplitCompositeKey(t *testing.T) {
	key := compositeKey("partialdec", "sample-partial", "president/cand0", "1")
	objType, parts, ok := splitCompositeKey(key)
	if !ok {
		t.Fatalf("splitCompositeKey(%q) ok = false", key)
	}
	if objType != "partialdec" {
		t.Errorf("objType = %q, want partialdec", objType)
	}
	want := []string{"sample-partial", "president/cand0", "1"}
	if len(parts) != len(want) {
		t.Fatalf("parts = %v, want %v", parts, want)
	}
	for i := range want {
		if parts[i] != want[i] {
			t.Errorf("parts[%d] = %q, want %q", i, parts[i], want[i])
		}
	}

	if _, _, ok := splitCompositeKey("plain-key-not-composite"); ok {
		t.Error("a plain key must not be read as composite")
	}
}

var fixedTime = time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
