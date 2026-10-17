package sigverify

import (
	"encoding/binary"
	"fmt"
)

// returnSigDomain is the domain separator a precinct authority signs a precinct
// return under. It must equal saksi-auditor's precinct_return::RETURN_SIG_DOMAIN.
const returnSigDomain = "saksi.er.sig.v1"

// ReturnContest is one contest's homomorphic aggregate in a precinct return:
// the compressed points Σc1 (pads) and Σc2 (data), 32 bytes each.
type ReturnContest struct {
	ContestID string
	SumC1     []byte
	SumC2     []byte
}

// ReturnSigMessage rebuilds the exact bytes a precinct authority signs, the Go
// mirror of saksi-auditor's `PrecinctReturn::message`:
//
//	"saksi.er.sig.v1"
//	u32le len ‖ election_id
//	u32le len ‖ precinct_id
//	u64le close_block
//	close_tip_hash (32)
//	u64le record_count
//	ledger_digest (32)
//	u32le contest count, then per contest: u32le len ‖ contest_id ‖ Σc1 (32) ‖ Σc2 (32)
//
// Not called by any chaincode function in this build (the canvass is
// verifier-side); kept so an on-chain return gate can reuse it.
func ReturnSigMessage(electionID, precinctID string, closeBlock uint64, tipHash []byte,
	recordCount uint64, ledgerDigest []byte, contests []ReturnContest) ([]byte, error) {
	if len(tipHash) != 32 || len(ledgerDigest) != 32 {
		return nil, fmt.Errorf("tip hash and ledger digest must be 32 bytes, got %d and %d", len(tipHash), len(ledgerDigest))
	}
	out := []byte(returnSigDomain)
	lp := func(b []byte) {
		out = binary.LittleEndian.AppendUint32(out, uint32(len(b)))
		out = append(out, b...)
	}
	lp([]byte(electionID))
	lp([]byte(precinctID))
	out = binary.LittleEndian.AppendUint64(out, closeBlock)
	out = append(out, tipHash...)
	out = binary.LittleEndian.AppendUint64(out, recordCount)
	out = append(out, ledgerDigest...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(contests)))
	for i, c := range contests {
		if len(c.SumC1) != 32 || len(c.SumC2) != 32 {
			return nil, fmt.Errorf("contest %d (%q): aggregate points must be 32 bytes", i, c.ContestID)
		}
		lp([]byte(c.ContestID))
		out = append(out, c.SumC1...)
		out = append(out, c.SumC2...)
	}
	return out, nil
}

// VerifyReturnSig checks a precinct return signature (64-byte Schnorr proof)
// over msg under the authority's compressed public key. Returns nil iff valid.
func VerifyReturnSig(msg, sig, pubkey []byte) error {
	return VerifySchnorr(pubkey, msg, sig)
}
