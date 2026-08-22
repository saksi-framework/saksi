# On-Chain Audit-Trail View Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove an election's full lifecycle is committed on the Fabric ledger: console-driven on-chain elections with per-event ledger receipts, and a sealed-until-tally public audit-trail view.

**Architecture:** The Go console (`packages/saksi-campaign`) imports the Go client-sdk (`packages/saksi-bulletin/client-sdk`) directly. A new `Ledger` API in the client-sdk wraps submit-with-receipt + qscc block queries + computed ASN.1 block hashes. The console's on-chain Submit drives the whole lifecycle, recording `receipts.csv`/`trail.json` per run; new `/api/trail/<id>` + `/trail/<id>` routes re-query the chain live and stay sealed until the tally is published.

**Tech Stack:** Go 1.23, fabric-gateway v1.7.1, fabric-protos-go-apiv2, encoding/asn1, existing single-file console web UI.

**Spec:** `docs/superpowers/specs/2026-08-22-onchain-audit-trail-design.md` (in repo, committed). §4 handoff decisions are LOCKED — sealed gate, no voter identity, permissioned-read.

## Global Constraints

- Branch: `onchain-audit-trail` in the saksi repo (spike commit already cherry-picked: `Gateway()` accessor + `bundle-v1.json` exist).
- Go builds/tests run on Windows fine; live-network runs need WSL/CI (space-free path).
- `clippy`-equivalent hygiene: `go vet` + `staticcheck` must stay clean (CI enforces).
- Offline console behavior and all existing tests must stay green.
- Never render voter identity anywhere (there is none on-chain — keep it that way).
- Fail-closed: any error deciding seal status renders SEALED.
- Golden receipt fixture (from CI spike run 32551023972, Fabric 2.5.15): block number `28`, previous_hash `003ef1053b17f9cf286bd087f03dbd72cddb7c1fb8f2e680128c32e5c6db6b8d`, data_hash `9cd1500e262501b40b0c9c7dba2dc17fd7282d3b9f91c04f26f6564d774d3655`, block hash `5f896f60ee4a5a755dacd92ba162a707299621442683754c2469de8a123c43da`.
- Commits: Conventional Commits + `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` trailer.

---

### Task 1: Block header hash (client-sdk `ledger.go` core)

**Files:**
- Create: `packages/saksi-bulletin/client-sdk/ledger.go`
- Test: `packages/saksi-bulletin/client-sdk/ledger_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `type Receipt struct { TxID string; BlockNumber uint64; BlockHash, DataHash, PreviousHash []byte }` and `func blockHeaderHash(number uint64, previousHash, dataHash []byte) []byte`.

- [ ] **Step 1: Write the failing golden test**

```go
package clientsdk

import (
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

// Golden values captured from the QSCC spike (CI run 32551023972, Fabric
// 2.5.15): GetChainInfo.CurrentBlockHash at height 29 is the hash of block 28.
func TestBlockHeaderHashGolden(t *testing.T) {
	prev := mustHex(t, "003ef1053b17f9cf286bd087f03dbd72cddb7c1fb8f2e680128c32e5c6db6b8d")
	data := mustHex(t, "9cd1500e262501b40b0c9c7dba2dc17fd7282d3b9f91c04f26f6564d774d3655")
	want := "5f896f60ee4a5a755dacd92ba162a707299621442683754c2469de8a123c43da"
	got := hex.EncodeToString(blockHeaderHash(28, prev, data))
	if got != want {
		t.Fatalf("blockHeaderHash = %s, want %s", got, want)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run (in `packages/saksi-bulletin/client-sdk`): `go test ./... -run TestBlockHeaderHashGolden -v`
Expected: FAIL — `blockHeaderHash` undefined.

- [ ] **Step 3: Implement `ledger.go`**

```go
// Ledger receipts: proof that a transaction committed on the Fabric ledger.
//
// A Fabric block's hash is stored in no block field — it is SHA256 over the
// ASN.1-DER encoding of the header (number, previous_hash, data_hash), exactly
// as fabric's protoutil computes it. blockHeaderHash reproduces that, so
// receipts carry a real block hash for ANY block, tip or not.
package clientsdk

import (
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
)

// Receipt is a transaction's ledger receipt.
type Receipt struct {
	TxID         string
	BlockNumber  uint64
	BlockHash    []byte
	DataHash     []byte
	PreviousHash []byte
}

// asn1Header mirrors fabric protoutil's ASN.1 block-header encoding.
type asn1Header struct {
	Number       *big.Int
	PreviousHash []byte
	DataHash     []byte
}

func blockHeaderHash(number uint64, previousHash, dataHash []byte) []byte {
	der, err := asn1.Marshal(asn1Header{
		Number:       new(big.Int).SetUint64(number),
		PreviousHash: previousHash,
		DataHash:     dataHash,
	})
	if err != nil {
		// Marshalling a struct of int + byte slices cannot fail at runtime.
		panic(err)
	}
	sum := sha256.Sum256(der)
	return sum[:]
}
```

NOTE: fabric's protoutil uses `*big.Int` for the number (`BlockHeaderBytes`). If the golden test fails with `int64`-style encoding differences, this big.Int form is the correct one — do not "fix" the fixture.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... -run TestBlockHeaderHashGolden -v`
Expected: PASS. (If FAIL: print the DER hex, compare against fabric protoutil source — the fixture is ground truth from a real network.)

- [ ] **Step 5: Commit**

```bash
git add packages/saksi-bulletin/client-sdk/ledger.go packages/saksi-bulletin/client-sdk/ledger_test.go
git commit -m "feat(client-sdk): computed ASN.1 block-header hash + Receipt type"
```

---

### Task 2: Ledger API on Connection; delete the spike probe

**Files:**
- Modify: `packages/saksi-bulletin/client-sdk/ledger.go` (append)
- Modify: `packages/saksi-bulletin/client-sdk/connect.go` (promote `Gateway()` doc comment: drop the THROWAWAY line)
- Delete: `packages/saksi-bulletin/client-sdk/cmd/qscc-probe/` (superseded)
- Test: `packages/saksi-bulletin/client-sdk/ledger_test.go` (append)

**Interfaces:**
- Consumes: `Connection.Gateway() *client.Gateway`, `blockHeaderHash`, `Receipt` (Task 1).
- Produces (the console's mock seam):

```go
type Ledger interface {
	SubmitWithReceipt(fn string, args ...string) ([]byte, Receipt, error)
	LedgerReceipt(txID string) (Receipt, error)
	ChainInfo() (height uint64, currentBlockHash []byte, err error)
}
```
and `func (c *Connection) Ledger() Ledger`.

- [ ] **Step 1: Write failing tests for the block→receipt helper**

```go
// in ledger_test.go
import (
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
)

func TestReceiptFromBlock(t *testing.T) {
	prev := mustHex(t, "003ef1053b17f9cf286bd087f03dbd72cddb7c1fb8f2e680128c32e5c6db6b8d")
	data := mustHex(t, "9cd1500e262501b40b0c9c7dba2dc17fd7282d3b9f91c04f26f6564d774d3655")
	block := &common.Block{Header: &common.BlockHeader{Number: 28, PreviousHash: prev, DataHash: data}}
	r := receiptFromBlock("tx-abc", block)
	if r.TxID != "tx-abc" || r.BlockNumber != 28 {
		t.Fatalf("bad receipt identity: %+v", r)
	}
	if hex.EncodeToString(r.BlockHash) != "5f896f60ee4a5a755dacd92ba162a707299621442683754c2469de8a123c43da" {
		t.Fatalf("bad block hash: %x", r.BlockHash)
	}
}
```

- [ ] **Step 2: Run test — expect FAIL** (`receiptFromBlock` undefined): `go test ./... -run TestReceiptFromBlock -v`

- [ ] **Step 3: Append the Ledger implementation to `ledger.go`**

```go
import (
	"fmt"
	"strconv"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"google.golang.org/protobuf/proto"
)

// Ledger is the receipt-bearing view of the chain. The console mocks this
// interface in unit tests; Connection provides the real one.
type Ledger interface {
	// SubmitWithReceipt submits a bulletin-chaincode transaction and returns
	// its result plus the ledger receipt (waits for commit; errors if the
	// transaction does not validate).
	SubmitWithReceipt(fn string, args ...string) ([]byte, Receipt, error)
	// LedgerReceipt fetches the receipt for an already-committed transaction
	// via the qscc system chaincode.
	LedgerReceipt(txID string) (Receipt, error)
	// ChainInfo returns the channel height and the current (tip) block hash.
	ChainInfo() (height uint64, currentBlockHash []byte, err error)
}

// ledger implements Ledger over an open gateway connection.
type ledger struct {
	network  *client.Network
	contract *client.Contract // the bulletin chaincode
	qscc     *client.Contract
	channel  string
}

// Ledger returns the receipt-bearing view of this connection's channel.
func (c *Connection) Ledger() Ledger {
	network := c.gateway.GetNetwork(c.channel)
	return &ledger{
		network:  network,
		contract: network.GetContract(c.chaincode),
		qscc:     network.GetContract("qscc"),
		channel:  c.channel,
	}
}

func (l *ledger) SubmitWithReceipt(fn string, args ...string) ([]byte, Receipt, error) {
	result, commit, err := l.contract.SubmitAsync(fn, client.WithArguments(args...))
	if err != nil {
		return nil, Receipt{}, fmt.Errorf("submit %s: %w", fn, err)
	}
	status, err := commit.Status()
	if err != nil {
		return nil, Receipt{}, fmt.Errorf("commit status for %s: %w", fn, err)
	}
	if !status.Successful {
		return nil, Receipt{}, fmt.Errorf("%s tx %s did not validate (code %d)", fn, commit.TransactionID(), int32(status.Code))
	}
	receipt, err := l.LedgerReceipt(commit.TransactionID())
	if err != nil {
		return nil, Receipt{}, err
	}
	return result, receipt, nil
}

func (l *ledger) LedgerReceipt(txID string) (Receipt, error) {
	blockBytes, err := l.qscc.EvaluateTransaction("GetBlockByTxID", l.channel, txID)
	if err != nil {
		return Receipt{}, fmt.Errorf("qscc GetBlockByTxID: %w", err)
	}
	var block common.Block
	if err := proto.Unmarshal(blockBytes, &block); err != nil {
		return Receipt{}, fmt.Errorf("decode block: %w", err)
	}
	return receiptFromBlock(txID, &block), nil
}

func (l *ledger) ChainInfo() (uint64, []byte, error) {
	infoBytes, err := l.qscc.EvaluateTransaction("GetChainInfo", l.channel)
	if err != nil {
		return 0, nil, fmt.Errorf("qscc GetChainInfo: %w", err)
	}
	var info common.BlockchainInfo
	if err := proto.Unmarshal(infoBytes, &info); err != nil {
		return 0, nil, fmt.Errorf("decode chain info: %w", err)
	}
	return info.GetHeight(), info.GetCurrentBlockHash(), nil
}

func receiptFromBlock(txID string, block *common.Block) Receipt {
	h := block.GetHeader()
	return Receipt{
		TxID:         txID,
		BlockNumber:  h.GetNumber(),
		BlockHash:    blockHeaderHash(h.GetNumber(), h.GetPreviousHash(), h.GetDataHash()),
		DataHash:     h.GetDataHash(),
		PreviousHash: h.GetPreviousHash(),
	}
}

var _ = strconv.FormatUint // remove if unused after wiring
```

`Connection` currently stores no channel/chaincode names — add unexported fields `channel, chaincode string` to the `Connection` struct in `connect.go` and set them in `Connect()` from `cfg.Channel` / `cfg.Chaincode` (two lines each). Drop the `strconv` blank-use line if nothing needs it.

- [ ] **Step 4: Delete the probe, build, test**

```bash
git rm -r packages/saksi-bulletin/client-sdk/cmd/qscc-probe
cd packages/saksi-bulletin/client-sdk && go build ./... && go vet ./... && go test ./...
```
Expected: all PASS, no vet issues.

- [ ] **Step 5: Commit**

```bash
git add -A packages/saksi-bulletin/client-sdk
git commit -m "feat(client-sdk): Ledger receipt API (SubmitWithReceipt/LedgerReceipt/ChainInfo); retire spike probe"
```

---

### Task 3: Console Fabric config + client-sdk dependency

**Files:**
- Create: `packages/saksi-campaign/fabric.go`
- Modify: `packages/saksi-campaign/go.mod` (+ require/replace), `packages/saksi-campaign/cmd/saksi-campaign/main.go` (flags)
- Test: `packages/saksi-campaign/fabric_test.go`

**Interfaces:**
- Consumes: `clientsdk.Connect(clientsdk.ConnectionConfig) (*clientsdk.Connection, error)`, `Connection.Ledger() clientsdk.Ledger`, `Connection.Bulletin *clientsdk.BulletinClient`, `Connection.Close() error`.
- Produces:

```go
type FabricConfig struct {
	PeerEndpoint, GatewayPeer, TLSCert, MSPID, Cert, Key, Channel, Chaincode string
}
func (c FabricConfig) Enabled() bool // all cert paths set
func (c FabricConfig) Connect() (*clientsdk.Connection, error)
```

- [ ] **Step 1: go.mod wiring**

In `packages/saksi-campaign/go.mod` add:

```
require github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk v0.0.0-00010101000000-000000000000

replace github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk => ../saksi-bulletin/client-sdk
```

Then `cd packages/saksi-campaign && go mod tidy`.

- [ ] **Step 2: Write failing test**

```go
package campaign

import "testing"

func TestFabricConfigEnabled(t *testing.T) {
	if (FabricConfig{}).Enabled() {
		t.Fatal("empty config must be disabled")
	}
	full := FabricConfig{
		PeerEndpoint: "localhost:7051", GatewayPeer: "peer0.org1.example.com",
		TLSCert: "/tls/ca.crt", MSPID: "Org1MSP", Cert: "/msp/cert.pem", Key: "/msp/key.pem",
		Channel: "saksi", Chaincode: "saksi-bulletin",
	}
	if !full.Enabled() {
		t.Fatal("full config must be enabled")
	}
	if (FabricConfig{PeerEndpoint: "localhost:7051"}).Enabled() {
		t.Fatal("partial config must be disabled")
	}
}
```

(Adjust `package campaign` to the actual package name used by the existing files — read `server.go`'s package line and match it.)

- [ ] **Step 3: Run — FAIL** (`FabricConfig` undefined). `go test ./... -run TestFabricConfigEnabled`

- [ ] **Step 4: Implement `fabric.go`**

```go
package campaign

import (
	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

// FabricConfig holds the connection material for on-chain mode. Zero-value =
// on-chain mode unavailable; the offline path never touches it.
type FabricConfig struct {
	PeerEndpoint string
	GatewayPeer  string
	TLSCert      string
	MSPID        string
	Cert         string
	Key          string
	Channel      string
	Chaincode    string
}

// Enabled reports whether every field needed to reach a live network is set.
func (c FabricConfig) Enabled() bool {
	return c.PeerEndpoint != "" && c.GatewayPeer != "" && c.TLSCert != "" &&
		c.MSPID != "" && c.Cert != "" && c.Key != "" && c.Channel != "" && c.Chaincode != ""
}

// Connect opens a gateway connection for this config.
func (c FabricConfig) Connect() (*clientsdk.Connection, error) {
	return clientsdk.Connect(clientsdk.ConnectionConfig{
		PeerEndpoint: c.PeerEndpoint,
		GatewayPeer:  c.GatewayPeer,
		TLSCertPath:  c.TLSCert,
		MSPID:        c.MSPID,
		CertPath:     c.Cert,
		KeyPath:      c.Key,
		Channel:      c.Channel,
		Chaincode:    c.Chaincode,
	})
}
```

In `cmd/saksi-campaign/main.go`, add flags mirroring the serve flags style, defaults matching the test-network: `--fabric-peer` (default `localhost:7051`), `--fabric-gateway-peer` (`peer0.org1.example.com`), `--fabric-tls-cert`, `--fabric-msp-id` (`Org1MSP`), `--fabric-cert`, `--fabric-key`, `--fabric-channel` (`saksi`), `--fabric-chaincode` (`saksi-bulletin`); build a `FabricConfig` and pass it through to the server/executor constructors (extend their signatures — follow how `--demo`/`--runs` travel today).

- [ ] **Step 5: Test + vet + commit**

```bash
cd packages/saksi-campaign && go build ./... && go vet ./... && go test ./...
git add -A packages/saksi-campaign
git commit -m "feat(campaign): Fabric connection config + client-sdk dependency"
```

---

### Task 4: Receipts recording (receipts.csv + trail.json)

**Files:**
- Create: `packages/saksi-campaign/receipts.go`
- Test: `packages/saksi-campaign/receipts_test.go`

**Interfaces:**
- Consumes: `clientsdk.Receipt` (Task 1).
- Produces:

```go
type TrailEvent struct {
	Event   string            `json:"event"`   // CreateElection | PublishDKGTranscript | SubmitBallot | CloseElection | SubmitPartialDecryption | PublishTally
	Ref     string            `json:"ref"`     // e.g. ballot index "3", trustee id, or "" for singletons
	Receipt clientsdk.Receipt `json:"receipt"`
}
func appendReceipt(runDir string, ev TrailEvent) error // appends receipts.csv + rewrites trail.json
```

- [ ] **Step 1: Write failing test**

```go
package campaign

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

func TestAppendReceipt(t *testing.T) {
	dir := t.TempDir()
	ev := TrailEvent{Event: "SubmitBallot", Ref: "0", Receipt: clientsdk.Receipt{
		TxID: "tx1", BlockNumber: 7,
		BlockHash: []byte{0xaa}, DataHash: []byte{0xbb}, PreviousHash: []byte{0xcc},
	}}
	if err := appendReceipt(dir, ev); err != nil {
		t.Fatal(err)
	}
	if err := appendReceipt(dir, TrailEvent{Event: "CloseElection", Receipt: clientsdk.Receipt{TxID: "tx2", BlockNumber: 8}}); err != nil {
		t.Fatal(err)
	}

	csvBytes, err := os.ReadFile(filepath.Join(dir, "receipts.csv"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(csvBytes)), "\n")
	if len(lines) != 3 { // header + 2 rows
		t.Fatalf("want 3 csv lines, got %d: %q", len(lines), lines)
	}
	if lines[0] != "event,ref,tx_id,block_number,block_hash,data_hash,previous_hash" {
		t.Fatalf("bad header: %s", lines[0])
	}
	if !strings.HasPrefix(lines[1], "SubmitBallot,0,tx1,7,aa,bb,cc") {
		t.Fatalf("bad row: %s", lines[1])
	}

	var trail []TrailEvent
	data, err := os.ReadFile(filepath.Join(dir, "trail.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &trail); err != nil {
		t.Fatal(err)
	}
	if len(trail) != 2 || trail[1].Event != "CloseElection" {
		t.Fatalf("bad trail: %+v", trail)
	}
}
```

- [ ] **Step 2: Run — FAIL.** `go test ./... -run TestAppendReceipt`

- [ ] **Step 3: Implement `receipts.go`**

```go
package campaign

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

// TrailEvent is one lifecycle event's ledger receipt, as recorded in the run
// folder (receipts.csv for the evidence-CSV export set, trail.json for the UI).
type TrailEvent struct {
	Event   string            `json:"event"`
	Ref     string            `json:"ref"`
	Receipt clientsdk.Receipt `json:"receipt"`
}

const receiptsCSVHeader = "event,ref,tx_id,block_number,block_hash,data_hash,previous_hash"

// appendReceipt appends the event to receipts.csv (creating it with a header)
// and rewrites trail.json with the full ordered event list.
func appendReceipt(runDir string, ev TrailEvent) error {
	csvPath := filepath.Join(runDir, "receipts.csv")
	newFile := false
	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		newFile = true
	}
	f, err := os.OpenFile(csvPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open receipts.csv: %w", err)
	}
	defer f.Close()
	if newFile {
		if _, err := fmt.Fprintln(f, receiptsCSVHeader); err != nil {
			return err
		}
	}
	r := ev.Receipt
	if _, err := fmt.Fprintf(f, "%s,%s,%s,%d,%s,%s,%s\n",
		ev.Event, ev.Ref, r.TxID, r.BlockNumber,
		hex.EncodeToString(r.BlockHash), hex.EncodeToString(r.DataHash), hex.EncodeToString(r.PreviousHash)); err != nil {
		return err
	}

	trailPath := filepath.Join(runDir, "trail.json")
	var trail []TrailEvent
	if data, err := os.ReadFile(trailPath); err == nil {
		_ = json.Unmarshal(data, &trail) // corrupt trail.json: start over rather than fail the run
	}
	trail = append(trail, ev)
	data, err := json.MarshalIndent(trail, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(trailPath, data, 0o644)
}
```

- [ ] **Step 4: Run — PASS.** `go test ./... -run TestAppendReceipt`

- [ ] **Step 5: Commit**

```bash
git add packages/saksi-campaign/receipts.go packages/saksi-campaign/receipts_test.go
git commit -m "feat(campaign): per-event receipts.csv + trail.json recording"
```

---

### Task 5: On-chain Submit orchestration

**Files:**
- Modify: `packages/saksi-campaign/executor.go` (the Submit phase's onchain branch — read the current `Submit` method first; today it is a network-gated placeholder)
- Test: `packages/saksi-campaign/executor_onchain_test.go`

**Interfaces:**
- Consumes: `clientsdk.Ledger` (Task 2), `appendReceipt` (Task 4), `FabricConfig` (Task 3), the executor's existing `publish(runID, phase, level, msg)` SSE helper and run-folder path helper (read `executor.go` for exact names and follow them).
- Produces: `func (e *Executor) submitOnChain(ctx context.Context, runID string, c Config, led clientsdk.Ledger, bundlePath string) error` — the testable core, called by the Submit phase when `c.Mode == "onchain"` && FabricConfig.Enabled(). Bundle generation: the Submit phase shells the existing `--demo` binary: `saksi-demo gen --voters N --positions P --candidates C --trustees n --threshold t --election-id <runID> --election-name <name> --trustee-names <a,b,...> <runDir>/bundle.json` (mirror how Generate already shells it).

**Lifecycle order (assert in tests):** CreateElection(params) → PublishDKGTranscript(dkg) → SubmitBallot × each ballot → CloseElection(electionID) → SubmitPartialDecryption(electionID, partial) × each → PublishTally(tally). Args come from the bundle JSON — reuse the bundle struct shape from `cmd/saksi-console/main.go:33-45` (copy the struct into the campaign package; the console cmd's is package-main).

- [ ] **Step 1: Write failing test with a fake Ledger**

```go
package campaign

import (
	"context"
	"errors"
	"fmt"
	"testing"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

type fakeLedger struct {
	calls   []string // "fn arg0-prefix"
	failOn  string   // fn name to fail on ("" = never)
	nextBlk uint64
}

func (f *fakeLedger) SubmitWithReceipt(fn string, args ...string) ([]byte, clientsdk.Receipt, error) {
	f.calls = append(f.calls, fn)
	if fn == f.failOn {
		return nil, clientsdk.Receipt{}, errors.New("boom")
	}
	f.nextBlk++
	return nil, clientsdk.Receipt{TxID: fmt.Sprintf("tx-%d", f.nextBlk), BlockNumber: f.nextBlk}, nil
}
func (f *fakeLedger) LedgerReceipt(string) (clientsdk.Receipt, error) { return clientsdk.Receipt{}, nil }
func (f *fakeLedger) ChainInfo() (uint64, []byte, error)             { return f.nextBlk + 1, nil, nil }

func writeTestBundle(t *testing.T, dir string) string {
	t.Helper()
	// Minimal bundle: 2 ballots, 2 partial decryptions. Hex payloads are
	// opaque to the orchestrator — any string works against the fake.
	path := dir + "/bundle.json"
	data := `{"election_id":"run-1","params":"aa","dkg":"bb","ballots":["b0","b1"],"partial_decryptions":["p0","p1"],"tally":"tt"}`
	if err := osWriteFile(path, []byte(data)); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSubmitOnChainOrder(t *testing.T) {
	dir := t.TempDir()
	led := &fakeLedger{}
	e := newTestExecutor(t, dir) // use the same constructor pattern executor_test.go already uses
	err := e.submitOnChain(context.Background(), "run-1", Config{}, led, writeTestBundle(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"CreateElection", "PublishDKGTranscript", "SubmitBallot", "SubmitBallot", "CloseElection", "SubmitPartialDecryption", "SubmitPartialDecryption", "PublishTally"}
	if len(led.calls) != len(want) {
		t.Fatalf("calls = %v", led.calls)
	}
	for i := range want {
		if led.calls[i] != want[i] {
			t.Fatalf("call %d = %s, want %s (all: %v)", i, led.calls[i], want[i], led.calls)
		}
	}
}

func TestSubmitOnChainFailsLoudMidLifecycle(t *testing.T) {
	dir := t.TempDir()
	led := &fakeLedger{failOn: "CloseElection"}
	e := newTestExecutor(t, dir)
	err := e.submitOnChain(context.Background(), "run-1", Config{}, led, writeTestBundle(t, dir))
	if err == nil {
		t.Fatal("want error when CloseElection fails")
	}
	// Partial receipts must be preserved: header + 4 rows (create, dkg, 2 ballots).
	// Read receipts.csv from the run folder and count lines = 5.
}
```

Adapt `newTestExecutor` / run-folder access to the existing patterns in `executor_test.go` (there is already a test executor setup — reuse it, don't invent a parallel one). `osWriteFile` = `os.WriteFile` with imports; finish the mid-failure test's receipt count assertion concretely against the executor's run-dir helper.

- [ ] **Step 2: Run — FAIL** (`submitOnChain` undefined).

- [ ] **Step 3: Implement `submitOnChain`**

```go
// bundle mirrors the JSON emitted by `saksi-demo gen` (fields the on-chain
// lifecycle needs; same shape as cmd/saksi-console's).
type bundle struct {
	ElectionID         string   `json:"election_id"`
	Params             string   `json:"params"`
	DKG                string   `json:"dkg"`
	Ballots            []string `json:"ballots"`
	PartialDecryptions []string `json:"partial_decryptions"`
	Tally              string   `json:"tally"`
}

func (e *Executor) submitOnChain(ctx context.Context, runID string, c Config, led clientsdk.Ledger, bundlePath string) error {
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	var b bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return fmt.Errorf("parse bundle: %w", err)
	}
	runDir := e.runDir(runID) // use the executor's actual run-dir helper name

	step := func(event, ref, fn string, args ...string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, receipt, err := led.SubmitWithReceipt(fn, args...)
		if err != nil {
			e.publish(runID, "submit", "error", fmt.Sprintf("%s %s: %v", event, ref, err))
			return fmt.Errorf("%s: %w", event, err)
		}
		if err := appendReceipt(runDir, TrailEvent{Event: event, Ref: ref, Receipt: receipt}); err != nil {
			return err
		}
		e.publish(runID, "submit", "info", fmt.Sprintf("%s %s committed: block %d tx %s",
			event, ref, receipt.BlockNumber, receipt.TxID))
		return nil
	}

	if err := step("CreateElection", "", "CreateElection", b.Params); err != nil {
		return err
	}
	if err := step("PublishDKGTranscript", "", "PublishDKGTranscript", b.DKG); err != nil {
		return err
	}
	for i, ballot := range b.Ballots {
		if err := step("SubmitBallot", strconv.Itoa(i), "SubmitBallot", ballot); err != nil {
			return err
		}
	}
	if err := step("CloseElection", "", "CloseElection", b.ElectionID); err != nil {
		return err
	}
	for i, pd := range b.PartialDecryptions {
		if err := step("SubmitPartialDecryption", strconv.Itoa(i), "SubmitPartialDecryption", b.ElectionID, pd); err != nil {
			return err
		}
	}
	if err := step("PublishTally", "", "PublishTally", b.Tally); err != nil {
		return err
	}
	e.publish(runID, "submit", "done", "full lifecycle committed on-chain")
	return nil
}
```

Wire the Submit phase: where `Executor.Submit` currently handles/skips on-chain, branch: `Mode=="onchain"` and fabric enabled → gen bundle (shell the demo binary with the run's config, election-id = runID, into `<runDir>/bundle.json`), `conn, err := e.fabric.Connect()`, `defer conn.Close()`, call `submitOnChain(ctx, runID, c, conn.Ledger(), bundlePath)`. Mode offline: existing behavior untouched. Chaincode arg forms MUST match `cmd/saksi-console/main.go`'s calls (read them: CreateElection takes params hex; CloseElection takes electionID; SubmitPartialDecryption takes electionID + partial hex; PublishTally takes tally hex).

- [ ] **Step 4: Run all campaign tests — PASS.** `go test ./...` (offline tests must stay green.)

- [ ] **Step 5: Commit**

```bash
git add -A packages/saksi-campaign
git commit -m "feat(campaign): on-chain Submit drives the full lifecycle with per-event receipts"
```

---

### Task 6: Trail API route + unlock gate

**Files:**
- Modify: `packages/saksi-campaign/server.go` (routes), constructor to accept the fabric config/connection factory
- Create: `packages/saksi-campaign/trail.go`
- Test: `packages/saksi-campaign/trail_test.go`

**Interfaces:**
- Consumes: `clientsdk.Ledger` (receipts), `BulletinClient` reads — abstract them behind a small local interface so tests mock both:

```go
// chainReader is what the trail needs from the chain. *clientsdk.BulletinClient
// satisfies it (compile-check with var _ chainReader = (*clientsdk.BulletinClient)(nil)).
type chainReader interface {
	GetElectionStatus(electionID string) (string, error)
	GetElection(electionID string) (string, error)
	GetDKGTranscript(electionID string) (string, error)
	GetTally(electionID string) (string, error)
	ListNullifiers(electionID string, pageSize int, bookmark string) (clientsdk.NullifierPage, error)
}
```
- Produces: `GET /api/trail/{electionID}` JSON and `buildTrail(reader chainReader, runDir, electionID string, operator bool) (trailResponse, error)`.

**Gate rules (test all three):** status ≠ `"tallied"` → sealed (unless operator). Status error → sealed + the error logged, never surfaced as open. Operator flag honored only when request remote addr is loopback (handler-level check; `buildTrail` just takes the bool).

**Trail response shape:**

```go
type trailResponse struct {
	Sealed   bool         `json:"sealed"`
	Status   string       `json:"status,omitempty"`
	Election string       `json:"election_id"`
	Events   []TrailEvent `json:"events,omitempty"` // from trail.json (recorded receipts)
	Live     *liveProof   `json:"live,omitempty"`   // fresh chain reads proving the records exist NOW
}
type liveProof struct {
	StatusNow     string `json:"status_now"`
	NullifierRows int    `json:"nullifier_count"`
	TallyHex      string `json:"tally_hex,omitempty"`
	ChainHeight   uint64 `json:"chain_height"`
	TipHash       string `json:"tip_hash"`
}
```

(Events carry the recorded receipts; Live re-proves against the chain at render time — both, per the approved live+export decision. On-chain data only: nullifiers, hex blobs, counts. No voter identity exists in any of these.)

- [ ] **Step 1: Write failing tests** — mock `chainReader` + fake `Ledger` (reuse Task 5's `fakeLedger`); table-test: (a) status "open" → sealed, no events; (b) status "tallied" → open, events from a fixture trail.json, live proof populated; (c) reader error → sealed; (d) operator=true + status "open" → open with events. Follow `server_test.go`'s `testServer` harness for the HTTP-level tests: `GET /api/trail/run-1` (loopback → operator honored; also assert the JSON decodes to `trailResponse`).

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement `trail.go` + route wiring.** `handleTrailAPI` parses `/api/trail/`, `operator := r.URL.Query().Get("operator") == "1" && isLoopback(r.RemoteAddr)`, connects (or reuses a lazily-opened cached connection guarded by a mutex), calls `buildTrail`, writes JSON. Chain unreachable → `http.Error(w, "chain unreachable: …", http.StatusBadGateway)`. Register in `NewServer`: `mux.HandleFunc("/api/trail/", s.handleTrailAPI)` and `mux.HandleFunc("/trail/", s.handleTrailPage)` (page in Task 7; register both now with the page returning 501 until Task 7 lands — or wire the page handler in Task 7; either is fine, keep the route list together).

- [ ] **Step 4: Run all tests — PASS. vet clean.**

- [ ] **Step 5: Commit** — `feat(campaign): /api/trail with threshold-unlock gate (fail-closed)`

---

### Task 7: Trail UI — public page + operator panel

**Files:**
- Create: `packages/saksi-campaign/web/trail.html` (embedded via the same `webFS` embed as index)
- Modify: `packages/saksi-campaign/web/index.html` (operator Trail panel), `packages/saksi-campaign/server.go` (`handleTrailPage` serves trail.html)
- Test: `packages/saksi-campaign/web_test.go` (extend: trail.html embeds + contains the sealed banner markup), `server_test.go` (GET /trail/x returns 200 text/html)

**Content requirements (both themes, same token system as index.html):**
- Sealed state: prominent banner — "Election in progress — results are not yet unlocked. This page opens when ≥t trustees have published the tally." + current status pill. NOTHING else (no counts, no events).
- Open state: header (election id/name, chain height, tip hash), then a vertical timeline: one row per event — event name, ref, `block #N`, tx id (truncated, monospace, click-to-copy), block hash (truncated); tally table at the end (contest → counts). Rows link receipts: hovering/expanding a row shows data_hash/previous_hash full values.
- Fetches `/api/trail/<id>` (id from the URL path) on load + a Refresh button; operator panel in index.html polls the same API with `?operator=1` during/after on-chain runs and renders the same timeline component (copy the small render function into index.html's script — the two files stay self-contained; a shared JS file is NOT worth breaking the single-file convention both files follow).

- [ ] **Step 1: Failing test** — extend the existing web embed test pattern: assert `web/trail.html` is embedded, contains `id="sealed-banner"` and `id="timeline"`, and `server_test.go`: `GET /trail/anything` → 200, `Content-Type: text/html`.
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement** trail.html (self-contained, theme-aware per the console's existing `:root`/`data-theme` pattern), `handleTrailPage`, and the index.html operator panel (appears when a run's config mode is onchain; shows live event rows from `/api/trail/<runID>?operator=1`).
- [ ] **Step 4: All tests PASS; open the page manually against a mock later (live check is Task 9).**
- [ ] **Step 5: Commit** — `feat(campaign): public sealed/open trail page + operator trail panel`

---

### Task 8: CI integration (balotachain repo)

**Files (balotachain repo, branch `spike/qscc-ci` → rename commit onto a `ci/audit-trail` branch):**
- Modify: `.github/workflows/ci.yml` — replace the THROWAWAY spike step with the audit-trail assertion step; point the saksi checkout `ref:` at `onchain-audit-trail`.

**Step content (single CI step after the demo cycle):**

```sh
# Build the console, start it against the live network, drive one on-chain run
# over HTTP, and assert the gate + receipts.
ORG="$FABRIC_SAMPLES/test-network/organizations/peerOrganizations/org1.example.com"
MSP="$ORG/users/User1@org1.example.com/msp"
cd saksi
cargo build --release -p saksi-demo
cd packages/saksi-campaign
go build -o /tmp/saksi-campaign ./cmd/saksi-campaign
/tmp/saksi-campaign serve --addr 127.0.0.1:8090 \
  --demo ../../target/release/saksi-demo --runs /tmp/runs \
  --fabric-tls-cert "$ORG/peers/peer0.org1.example.com/tls/ca.crt" \
  --fabric-cert "$(find "$MSP/signcerts" -type f | head -n1)" \
  --fabric-key "$(find "$MSP/keystore" -type f | head -n1)" &
CONSOLE_PID=$!; trap 'kill $CONSOLE_PID 2>/dev/null || true' EXIT
for i in $(seq 1 20); do curl -fsS 127.0.0.1:8090/ >/dev/null && break || sleep 1; done

RUN_ID=$(curl -fsS -X POST 127.0.0.1:8090/generate -H 'Content-Type: application/json' -d '{
  "name":"ci-trail","trustees":[{"name":"a"},{"name":"b"},{"name":"c"}],"threshold":2,
  "positions":1,"candidates":2,"voters":3,"distribution":"uniform","mode":"onchain"}' | jq -r .run_id)
# Submit runs async — poll trail (operator view, loopback) until PublishTally lands or timeout.
curl -fsS -X POST 127.0.0.1:8090/submit -H 'Content-Type: application/json' -d "{\"run_id\":\"$RUN_ID\"}"
for i in $(seq 1 60); do
  OPEN=$(curl -fsS "127.0.0.1:8090/api/trail/$RUN_ID?operator=1" | jq -r '.sealed == false' || echo false)
  [ "$OPEN" = "true" ] && break; sleep 5
done
TRAIL=$(curl -fsS "127.0.0.1:8090/api/trail/$RUN_ID?operator=1")
echo "$TRAIL" | jq .
echo "$TRAIL" | jq -e '.sealed == false'
echo "$TRAIL" | jq -e '.events | length >= 8'            # create+dkg+3 ballots+close+2 partials+tally
echo "$TRAIL" | jq -e '[.events[].receipt.BlockNumber] as $b | $b == ($b | sort)'  # monotonic blocks
test -f "/tmp/runs/$RUN_ID/receipts.csv"
# Public (non-operator) gate must be OPEN now that the tally is published:
curl -fsS "127.0.0.1:8090/api/trail/$RUN_ID" | jq -e '.sealed == false'
```

Note: the SEALED-before-tally assertion needs a mid-run probe — add right after the submit POST: `curl -fsS "127.0.0.1:8090/api/trail/$RUN_ID" | jq -e '.sealed == true'` (the lifecycle takes long enough that the first public read lands pre-tally; if flaky, drop this line rather than sleep-tuning). JSON field name casing: match `trailResponse`'s actual tags (`receipt` fields marshal with Go names unless tagged — tag `Receipt` fields lowercase in Task 4 if this bites; keep CI's jq in sync with the tags chosen).

- [ ] Steps: edit workflow on a `ci/audit-trail` balotachain branch (prettier-format it), push, `gh workflow run ci.yml --ref ci/audit-trail`, iterate to green, capture the trail JSON from the log into the PR description.
- [ ] Commit — `ci(fabric): assert the on-chain audit trail end-to-end (gate + receipts)`

---

### Task 9: WSL environment + live demo smoke

**No repo files** (environment task) — record outcomes in the PR/update doc.

- [ ] Enable Docker Desktop → Settings → Resources → WSL integration → Ubuntu; verify `wsl -d Ubuntu -- docker version`.
- [ ] In WSL: install Go (go.dev tarball → /usr/local/go) + Rust (rustup); `git clone <github saksi> ~/saksi && cd ~/saksi && git switch onchain-audit-trail` (or clone from `/mnt/q/...` to avoid auth).
- [ ] `cd ~ && curl -sSL https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh | bash -s -- --fabric-version 2.5.15 docker samples binary`
- [ ] `cd ~/saksi/packages/saksi-bulletin/network && ./network.sh all`
- [ ] On Windows: run the console with `--fabric-*` flags pointing at `localhost:7051` and certs via `\\wsl$\Ubuntu\home\<user>\fabric-samples\test-network\organizations\...`; configure an on-chain run in the browser, Run all, watch the operator trail panel fill with receipts; open `/trail/<run-id>` mid-run (sealed) and after (open). Screenshot both states.
- [ ] `./network.sh down` when done.

---

## Self-Review (done at write time)

- **Spec coverage:** SDK API (T1-2), console Submit (T3-5), trail+gate (T6), UI (T7), tests (each task + T8 CI), WSL env (T9), receipts export (T4), operator loopback rule (T6), ASN.1 hash (T1). Out-of-scope items from the spec have no tasks — correct.
- **Placeholders:** none; every code step carries real code. T5/T6 reference existing helper names (`publish`, run-dir, `testServer`) with instructions to read-and-match rather than invented signatures.
- **Type consistency:** `Receipt` fields consistent T1→T4→T8 (T8 notes the JSON-tag casing decision explicitly); `TrailEvent` consistent T4→T6; `fakeLedger` satisfies the T2 `Ledger` interface.
