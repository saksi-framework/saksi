package canvass

import (
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// readBackChain stands in for Fabric only: the lifecycle commits nothing, and
// the "chain read-back" is the precinct's own ballots in nullifier order (the
// order ListNullifiers serves), next to a copy of its header.
type readBackChain struct {
	t      *testing.T
	dir    string
	height uint64
}

func (c *readBackChain) Lifecycle(ctx context.Context, _ string, h Hooks) (string, error) {
	return "published", h.BeforeClose(ctx)
}

func (c *readBackChain) Verify(_ context.Context, folder string) (string, error) {
	pdir := filepath.Join(c.dir, folder)
	raw, err := os.ReadFile(filepath.Join(pdir, "ballots.ndjson"))
	if err != nil {
		return "", err
	}
	lines := strings.Fields(string(raw))
	key := func(line string) string {
		b, _ := hex.DecodeString(line)
		var ballot pb.Ballot
		if err := proto.Unmarshal(b, &ballot); err != nil {
			c.t.Fatalf("decode ballot: %v", err)
		}
		return hex.EncodeToString(ballot.GetCredentialPresentation().GetNullifier().GetValue())
	}
	sort.Slice(lines, func(i, k int) bool { return key(lines[i]) < key(lines[k]) })
	led := filepath.Join(pdir, "ledger")
	if err := os.MkdirAll(led, 0o755); err != nil {
		return "", err
	}
	h, err := os.ReadFile(filepath.Join(pdir, "header.json"))
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(led, "header.json"), h, 0o644); err != nil {
		return "", err
	}
	return "pass", os.WriteFile(filepath.Join(led, "ballots.ndjson"), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func (c *readBackChain) ChainInfo(context.Context) (uint64, []byte, error) {
	c.height += 7
	tip := make([]byte, 32)
	tip[0] = byte(c.height)
	return c.height, tip, nil
}

// TestRealSaksiDemoContract runs the driver against the real saksi-demo
// (sign-return and audit-canvass) over a real two-precinct generation, so the
// argument lists, close.json and the returns layout are checked against the
// binary rather than against this package's own reading of it. Opt-in:
// SAKSI_DEMO_BIN=<path to saksi-demo>.
func TestRealSaksiDemoContract(t *testing.T) {
	bin := os.Getenv("SAKSI_DEMO_BIN")
	if bin == "" {
		t.Skip("SAKSI_DEMO_BIN not set")
	}
	dir := t.TempDir()
	gen := exec.Command(bin, "gen", "--stream", dir, "--precincts", "2", "--voters", "12",
		"--positions", "2", "--candidates", "2", "--election-id", "drv", "--threshold", "2", "--trustees", "3")
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("gen: %v\n%s", err, out)
	}
	run := Runner(runForTest)
	o := Options{Dir: dir, Out: filepath.Join(dir, "run"), DemoBin: bin, Chain: &readBackChain{t: t, dir: dir}, Run: run}
	code, err := Run(context.Background(), o)
	rec := readRecord(t, o)
	if err != nil || code != ExitPass {
		t.Fatalf("code %d, err %v, record %+v", code, err, rec)
	}
	if len(rec.Precincts) != 2 || rec.Precincts[1].Records != 12 || rec.Precincts[1].Verified != 12 || rec.Precincts[1].CloseBlock != 14 {
		t.Fatalf("rows = %+v", rec.Precincts)
	}
	for _, f := range []string{"canvass.json", "canvass-checks.csv"} {
		if _, err := os.Stat(filepath.Join(o.Out, f)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}

	// The same generation with precinct 02's return dropped on the path is a
	// failed canvass, which a clean run reports as exit 1.
	dir2 := t.TempDir()
	if out, err := exec.Command(bin, "gen", "--stream", dir2, "--precincts", "2", "--voters", "12",
		"--positions", "2", "--candidates", "2", "--election-id", "drv2", "--threshold", "2", "--trustees", "3").CombinedOutput(); err != nil {
		t.Fatalf("gen: %v\n%s", err, out)
	}
	o2 := Options{Dir: dir2, Out: dir2, DemoBin: bin, Chain: &readBackChain{t: t, dir: dir2}, Run: run,
		Attack: "T13", AttackScript: "drop"}
	o2.Run = func(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
		if name == "drop" {
			if strings.HasSuffix(args[0], "precinct-02") {
				return nil, os.Remove(args[1])
			}
			return nil, nil
		}
		return runForTest(ctx, env, name, args...)
	}
	code, err = Run(context.Background(), o2)
	rec = readRecord(t, o2)
	if err != nil || code != ExitPass || rec.CanvassPass == nil || *rec.CanvassPass ||
		!strings.Contains(strings.Join(rec.FailedChecks, ","), "canvass.completeness") {
		t.Fatalf("attack run: code %d, err %v, failed %v", code, err, rec.FailedChecks)
	}
}

func runForTest(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stderr = os.Stderr
	return cmd.Output()
}
