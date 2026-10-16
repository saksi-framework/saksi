// saksi-canvass-demo drives the precinct-to-national smoke demonstration on a
// live Fabric network: each precinct-NN folder of one
// `saksi-demo gen --stream <dir> --precincts N` pass runs the console's
// on-chain lifecycle in turn on the one channel, signs a precinct return over
// its ledger read-back and transmits it to national/returns/, and the national
// canvass (`saksi-demo audit-canvass`) then runs over all of them.
//
//	saksi-canvass-demo --dir <gen dir> --demo <saksi-demo> --out <run folder> \
//	    --fabric-tls-cert … --fabric-cert … --fabric-key … \
//	    [--attack <id> --attack-script <cmd> --attack-pre-close-script <cmd>]
//
// It is a standalone driver: the console (/wizard) and its Executor runs are
// untouched. The network is NOT reset between precincts; reset it once before
// the run (tools/tier.sh).
//
// Exit codes: 0 canvass passed (or an attack run finished, whatever the
// verdict), 1 a clean run's canvass failed a check, 2 the run could not
// complete. canvass-run.json in --out records the details either way.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	campaign "github.com/saksi-framework/saksi/packages/saksi-campaign"
	"github.com/saksi-framework/saksi/packages/saksi-campaign/canvass"
)

func main() {
	fs := flag.NewFlagSet("saksi-canvass-demo", flag.ExitOnError)
	dir := fs.String("dir", "", "generator output dir (saksi-demo gen --stream <dir> --precincts N)")
	demoBin := fs.String("demo", "saksi-demo", "path to the saksi-demo binary")
	out := fs.String("out", "", "run folder for canvass-run.json, canvass.json, canvass-checks.csv (default --dir)")
	attack := fs.String("attack", "", "attack id this run mounts (e.g. T9); a failed canvass then exits 0")
	attackScript := fs.String("attack-script", "", "command run after each return is built (<precinct dir> <return.json> <national dir>) and once before the canvass (<national dir>)")
	preClose := fs.String("attack-pre-close-script", "", "command run after each precinct's ballots, before CloseElection (<precinct dir> <election id>)")
	// The console's Fabric flags, same names and defaults
	// (cmd/saksi-campaign/main.go).
	fabricPeer := fs.String("fabric-peer", "localhost:7051", "Fabric gateway peer endpoint (host:port)")
	fabricGatewayPeer := fs.String("fabric-gateway-peer", "peer0.org1.example.com", "Fabric gateway peer TLS server name")
	fabricTLSCert := fs.String("fabric-tls-cert", "", "path to the peer TLS CA certificate")
	fabricMSPID := fs.String("fabric-msp-id", "Org1MSP", "Fabric MSP id of the acting organization")
	fabricCert := fs.String("fabric-cert", "", "path to the client identity certificate")
	fabricKey := fs.String("fabric-key", "", "path to the client identity private key")
	fabricChannel := fs.String("fabric-channel", "saksi", "Fabric channel the bulletin board runs on")
	fabricChaincode := fs.String("fabric-chaincode", "saksi-bulletin", "deployed chaincode name")
	fabricPeerVolume := fs.String("fabric-peer-volume", "", "host path of the peer's ledger volume (enables perf.csv's ledger_bytes_delta)")
	_ = fs.Parse(os.Args[1:])

	fabric := campaign.FabricConfig{
		PeerEndpoint: *fabricPeer, GatewayPeer: *fabricGatewayPeer, TLSCert: *fabricTLSCert,
		MSPID: *fabricMSPID, Cert: *fabricCert, Key: *fabricKey,
		Channel: *fabricChannel, Chaincode: *fabricChaincode, PeerVolume: *fabricPeerVolume,
	}
	if *dir == "" {
		fatal("--dir is required")
	}
	if !fabric.Enabled() {
		fatal("a live Fabric network is required: pass --fabric-tls-cert, --fabric-cert and --fabric-key")
	}
	if (*attackScript != "" || *preClose != "") && *attack == "" {
		fatal("--attack-script and --attack-pre-close-script need --attack <id>")
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		fatal("%v", err)
	}
	if *out == "" {
		*out = abs
	}

	fmt.Printf("saksi-canvass-demo: %s on channel %s via %s\n", abs, fabric.Channel, fabric.PeerEndpoint)
	fmt.Println("  reminder: the network is NOT reset between precincts. Reset it once before this run")
	fmt.Println("  (tools/tier.sh), with host hygiene done first (disk compaction, free space, power).")
	if *attack != "" {
		fmt.Printf("  attack run: %s\n", *attack)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	exe := campaign.NewExecutor(campaign.NewRunStore(abs), nil, *demoBin, "", fabric)
	code, err := canvass.Run(ctx, canvass.Options{
		Dir: abs, Out: *out, DemoBin: *demoBin,
		Attack: *attack, AttackScript: *attackScript, PreCloseScript: *preClose,
		Chain: execChain{exe}, Run: runCmd, Log: os.Stdout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "saksi-canvass-demo: %v\n", err)
	}
	fmt.Printf("record: %s (exit %d)\n", filepath.Join(*out, canvass.RunFile), code)
	os.Exit(code)
}

// execChain is canvass.Chain over the console's own Executor.
type execChain struct{ e *campaign.Executor }

func (c execChain) Lifecycle(ctx context.Context, folder string, beforeClose func(context.Context) error) error {
	return c.e.PrecinctLifecycle(ctx, folder, beforeClose)
}

func (c execChain) Verify(ctx context.Context, folder string) (string, error) {
	sa, err := c.e.PrecinctVerify(ctx, folder)
	return sa.Overall, err
}

func (c execChain) ChainInfo(context.Context) (uint64, []byte, error) {
	return c.e.PrecinctChainInfo()
}

// runCmd runs a child with extra environment entries; stdout is returned even
// on a non-zero exit, and stderr is folded into the error.
func runCmd(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "saksi-canvass-demo: "+format+"\n", a...)
	os.Exit(2)
}
