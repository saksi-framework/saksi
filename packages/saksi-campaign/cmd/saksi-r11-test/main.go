// Command saksi-r11-test runs the R11 blackout-and-recovery test against a
// live network: one on-chain election through the console executor's
// lifecycle, a SIGKILL of the whole network (orderer, both peers, the
// chaincode containers) once a fraction of the ballot records has committed,
// a restart after the downtime, the executor's own journal-based resume, then
// the ceremony and the verifier. It writes r11-evidence.json and the raw logs
// into --out. tools/r11-blackout-test.sh builds and runs it.
//
// Exit status: 0 every check passed, 1 a check failed or the run aborted,
// 2 the test could not start.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	campaign "github.com/saksi-framework/saksi/packages/saksi-campaign"
)

func main() {
	fs := flag.NewFlagSet("saksi-r11-test", flag.ExitOnError)
	stampDefault := strings.ToLower(time.Now().UTC().Format("20060102t150405"))
	out := fs.String("out", "", "output directory (default r11-<stamp> in the working directory)")
	demoBin := fs.String("demo", "saksi-demo", "path to the saksi-demo binary (generator and auditor)")
	stamp := fs.String("stamp", stampDefault, "election name stamp")
	voters := fs.Int("voters", 20, "voters")
	positions := fs.Int("positions", 3, "positions per ballot")
	candidates := fs.Int("candidates", 4, "candidates per position")
	trustees := fs.Int("trustees", 5, "trustees")
	threshold := fs.Int("threshold", 3, "decryption threshold")
	distribution := fs.String("distribution", "uniform", "generator selection distribution (uniform|skewed|realistic)")
	concurrency := fs.Int("concurrency", 32, "ballots in flight")
	blackoutAt := fs.Float64("blackout-at", 0.4, "fraction of the ballot records committed when the network is killed")
	downtime := fs.Duration("downtime", 30*time.Second, "how long the network stays down")
	stopWindow := fs.String("stop-window", campaign.R11StopWithKill, "when the ballot window stops dispatching: with-kill (immediately before docker kill) or after-kill (once it returns)")
	readyTimeout := fs.Duration("ready-timeout", 5*time.Minute, "wait for the first successful query after the restart")
	ccGrace := fs.Duration("chaincode-grace", time.Minute, "time the peers get to relaunch the chaincode containers before the harness starts them")
	project := fs.String("compose-project", "r14", "compose project the orderer and peers must belong to")
	orgDir := fs.String("org-dir", "", "test-network org folder, e.g. <fabric-samples>/test-network/organizations/peerOrganizations/org1.example.com")
	peer := fs.String("peer", "localhost:7051", "gateway peer endpoint")
	gatewayPeer := fs.String("gateway-peer", "peer0.org1.example.com", "gateway peer TLS server name")
	tlsCert := fs.String("tls-cert", "", "peer TLS CA certificate (default <org-dir>/peers/<gateway-peer>/tls/ca.crt)")
	mspID := fs.String("msp-id", "Org1MSP", "MSP id")
	channel := fs.String("channel", "saksi", "channel")
	chaincode := fs.String("chaincode", "saksi-bulletin", "chaincode name")
	commit := fs.String("commit", "", "saksi commit (recorded in the evidence)")
	chaincodeID := fs.String("chaincode-package-id", "", "installed chaincode package id (recorded in the evidence)")
	dryRun := fs.Bool("dry-run", false, "print the plan; contact nothing")
	timeout := fs.Duration("timeout", 3*time.Hour, "whole-run timeout")
	_ = fs.Parse(os.Args[1:])

	if *out == "" {
		*out = "r11-" + *stamp
	}
	cfg := campaign.BlackoutConfig{
		OutDir: *out, DemoBin: *demoBin, Stamp: *stamp,
		Voters: *voters, Positions: *positions, Candidates: *candidates,
		Trustees: *trustees, Threshold: *threshold, Distribution: *distribution,
		Concurrency: *concurrency, BlackoutAt: *blackoutAt, Downtime: *downtime,
		ReadyTimeout: *readyTimeout, ChaincodeGrace: *ccGrace, StopWindow: *stopWindow,
		ComposeProject: *project, Chaincode: *chaincode, Commit: *commit,
		Network: map[string]string{
			"peer": *peer, "gateway_peer": *gatewayPeer, "msp_id": *mspID,
			"channel": *channel, "chaincode": *chaincode, "chaincode_package_id": *chaincodeID,
			"org_dir": *orgDir, "compose_project": *project,
		},
		Log: os.Stdout,
	}
	if *dryRun {
		campaign.R11DryRun(os.Stdout, cfg)
		if err := cfg.Validate(); err != nil {
			fmt.Printf("\nnote: %v\n", err)
		}
		return
	}
	if err := cfg.Validate(); err != nil {
		fatal(2, "%v", err)
	}
	if *orgDir == "" {
		fatal(2, "--org-dir is required")
	}
	if *tlsCert == "" {
		*tlsCert = filepath.Join(*orgDir, "peers", *gatewayPeer, "tls", "ca.crt")
	}
	domain := filepath.Base(*orgDir)
	anchor := filepath.Join(*orgDir, "users", "Admin@"+domain, "msp", "signcerts", "cert.pem")
	cert, key, err := clientsdk.TestNetworkUser(anchor, "User1")
	if err != nil {
		fatal(2, "User1 (the precinct machine): %v", err)
	}
	fabric := campaign.FabricConfig{
		PeerEndpoint: *peer, GatewayPeer: *gatewayPeer, TLSCert: *tlsCert, MSPID: *mspID,
		Cert: cert, Key: key, Channel: *channel, Chaincode: *chaincode,
	}
	if err := fabric.ResolveTestNetworkRoles(); err != nil {
		fatal(2, "%v", err)
	}
	cfg.Network["admin_cert"], cfg.Network["machine_cert"] = fabric.AdminCert, fabric.MachineCert
	if fp, err := clientsdk.CertFileFingerprint(fabric.MachineCert); err == nil {
		cfg.Network["machine_fingerprint"] = fp
	}
	cfg.Dial = func() (campaign.BlackoutConn, error) {
		conn, err := fabric.Connect()
		if err != nil {
			return campaign.BlackoutConn{}, err
		}
		return campaign.BlackoutConn{Ledger: conn.Ledger(), Reader: conn.Bulletin, Close: func() { _ = conn.Close() }}, nil
	}
	self, _ := os.Executable()
	demoPath := *demoBin
	if p, err := filepath.Abs(demoPath); err == nil && strings.ContainsRune(demoPath, os.PathSeparator) {
		demoPath = p
	}
	cfg.DemoBin = demoPath
	cfg.Binaries = map[string]string{"saksi-r11-test": self, "saksi-demo": demoPath}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	ev, err := campaign.RunBlackoutTest(ctx, cfg)
	if err != nil {
		fatal(2, "%v", err)
	}
	fmt.Println(strings.Repeat("-", 72))
	fmt.Printf("records %d: C %d, U %d, N %d; downtime %d ms; ready %d ms after start\n",
		ev.Classification.Records, ev.Classification.Committed, ev.Classification.Uncertain,
		ev.Classification.NotSent, ev.Blackout.DowntimeMs, ev.Blackout.TimeToReadyMs)
	for _, c := range ev.Checks {
		fmt.Printf("[%s] %-26s %s\n", word(c.Pass), c.ID, c.Observed)
	}
	if ev.Aborted != "" {
		fmt.Printf("ABORTED: %s\n", ev.Aborted)
	}
	fmt.Printf("R11: %s  evidence %s\n", word(ev.Pass), filepath.Join(*out, "r11-evidence.json"))
	if !ev.Pass {
		os.Exit(1)
	}
}

func word(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func fatal(code int, format string, a ...any) {
	fmt.Fprintf(os.Stderr, "saksi-r11-test: "+format+"\n", a...)
	os.Exit(code)
}
