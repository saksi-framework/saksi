// Command saksi-r14-test runs the R14 precinct-machine test against a live
// network: two precinct elections bound to two machines, then the five cases
// (registered machine accepted, unregistered client and the other precinct's
// machine refused at gate caller, non-admin setup refused at gate admin, and
// the verifier over precinct A). It writes r14-evidence.json and the raw logs
// into --out. tools/r14-machine-test.sh builds and runs it; see that script
// for bringing the network up.
//
// Exit status: 0 every case passed, 1 a case failed or the run aborted,
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
	fs := flag.NewFlagSet("saksi-r14-test", flag.ExitOnError)
	stampDefault := strings.ToLower(time.Now().UTC().Format("20060102t150405"))
	out := fs.String("out", "", "output directory (default r14-<stamp> in the working directory)")
	demoBin := fs.String("demo", "saksi-demo", "path to the saksi-demo binary (generator and auditor)")
	stamp := fs.String("stamp", stampDefault, "election id stamp: elections are r14-<stamp>-p01 and -p02")
	voters := fs.Int("voters", 20, "precinct A's voters")
	positions := fs.Int("positions", 3, "positions per ballot")
	candidates := fs.Int("candidates", 4, "candidates per position")
	trustees := fs.Int("trustees", 5, "trustees")
	threshold := fs.Int("threshold", 3, "decryption threshold")
	distribution := fs.String("distribution", "uniform", "generator selection distribution (uniform|skewed|realistic)")
	concurrency := fs.Int("concurrency", 32, "case 1 ballots in flight")
	orgDir := fs.String("org-dir", "", "test-network org folder, e.g. <fabric-samples>/test-network/organizations/peerOrganizations/org1.example.com (Admin, User1, User2, User3 are read from <org-dir>/users)")
	peer := fs.String("peer", "localhost:7051", "gateway peer endpoint")
	gatewayPeer := fs.String("gateway-peer", "peer0.org1.example.com", "gateway peer TLS server name")
	tlsCert := fs.String("tls-cert", "", "peer TLS CA certificate (default <org-dir>/peers/<gateway-peer>/tls/ca.crt)")
	mspID := fs.String("msp-id", "Org1MSP", "MSP id of every identity")
	channel := fs.String("channel", "saksi", "channel")
	chaincode := fs.String("chaincode", "saksi-bulletin", "chaincode name")
	commit := fs.String("commit", "", "saksi commit the network and binaries were built from (recorded in the evidence)")
	chaincodeID := fs.String("chaincode-package-id", "", "installed chaincode package id (recorded in the evidence)")
	dryRun := fs.Bool("dry-run", false, "print the plan of calls and identities; contact nothing")
	timeout := fs.Duration("timeout", 2*time.Hour, "whole-run timeout")
	_ = fs.Parse(os.Args[1:])

	if *orgDir == "" {
		fatal(2, "--org-dir is required")
	}
	if *tlsCert == "" {
		*tlsCert = filepath.Join(*orgDir, "peers", *gatewayPeer, "tls", "ca.crt")
	}
	if *out == "" {
		*out = "r14-" + *stamp
	}

	ids, paths, missing := resolveIdentities(*orgDir)
	cfg := campaign.MachineTestConfig{
		OutDir: *out, DemoBin: *demoBin, Stamp: *stamp,
		Voters: *voters, Positions: *positions, Candidates: *candidates,
		Trustees: *trustees, Threshold: *threshold, Distribution: *distribution,
		Concurrency: *concurrency, Identities: ids, Commit: *commit,
		Network: map[string]string{
			"peer": *peer, "gateway_peer": *gatewayPeer, "msp_id": *mspID,
			"channel": *channel, "chaincode": *chaincode, "chaincode_package_id": *chaincodeID,
			"org_dir": *orgDir,
		},
		Log: os.Stdout,
	}
	if *dryRun {
		campaign.R14DryRun(os.Stdout, cfg)
		for _, m := range missing {
			fmt.Printf("note: %s\n", m)
		}
		return
	}
	if len(missing) > 0 {
		fatal(2, "cannot start:\n  %s\nbring the network up with SAKSI_ORG1_USERS=3 (network.sh up) so Org1 issues User1..User3", strings.Join(missing, "\n  "))
	}
	if err := cfg.Validate(); err != nil {
		fatal(2, "%v", err)
	}
	self, _ := os.Executable()
	demoPath := *demoBin
	if p, err := lookPath(demoPath); err == nil {
		demoPath = p
	}
	cfg.Binaries = map[string]string{"saksi-r14-test": self, "saksi-demo": demoPath}

	chain := campaign.MachineTestChain{Actors: map[string]campaign.MachineTestActor{}}
	var conns []*clientsdk.Connection
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for _, id := range campaign.R14Identities {
		conn, err := clientsdk.Connect(clientsdk.ConnectionConfig{
			PeerEndpoint: *peer, GatewayPeer: *gatewayPeer, TLSCertPath: *tlsCert, MSPID: *mspID,
			CertPath: paths[id.Key][0], KeyPath: paths[id.Key][1], Channel: *channel, Chaincode: *chaincode,
		})
		if err != nil {
			fatal(2, "connect as %s: %v", id.User, err)
		}
		conns = append(conns, conn)
		// A connection with only a default identity signs every
		// transaction as that identity, whatever the function.
		chain.Actors[id.Key] = conn.Ledger()
		if fp := conn.MachineFingerprint(); fp != ids[id.Key].Fingerprint {
			fatal(2, "%s: connection fingerprint %s differs from the certificate's %s", id.User, fp, ids[id.Key].Fingerprint)
		}
		if id.Key == campaign.R14Admin {
			chain.Reader = conn.Bulletin
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	ev, err := campaign.RunMachineTest(ctx, cfg, chain)
	if err != nil {
		fatal(2, "%v", err)
	}
	fmt.Println(strings.Repeat("-", 72))
	for _, c := range ev.Cases {
		fmt.Printf("[%s] %-5s %s\n", word(c.Pass), c.ID, c.Title)
	}
	if ev.Aborted != "" {
		fmt.Printf("ABORTED: %s\n", ev.Aborted)
	}
	fmt.Printf("R14: %s  evidence %s\n", word(ev.Pass), filepath.Join(*out, "r14-evidence.json"))
	if !ev.Pass {
		os.Exit(1)
	}
}

// resolveIdentities reads Admin, User1, User2 and User3 from the cryptogen
// layout under orgDir: the first file in each msp/signcerts and msp/keystore.
func resolveIdentities(orgDir string) (map[string]campaign.MachineTestIdentity, map[string][2]string, []string) {
	domain := filepath.Base(orgDir)
	// TestNetworkUser takes any user's certificate path; only its shape is read.
	anchor := filepath.Join(orgDir, "users", "Admin@"+domain, "msp", "signcerts", "cert.pem")
	ids := map[string]campaign.MachineTestIdentity{}
	paths := map[string][2]string{}
	var missing []string
	for _, id := range campaign.R14Identities {
		mi := campaign.MachineTestIdentity{User: id.User + "@" + domain, Role: id.Role}
		cert, key, err := clientsdk.TestNetworkUser(anchor, id.User)
		if err != nil {
			missing = append(missing, fmt.Sprintf("%s (%s): %v", id.User, id.Role, err))
		} else if mi.Fingerprint, err = clientsdk.CertFileFingerprint(cert); err != nil {
			missing = append(missing, fmt.Sprintf("%s: %v", id.User, err))
		}
		mi.Cert = cert
		ids[id.Key] = mi
		paths[id.Key] = [2]string{cert, key}
	}
	return ids, paths, missing
}

func lookPath(p string) (string, error) {
	if strings.ContainsRune(p, os.PathSeparator) {
		return filepath.Abs(p)
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		c := filepath.Join(dir, p)
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("%s not on PATH", p)
}

func word(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func fatal(code int, format string, a ...any) {
	fmt.Fprintf(os.Stderr, "saksi-r14-test: "+format+"\n", a...)
	os.Exit(code)
}
