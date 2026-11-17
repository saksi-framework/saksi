// Command saksi-campaign serves the Research Election Console — a loopback web
// app to configure + run the paper's elections in phases.
//
//	saksi-campaign serve [--addr host:port] [--runs dir] [--demo path]
//	                     [--console path] [--allow-host host[:port]]... [--phase-timeout d]
//	                     [--web-dir dir] [--auth-file users.json]
//	                     [--fabric-peer host:port] [--fabric-gateway-peer name]
//	                     [--fabric-tls-cert path] [--fabric-msp-id id]
//	                     [--fabric-cert path] [--fabric-key path]
//	                     [--fabric-channel name] [--fabric-chaincode name]
//	                     [--tls-cert cert.pem --tls-key key.pem]
//	                     [--live --trustee-tokens tokens.json [--live-precinct 0001A]]
//
// --live runs one live election (docs/live/http-api.md): it needs --auth-file
// (the presenter), --trustee-tokens and, unless the bind is loopback, TLS. Its
// voters are the precinct's voter list, uploaded at setup
// (docs/live/voter-list-api.md); --live-precinct is that precinct's number.
//
// The same binary is also the campaign driver for an ALREADY-RUNNING console,
// over that console's own HTTP API — it never reaches into a run folder:
//
//	saksi-campaign --repeat --config run.json --warmups 2 --reps 10
//	                        [--sweep 1.5] [--window 120s] [--burst N]
//	                        [--base-url http://127.0.0.1:8090] [--out summary.csv]
//	saksi-campaign --ladder [--base-url URL] [--runs dir]
//
// One live election trustee process per trustee (docs/live/trustee-api.md):
//
//	saksi-campaign trustee --id N --addr :9001 --tls-cert c.pem --tls-key k.pem
//	                       --allow-host t1.example --auth-file t1-accounts.json
//	                       --console https://vote.example:8443 --token-file t1.token
//	                       --state-dir ~/.saksi/trustee-1 --peers 2=https://t2.example:9002,...
//	                       --demo saksi-demo --web-dir dist-web --fabric-...
//
// And it makes the password hashes for a --auth-file users file, reading the
// password from stdin so it never lands in shell history:
//
//	saksi-campaign hash-password < password.txt
//
// and a trustee process's token and the hash the --trustee-tokens file holds:
//
//	saksi-campaign new-token
//	saksi-campaign hash-token < token.txt
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	campaign "github.com/saksi-framework/saksi/packages/saksi-campaign"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

const defaultBaseURL = "http://127.0.0.1:8090"

func main() {
	mode := ""
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "serve":
		serve(os.Args[2:])
	case "trustee":
		trustee(os.Args[2:])
	case "--repeat":
		repeat(os.Args[2:])
	case "--ladder":
		ladder(os.Args[2:])
	case "hash-password":
		fmt.Fprintln(os.Stderr, "reading one password line from stdin")
		h, err := campaign.HashPassword(os.Stdin)
		if err != nil {
			fatal("hash-password: %v", err)
		}
		fmt.Println(h)
	case "new-token":
		tok, err := campaign.NewTrusteeToken()
		if err != nil {
			fatal("new-token: %v", err)
		}
		fmt.Println(tok)
	case "hash-token":
		fmt.Fprintln(os.Stderr, "reading one token line from stdin")
		h, err := campaign.HashTrusteeToken(os.Stdin)
		if err != nil {
			fatal("hash-token: %v", err)
		}
		fmt.Println(h)
	default:
		fmt.Fprintln(os.Stderr, "usage: saksi-campaign serve [flags]")
		fmt.Fprintln(os.Stderr, "       saksi-campaign trustee --id N [flags]")
		fmt.Fprintln(os.Stderr, "       saksi-campaign --repeat --config run.json [flags]")
		fmt.Fprintln(os.Stderr, "       saksi-campaign --ladder [flags]")
		fmt.Fprintln(os.Stderr, "       saksi-campaign hash-password < password")
		fmt.Fprintln(os.Stderr, "       saksi-campaign new-token | saksi-campaign hash-token < token")
		os.Exit(2)
	}
}

// repeat drives a repeated-measures campaign against a running console.
func repeat(args []string) {
	fs := flag.NewFlagSet("--repeat", flag.ExitOnError)
	configPath := fs.String("config", "", "path to the election config JSON (required)")
	baseURL := fs.String("base-url", defaultBaseURL, "the running console to drive")
	warmups := fs.Int("warmups", 0, "discarded warm-up repetitions")
	reps := fs.Int("reps", 1, "measured repetitions")
	sweep := fs.Float64("sweep", 0, "raise the offered rate by this factor per step (0 = no sweep)")
	window := fs.Duration("window", campaign.DefaultWindow, "wall-clock window per sweep step")
	burst := fs.Int("burst", 0, "after the measured reps, submit this many ballots with no rate cap")
	out := fs.String("out", campaign.SummaryCSV, "where to write the campaign summary")
	_ = fs.Parse(args)

	if *configPath == "" {
		fatal("--config is required: it names the election every repetition runs")
	}
	data, err := os.ReadFile(*configPath)
	if err != nil {
		fatal("read %s: %v", *configPath, err)
	}
	var c campaign.ElectionConfig
	if err := json.Unmarshal(data, &c); err != nil {
		fatal("parse %s: %v", *configPath, err)
	}
	if err := campaign.Repeat(context.Background(), campaign.RepeatOpts{
		BaseURL: *baseURL, Config: c,
		Warmups: *warmups, Reps: *reps,
		Sweep: *sweep, Window: *window, Burst: *burst,
		Out: *out,
	}); err != nil {
		fatal("%v", err)
	}
	fmt.Println("summary written to " + *out)
}

// ladder runs the validation ladder against a running console.
func ladder(args []string) {
	fs := flag.NewFlagSet("--ladder", flag.ExitOnError)
	baseURL := fs.String("base-url", defaultBaseURL, "the running console to drive")
	runsDir := fs.String("runs", defaultRunsDir(), "the console's run-store root (where ladder.json is written)")
	_ = fs.Parse(args)

	if err := campaign.RunLadder(context.Background(), campaign.LadderOpts{
		BaseURL: *baseURL, DataDir: *runsDir,
	}); err != nil {
		fatal("%v", err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8090", "bind address (host:port); use 0.0.0.0 for LAN")
	runsDir := fs.String("runs", defaultRunsDir(), "run-folder store root")
	demoBin := fs.String("demo", "saksi-demo", "path to the saksi-demo binary")
	consBin := fs.String("console", "", "path to the on-chain console driver (optional)")
	webDir := fs.String("web-dir", os.Getenv("SAKSI_WEB_DIR"),
		"directory holding the browser apps to serve: <dir>/board, <dir>/trustee and <dir>/admin (env SAKSI_WEB_DIR)")
	authFile := fs.String("auth-file", os.Getenv("SAKSI_AUTH_FILE"),
		"users file (JSON) that turns on login and per-route roles; unset = no auth (env SAKSI_AUTH_FILE)")
	defTimeout := 60 * time.Minute
	if v := os.Getenv("SAKSI_PHASE_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			fatal("SAKSI_PHASE_TIMEOUT=%q: want a positive duration such as 90m or 4h", v)
		}
		defTimeout = d
	}
	timeout := fs.Duration("phase-timeout", defTimeout,
		"how long each phase (generate, ballot submission, verify; /run-all: all three together) may run before it is cancelled (env SAKSI_PHASE_TIMEOUT)")
	fs.DurationVar(timeout, "timeout", defTimeout, "alias of --phase-timeout")
	fabricPeer := fs.String("fabric-peer", "localhost:7051", "Fabric gateway peer endpoint (host:port)")
	fabricGatewayPeer := fs.String("fabric-gateway-peer", "peer0.org1.example.com", "Fabric gateway peer TLS server name")
	fabricTLSCert := fs.String("fabric-tls-cert", "", "path to the peer TLS CA certificate")
	fabricMSPID := fs.String("fabric-msp-id", "Org1MSP", "Fabric MSP id of the acting organization")
	fabricCert := fs.String("fabric-cert", "", "path to the client identity certificate")
	fabricKey := fs.String("fabric-key", "", "path to the client identity private key")
	fabricChannel := fs.String("fabric-channel", "saksi", "Fabric channel the bulletin board runs on")
	fabricChaincode := fs.String("fabric-chaincode", "saksi-bulletin", "deployed chaincode name")
	fabricPeerVolume := fs.String("fabric-peer-volume", "", "host path of the peer's ledger volume (enables perf.csv's ledger_bytes_delta)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate chain (PEM); with --tls-key the console serves HTTPS (TLS 1.2 or later)")
	tlsKey := fs.String("tls-key", "", "TLS private key (PEM) for --tls-cert")
	live := fs.Bool("live", false, "enable the live election routes (/api/live/); needs --auth-file and --trustee-tokens")
	trusteeTokens := fs.String("trustee-tokens", os.Getenv("SAKSI_TRUSTEE_TOKENS"),
		"live mode: JSON array of {trustee_id, token_sha256}, one token per trustee process (env SAKSI_TRUSTEE_TOKENS)")
	livePrecinct := fs.String("live-precinct", campaign.DefaultLivePrecinct,
		"live mode: the precinct number (four digits and a capital letter), always shown as a demonstration")
	var allow multiFlag
	fs.Var(&allow, "allow-host", "additional accepted Host header (repeatable; for LAN)")
	_ = fs.Parse(args)
	if *timeout <= 0 {
		fatal("--phase-timeout must be positive (got %s)", *timeout)
	}
	opts := campaign.ServeOptions{Addr: *addr, TLSCert: *tlsCert, TLSKey: *tlsKey, Live: *live, AuthFile: *authFile}
	warning, err := campaign.CheckServeOptions(opts)
	if err != nil {
		fatal("%v", err)
	}

	fabric := campaign.FabricConfig{
		PeerEndpoint: *fabricPeer,
		GatewayPeer:  *fabricGatewayPeer,
		TLSCert:      *fabricTLSCert,
		MSPID:        *fabricMSPID,
		Cert:         *fabricCert,
		Key:          *fabricKey,
		Channel:      *fabricChannel,
		Chaincode:    *fabricChaincode,
		PeerVolume:   *fabricPeerVolume,
	}

	if err := os.MkdirAll(*runsDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "cannot create runs dir %s: %v\n", *runsDir, err)
		os.Exit(1)
	}

	// NewServer reads SAKSI_WEB_DIR, so the flag and the env var are one
	// setting with the flag winning — no extra parameter on the constructor,
	// which several call sites and tests share.
	if *webDir != "" {
		if err := os.Setenv("SAKSI_WEB_DIR", *webDir); err != nil {
			fmt.Fprintf(os.Stderr, "cannot set SAKSI_WEB_DIR: %v\n", err)
			os.Exit(1)
		}
	}

	store := campaign.NewRunStore(*runsDir)
	hub := campaign.NewHub()
	exec := campaign.NewExecutor(store, hub, *demoBin, *consBin, fabric)
	handler := campaign.NewServer(store, exec, hub, fabric, allowedHosts(*addr, allow), *timeout)
	if *authFile != "" {
		if err := handler.EnableAuth(*authFile); err != nil {
			fatal("--auth-file %s: %v", *authFile, err)
		}
	}
	if *live {
		if err := handler.EnableLive(campaign.LiveOptions{TrusteeTokens: *trusteeTokens, Precinct: *livePrecinct}); err != nil {
			fatal("--live: %v", err)
		}
	}
	scheme := "http"
	if opts.TLS() {
		scheme = "https"
	}

	fmt.Printf("Research Election Console\n")
	fmt.Printf("  serving   %s://%s\n", scheme, displayHost(*addr))
	fmt.Printf("  runs      %s\n", *runsDir)
	fmt.Printf("  phase timeout %s\n", *timeout)
	fmt.Printf("  saksi-demo %s\n", *demoBin)
	if *webDir != "" {
		fmt.Printf("  apps      %s -> %s://%s/board/, /trustee/, /admin/ and /vote/\n", *webDir, scheme, displayHost(*addr))
	}
	if *authFile != "" {
		fmt.Printf("  auth      on, users from %s\n", *authFile)
	} else {
		fmt.Printf("  auth      off (no --auth-file)\n")
	}
	if fabric.Enabled() {
		fmt.Printf("  on-chain  fabric gateway %s (channel %s)\n", fabric.PeerEndpoint, fabric.Channel)
	} else if *consBin == "" {
		fmt.Printf("  on-chain  (no driver configured — offline mode only)\n")
	}
	if *live {
		fmt.Printf("  live      on: /api/live/ (trustee tokens from %s; precinct %s)\n", *trusteeTokens, *livePrecinct)
	}
	if warning != "" {
		fmt.Fprintln(os.Stderr, warning)
	}
	go restorePeerOnSignal(exec)
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fatal("listen %s: %v", *addr, err)
	}
	if err := campaign.Serve(ln, opts, handler); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

// trustee runs one live election trustee process.
func trustee(args []string) {
	fs := flag.NewFlagSet("trustee", flag.ExitOnError)
	id := fs.Int("id", 0, "this trustee's id, 1..n (required)")
	addr := fs.String("addr", "127.0.0.1:9001", "bind address (host:port)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate chain (PEM); with --tls-key this process serves HTTPS. Required unless --addr is loopback")
	tlsKey := fs.String("tls-key", "", "TLS private key (PEM) for --tls-cert")
	var allow multiFlag
	fs.Var(&allow, "allow-host", "accepted Host header (repeatable); a host without a port gets --addr's port")
	authFile := fs.String("auth-file", "", "this trustee's own accounts file: trustee accounts with this --id only (required)")
	consoleURL := fs.String("console", "", "the console's base URL, https://<host>:<port> (required). The host and port must be in the console's --allow-host list, and the name must be on the console's certificate (https://localhost:8443 against a vote.example certificate fails)")
	consoleCA := fs.String("console-ca", "", "extra CA certificate (PEM) trusted for the console and the peers, besides the system roots (tests)")
	tokenFile := fs.String("token-file", "", "file holding this trustee's bearer token for the console, mode 0600 (required)")
	stateDir := fs.String("state-dir", "", "this trustee's private folder, mode 0700: receive keys, key shares and progress per election (required)")
	peers := fs.String("peers", "", "the other trustees' base URLs by id: 1=https://t1.example:9001,2=https://t2.example:9002,...")
	demoBin := fs.String("demo", "saksi-demo", "path to the saksi-demo binary")
	webDir := fs.String("web-dir", "", "serve the trustee app at /trustee/ from <dir>/trustee")
	minBallots := fs.Int("min-ballots", campaign.DefaultMinBallots, "refuse to decrypt a position with fewer ballot records (1 is for rehearsals only: a one-ballot aggregate is that voter's choice)")
	fabricPeer := fs.String("fabric-peer", "localhost:7051", "Fabric gateway peer endpoint (host:port) this trustee reads the ledger from")
	fabricGatewayPeer := fs.String("fabric-gateway-peer", "peer0.org1.example.com", "Fabric gateway peer TLS server name")
	fabricTLSCert := fs.String("fabric-tls-cert", "", "path to the peer TLS CA certificate (required)")
	fabricMSPID := fs.String("fabric-msp-id", "Org1MSP", "Fabric MSP id of the reading identity")
	fabricCert := fs.String("fabric-cert", "", "path to the reading identity's certificate (required)")
	fabricKey := fs.String("fabric-key", "", "path to the reading identity's private key, read in place (required)")
	fabricChannel := fs.String("fabric-channel", "saksi", "Fabric channel")
	fabricChaincode := fs.String("fabric-chaincode", "saksi-bulletin", "deployed chaincode name")
	_ = fs.Parse(args)

	opts := campaign.ServeOptions{Addr: *addr, TLSCert: *tlsCert, TLSKey: *tlsKey}
	warning, err := campaign.CheckTrusteeServeOptions(opts)
	if err != nil {
		fatal("%v", err)
	}
	token, err := campaign.LoadTrusteeTokenFile(*tokenFile)
	if err != nil {
		fatal("%v", err)
	}
	peerMap, err := campaign.ParseTrusteePeers(*peers)
	if err != nil {
		fatal("%v", err)
	}
	fabric := campaign.FabricConfig{
		PeerEndpoint: *fabricPeer, GatewayPeer: *fabricGatewayPeer, TLSCert: *fabricTLSCert,
		MSPID: *fabricMSPID, Cert: *fabricCert, Key: *fabricKey,
		Channel: *fabricChannel, Chaincode: *fabricChaincode,
	}
	if !fabric.Enabled() {
		fatal("a trustee reads the ledger itself: --fabric-tls-cert, --fabric-cert and --fabric-key are required")
	}
	T, err := campaign.NewTrusteeService(campaign.TrusteeOptions{
		ID: *id, ConsoleURL: *consoleURL, ConsoleCA: *consoleCA, Token: token,
		StateDir: *stateDir, Peers: peerMap, MinBallots: *minBallots,
		Runner: campaign.ExecLiveRunner(*demoBin), Dial: campaign.TrusteeFabricDial(fabric),
	})
	if err != nil {
		fatal("%v", err)
	}
	handler, err := campaign.NewTrusteeServer(T, campaign.TrusteeServerOptions{
		AuthFile: *authFile, AllowHosts: allowedHosts(*addr, allow), WebDir: *webDir,
	})
	if err != nil {
		fatal("%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := T.ProbeConsole(ctx); err != nil {
		cancel()
		fatal("--console: %v", err)
	}
	if err := T.CheckIdentity(ctx); err != nil {
		cancel()
		fatal("trustee %d: %v", *id, err)
	}
	cancel()
	pctx, pcancel := context.WithTimeout(context.Background(), 20*time.Second)
	for _, w := range T.PeerWarnings(pctx) {
		fmt.Fprintln(os.Stderr, w)
	}
	pcancel()
	scheme := "http"
	if opts.TLS() {
		scheme = "https"
	}
	fmt.Printf("Trustee %d\n", *id)
	fmt.Printf("  serving   %s://%s\n", scheme, displayHost(*addr))
	fmt.Printf("  console   %s\n", *consoleURL)
	fmt.Printf("  state     %s\n", *stateDir)
	fmt.Printf("  ledger    fabric gateway %s (channel %s), read only\n", fabric.PeerEndpoint, fabric.Channel)
	if *webDir != "" {
		fmt.Printf("  app       %s -> /trustee/\n", *webDir)
	}
	if warning != "" {
		fmt.Fprintln(os.Stderr, warning)
	}
	// Bind first: a failed bind exits before the driver writes any state.
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fatal("listen %s: %v", *addr, err)
	}
	T.Start()
	if err := campaign.Serve(ln, opts, handler); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

// restorePeerOnSignal makes Ctrl-C and SIGTERM start the Fabric peer again when
// a peer-restart fault has it stopped, instead of leaving it down. A network
// reset in progress is not touched: tools/tier.sh runs in its own process group
// and finishes on its own.
func restorePeerOnSignal(exec *campaign.Executor) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	sig := <-sigs
	signal.Stop(sigs) // a second Ctrl-C kills at once, even while the restore waits
	if restored, err := exec.RestorePeer(); restored {
		if err != nil {
			fmt.Fprintf(os.Stderr, "stopping mid-fault: docker start peer0.org1.example.com failed: %v; start it by hand\n", err)
		} else {
			fmt.Fprintln(os.Stderr, "stopping mid-fault: started peer0.org1.example.com again")
		}
	}
	fmt.Fprintf(os.Stderr, "console stopped (%v)\n", sig)
	os.Exit(1)
}

func defaultRunsDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".saksi", "campaign", "runs")
	}
	return "saksi-runs"
}

// allowedHosts builds the Host-header allowlist from the bind address plus any
// operator-supplied hosts. Loopback aliases are always accepted; a non-loopback
// bind (e.g. 0.0.0.0 for LAN) additionally accepts each --allow-host.
func allowedHosts(addr string, extra []string) []string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return []string{addr}
	}
	set := map[string]bool{
		net.JoinHostPort("127.0.0.1", port): true,
		net.JoinHostPort("localhost", port): true,
		net.JoinHostPort("::1", port):       true,
	}
	if host != "0.0.0.0" && host != "::" && host != "" {
		set[net.JoinHostPort(host, port)] = true
	}
	for _, h := range extra {
		if strings.Contains(h, ":") {
			set[h] = true
		} else {
			set[net.JoinHostPort(h, port)] = true
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	return out
}

func displayHost(addr string) string {
	if strings.HasPrefix(addr, "0.0.0.0:") {
		return strings.Replace(addr, "0.0.0.0", "<this-host>", 1)
	}
	return addr
}
