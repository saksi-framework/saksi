// Command saksi-campaign serves the Research Election Console — a loopback web
// app to configure + run the paper's elections in phases.
//
//	saksi-campaign serve [--addr host:port] [--runs dir] [--demo path]
//	                     [--console path] [--allow-host host[:port]]... [--timeout d]
//	                     [--fabric-peer host:port] [--fabric-gateway-peer name]
//	                     [--fabric-tls-cert path] [--fabric-msp-id id]
//	                     [--fabric-cert path] [--fabric-key path]
//	                     [--fabric-channel name] [--fabric-chaincode name]
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	campaign "github.com/saksi-framework/saksi/packages/saksi-campaign"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	if len(os.Args) < 2 || os.Args[1] != "serve" {
		fmt.Fprintln(os.Stderr, "usage: saksi-campaign serve [flags]")
		os.Exit(2)
	}

	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8090", "bind address (host:port); use 0.0.0.0 for LAN")
	runsDir := fs.String("runs", defaultRunsDir(), "run-folder store root")
	demoBin := fs.String("demo", "saksi-demo", "path to the saksi-demo binary")
	consBin := fs.String("console", "", "path to the on-chain console driver (optional)")
	timeout := fs.Duration("timeout", 60*time.Minute, "per-phase timeout")
	fabricPeer := fs.String("fabric-peer", "localhost:7051", "Fabric gateway peer endpoint (host:port)")
	fabricGatewayPeer := fs.String("fabric-gateway-peer", "peer0.org1.example.com", "Fabric gateway peer TLS server name")
	fabricTLSCert := fs.String("fabric-tls-cert", "", "path to the peer TLS CA certificate")
	fabricMSPID := fs.String("fabric-msp-id", "Org1MSP", "Fabric MSP id of the acting organization")
	fabricCert := fs.String("fabric-cert", "", "path to the client identity certificate")
	fabricKey := fs.String("fabric-key", "", "path to the client identity private key")
	fabricChannel := fs.String("fabric-channel", "saksi", "Fabric channel the bulletin board runs on")
	fabricChaincode := fs.String("fabric-chaincode", "saksi-bulletin", "deployed chaincode name")
	var allow multiFlag
	fs.Var(&allow, "allow-host", "additional accepted Host header (repeatable; for LAN)")
	_ = fs.Parse(os.Args[2:])

	fabric := campaign.FabricConfig{
		PeerEndpoint: *fabricPeer,
		GatewayPeer:  *fabricGatewayPeer,
		TLSCert:      *fabricTLSCert,
		MSPID:        *fabricMSPID,
		Cert:         *fabricCert,
		Key:          *fabricKey,
		Channel:      *fabricChannel,
		Chaincode:    *fabricChaincode,
	}

	if err := os.MkdirAll(*runsDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "cannot create runs dir %s: %v\n", *runsDir, err)
		os.Exit(1)
	}

	store := campaign.NewRunStore(*runsDir)
	hub := campaign.NewHub()
	exec := campaign.NewExecutor(store, hub, *demoBin, *consBin, fabric)
	handler := campaign.NewServer(store, exec, hub, fabric, allowedHosts(*addr, allow), *timeout)

	fmt.Printf("Research Election Console\n")
	fmt.Printf("  serving   http://%s\n", displayHost(*addr))
	fmt.Printf("  runs      %s\n", *runsDir)
	fmt.Printf("  saksi-demo %s\n", *demoBin)
	if *consBin == "" {
		fmt.Printf("  on-chain  (no driver configured — offline mode only)\n")
	}
	if err := http.ListenAndServe(*addr, handler); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
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
