// Command saksi-campaign serves the Research Election Console — a loopback web
// app to configure + run the paper's elections in phases.
//
//	saksi-campaign serve [--addr host:port] [--runs dir] [--demo path]
//	                     [--console path] [--allow-host host[:port]]... [--timeout d]
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
	var allow multiFlag
	fs.Var(&allow, "allow-host", "additional accepted Host header (repeatable; for LAN)")
	_ = fs.Parse(os.Args[2:])

	if err := os.MkdirAll(*runsDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "cannot create runs dir %s: %v\n", *runsDir, err)
		os.Exit(1)
	}

	store := campaign.NewRunStore(*runsDir)
	hub := campaign.NewHub()
	exec := campaign.NewExecutor(store, hub, *demoBin, *consBin)
	handler := campaign.NewServer(store, exec, hub, allowedHosts(*addr, allow), *timeout)

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
