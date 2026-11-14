package campaign

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// ServeOptions is what `serve` decides how to listen from.
type ServeOptions struct {
	Addr     string
	TLSCert  string
	TLSKey   string
	Live     bool
	AuthFile string
}

// TLS reports whether the console serves HTTPS.
func (o ServeOptions) TLS() bool { return o.TLSCert != "" && o.TLSKey != "" }

// CheckServeOptions refuses a start-up the live election must not run with,
// and returns a warning to print for one it may run with but should not be
// left like. Live mode needs accounts (the voter roll and the presenter's
// login); without TLS it starts only on a loopback bind, where nothing leaves
// the machine.
func CheckServeOptions(o ServeOptions) (warning string, err error) {
	if (o.TLSCert == "") != (o.TLSKey == "") {
		return "", errors.New("--tls-cert and --tls-key go together: give both or neither")
	}
	if !o.Live {
		return "", nil
	}
	if o.AuthFile == "" {
		return "", errors.New("--live needs --auth-file: the voter roll and the presenter's account are in it")
	}
	if o.TLS() {
		return "", nil
	}
	host, _, err := net.SplitHostPort(o.Addr)
	if err != nil {
		return "", fmt.Errorf("--addr %q: %v", o.Addr, err)
	}
	if host == "localhost" {
		return loopbackWarning, nil
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("--live without --tls-cert/--tls-key serves passwords and session cookies in the clear; it starts only on a loopback --addr (got %q)", o.Addr)
	}
	return loopbackWarning, nil
}

const loopbackWarning = "WARNING: live mode without TLS. Passwords and session cookies travel in the clear; " +
	"this is only acceptable because the bind is loopback. Use --tls-cert and --tls-key for phones."

// tlsConfig is the console's HTTPS configuration: TLS 1.2 at least.
func tlsConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

// NewHTTPServer is the console's http.Server: the handler, the TLS minimum
// and header timeouts. The session cookie's Secure flag follows r.TLS, so it
// is set exactly when this server serves HTTPS.
func NewHTTPServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		TLSConfig:         tlsConfig(),
		ReadHeaderTimeout: 10 * time.Second,
	}
}

// Serve serves h on ln, over TLS when o says so.
func Serve(ln net.Listener, o ServeOptions, h http.Handler) error {
	srv := NewHTTPServer(h)
	if o.TLS() {
		return srv.ServeTLS(ln, o.TLSCert, o.TLSKey)
	}
	return srv.Serve(ln)
}

// CheckTrusteeServeOptions is the trustee process's start-up rule, the same
// as live mode's: TLS flags together, and without TLS only a loopback bind.
func CheckTrusteeServeOptions(o ServeOptions) (warning string, err error) {
	if (o.TLSCert == "") != (o.TLSKey == "") {
		return "", errors.New("--tls-cert and --tls-key go together: give both or neither")
	}
	if o.TLS() {
		return "", nil
	}
	host, _, err := net.SplitHostPort(o.Addr)
	if err != nil {
		return "", fmt.Errorf("--addr %q: %v", o.Addr, err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", fmt.Errorf("a trustee process without --tls-cert/--tls-key serves its password and session cookie in the clear; it starts only on a loopback --addr (got %q)", o.Addr)
	}
	return "WARNING: trustee process without TLS. Its password and session cookie travel in the clear; " +
		"this is only acceptable because the bind is loopback.", nil
}
