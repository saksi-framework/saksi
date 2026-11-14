package campaign

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// The trustee process's HTTPS clients: one to the console (with the bearer
// token) and one to the other trustees' public pages. TLS is verified against
// the system roots plus an optional extra CA file; nothing turns it off.

// trusteeHTTP is an HTTPS client that follows no redirect.
type trusteeHTTP struct {
	c *http.Client
}

func newTrusteeHTTP(caFile string, timeout time.Duration) (*trusteeHTTP, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("--console-ca: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--console-ca %s holds no PEM certificate", caFile)
		}
	}
	tr := &http.Transport{
		Proxy:               nil,
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 15 * time.Second,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     60 * time.Second,
	}
	return &trusteeHTTP{c: &http.Client{
		Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (h *trusteeHTTP) get(ctx context.Context, u string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := h.c.Do(req)
	if err != nil {
		return 0, nil, transportText(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, err
}

// checkHTTPSBase checks a base URL: https, a host, nothing after the host but
// an optional "/". It returns it without the trailing slash.
func checkHTTPSBase(flagName, raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return "", fmt.Errorf("%s %q: want https://<host>:<port>, with the host and port the other side serves and its certificate names", flagName, raw)
	}
	return "https://" + u.Host, nil
}

// transportText makes a transport error readable and says what to check.
func transportText(err error) error {
	var certErr *tls.CertificateVerificationError
	var hostErr x509.HostnameError
	var unknown x509.UnknownAuthorityError
	switch {
	case errors.As(err, &hostErr):
		return fmt.Errorf("the certificate does not name this host (%v): use the URL whose name is on the certificate", hostErr)
	case errors.As(err, &unknown), errors.As(err, &certErr):
		return fmt.Errorf("the certificate is not trusted (%v): the system roots and --console-ca are trusted", err)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fmt.Errorf("no answer in time: %v", err)
	}
	return err
}

// trusteeConsole is the console seen from a trustee process.
type trusteeConsole struct {
	base  string
	token string
	http  *trusteeHTTP
}

// do sends a JSON request with the bearer token and no Origin (so the
// console's guard sees a server-to-server call). A transport failure, a
// timeout or a 502/503/504 is a wait, never a refusal: the driver asks again.
func (c *trusteeConsole) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return 0, nil, err
		}
	}
	return c.doRaw(ctx, method, path, raw)
}

func (c *trusteeConsole) doRaw(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.c.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, nil, ctx.Err()
		}
		return 0, nil, tWait{"the console is not answering (" + transportText(err).Error() + "); trying again"}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return 0, nil, tWait{"the console's answer was cut off; trying again"}
	}
	switch resp.StatusCode {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return 0, nil, tWait{fmt.Sprintf("the console answered %d (%s); trying again", resp.StatusCode, errorText(data))}
	case http.StatusForbidden:
		if t := strings.TrimSpace(string(data)); t == "forbidden host" || t == "cross-origin request rejected" {
			return 0, nil, fmt.Errorf("the console's guard refused the request (%s): --console must name a host and port in the console's --allow-host list", t)
		}
	}
	return resp.StatusCode, data, nil
}

// election is GET /api/live/election, or nil when no election is set up.
func (c *trusteeConsole) election(ctx context.Context) (*LiveElectionView, error) {
	code, body, err := c.do(ctx, http.MethodGet, "/api/live/election", nil)
	if err != nil {
		return nil, err
	}
	if code == http.StatusNotFound {
		return nil, nil
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("the console answered %d to GET /api/live/election: %s", code, errorText(body))
	}
	var v LiveElectionView
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, errors.New("the console's election view is unreadable")
	}
	return &v, nil
}

// Probe checks the console can be reached with this URL: TLS verifies, the
// guard accepts the Host, and the live routes answer.
func (c *trusteeConsole) Probe(ctx context.Context) error {
	code, body, err := c.do(ctx, http.MethodGet, "/api/live/election", nil)
	var wait tWait
	if errors.As(err, &wait) {
		return fmt.Errorf("%s: %s. --console must carry a host and port in the console's --allow-host list and the name on its certificate", c.base, wait.msg)
	}
	if err != nil {
		return fmt.Errorf("%s: %v", c.base, err)
	}
	if code != http.StatusOK && code != http.StatusNotFound {
		return fmt.Errorf("%s answered %d to GET /api/live/election: %s", c.base, code, errorText(body))
	}
	if code == http.StatusNotFound && !strings.Contains(string(body), "election") {
		return fmt.Errorf("%s answered 404: is it a console in live mode (serve --live)?", c.base)
	}
	return nil
}

// errorText is the "error" field of a JSON error body, or the body itself.
func errorText(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return e.Error
	}
	t := strings.TrimSpace(string(body))
	if len(t) > 300 {
		t = t[:300] + "..."
	}
	return t
}
