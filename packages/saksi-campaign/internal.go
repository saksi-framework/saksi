package campaign

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
)

// The console driving itself.
//
// A campaign and the validation ladder reuse Repeat and RunLadder, which speak
// HTTP to a console. Run from the console, they speak it to this process's own
// handler chain (guard, authorize, the mux) through internalTransport, never
// over a socket. A wizard campaign therefore takes exactly the path a CLI
// campaign takes and produces the same artifacts.
//
// With auth on those requests carry no credential. authorize recognises a
// request whose context carries internalCallKey, and only this package can
// build such a context: the key's type is unexported, and net/http builds a
// served request's context itself, so no header, query, cookie or address can
// set it. There is no token to issue, store or leak.
//
// An internal request has no session (the driver submits every trustee's
// shares on /ceremony/submit, which an admin session would be refused), and in
// exchange it may reach only internalRoutes, with auth on and off alike.

type internalCallKey struct{}

// internalCall reports whether r was made by internalTransport.
func internalCall(r *http.Request) bool {
	v, _ := r.Context().Value(internalCallKey{}).(bool)
	return v
}

// internalRoutes is every route Repeat and RunLadder call (repeat.go: create,
// once's check, phase, ceremony, waitIdle, export), with the one method each
// uses. TestInternalRoutesCoverTheDriver fails when the driver gains a call
// that is not here, or this names one the driver no longer makes.
//
// GET on /api/runs/ reaches only the status action: resume and verify-only
// refuse every method but POST.
var internalRoutes = map[string]string{
	"/generate":         http.MethodPost,
	"/api/check/":       http.MethodGet,
	"/submit":           http.MethodPost,
	"/ceremony/start":   http.MethodPost,
	"/api/ceremony/":    http.MethodGet,
	"/ceremony/submit":  http.MethodPost,
	"/ceremony/publish": http.MethodPost,
	"/verify":           http.MethodPost,
	"/api/runs/":        http.MethodGet,
	"/export/":          http.MethodGet,
}

// internalRouteAllowed reports whether an internal request may reach the route
// the mux resolves it to.
func internalRouteAllowed(mux *routeMux, r *http.Request) bool {
	_, pattern := mux.Handler(r)
	method, ok := internalRoutes[pattern]
	return ok && method == r.Method
}

// errJobCancelled is what the transport answers a cancelled campaign's next
// /generate with, so Repeat stops between repetitions and never mid-way.
var errJobCancelled = errors.New("campaign cancelled")

// internalTransport serves each request with the console's own handler.
type internalTransport struct {
	s    *Server
	host string // an allowed Host, so guard() passes the request as it would a real one
	job  *job   // nil for a bare client; set, its hooks see the runs it creates
}

func (t *internalTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		defer req.Body.Close()
	}
	j := t.job
	generate := req.Method == http.MethodPost && req.URL.Path == "/generate"
	if generate && j != nil && t.s.jobs.cancelRequested(j) {
		return nil, errJobCancelled
	}
	// A repetition's host sample is taken before its /generate is served, never
	// inside a phase.
	var start HostSample
	if generate && j != nil && j.onRun != nil {
		start = sampleHost()
	}

	r := req.Clone(context.WithValue(req.Context(), internalCallKey{}, true))
	r.Host = t.host
	rec := httptest.NewRecorder()
	if err := serveRecovering(t.s, rec, r); err != nil {
		return nil, err
	}

	if generate && rec.Code == http.StatusAccepted && j != nil && j.onRun != nil {
		var body struct {
			RunID string `json:"run_id"`
		}
		if json.Unmarshal(rec.Body.Bytes(), &body) == nil && body.RunID != "" {
			j.onRun(body.RunID, start)
		}
	}
	// The driver downloads a run's perf.csv only once its verify phase is idle:
	// the repetition is over, so this is where its closing sample belongs.
	if j != nil && j.onRepEnd != nil && req.Method == http.MethodGet {
		if rest, ok := strings.CutPrefix(req.URL.Path, "/export/"); ok {
			if runID, ok := strings.CutSuffix(rest, "/"+PerfCSV); ok && !strings.Contains(runID, "/") {
				j.onRepEnd(runID)
			}
		}
	}
	return rec.Result(), nil
}

// serveRecovering turns a handler panic into an error, so a bug in one route
// fails the job that hit it instead of taking the console down with it.
func serveRecovering(h http.Handler, w http.ResponseWriter, r *http.Request) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("internal %s %s: handler panicked: %v", r.Method, r.URL.Path, p)
		}
	}()
	h.ServeHTTP(w, r)
	return nil
}

// internalClient returns a client that drives this console in-process, and the
// base URL to give Repeat/RunLadder. j may be nil.
func (s *Server) internalClient(j *job) (*http.Client, string) {
	host := "console.internal"
	if len(s.allowHosts) > 0 {
		host = slices.Sorted(maps.Keys(s.allowHosts))[0]
	}
	return &http.Client{Transport: &internalTransport{s: s, host: host, job: j}}, "http://" + host
}
