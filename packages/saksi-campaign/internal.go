package campaign

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
)

// The console driving itself.
//
// A campaign and the validation ladder reuse Repeat and RunLadder, which speak
// HTTP to a console. Run from the console, they speak it to this process's own
// handler chain (guard, authorize, the mux) through internalTransport, never
// over a socket. A wizard campaign therefore takes exactly the path a CLI
// campaign takes and produces the same artifacts.
//
// With auth on those requests carry no credential. authorize lets a request
// through when its context carries internalCallKey, and only this package can
// build such a context: the key's type is unexported, and net/http builds a
// served request's context itself, so no header, query, cookie or address can
// set it. There is no token to issue, store or leak.
//
// The internal caller takes the auth-off path rather than an admin session:
// the driver submits every trustee's shares on /ceremony/submit, which the
// role table reserves for trustees, so an admin session would be refused there.

type internalCallKey struct{}

// internalCall reports whether r was made by internalTransport.
func internalCall(r *http.Request) bool {
	v, _ := r.Context().Value(internalCallKey{}).(bool)
	return v
}

// errJobCancelled is what the transport answers a cancelled campaign's next
// /generate with, so Repeat stops between repetitions and never mid-way.
var errJobCancelled = errors.New("campaign cancelled")

// internalTransport serves each request with the console's own handler.
type internalTransport struct {
	s    *Server
	host string // an allowed Host, so guard() passes the request as it would a real one
	job  *job   // nil for a bare client; set, it may refuse /generate and records the runs created
}

func (t *internalTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		defer req.Body.Close()
	}
	generate := req.Method == http.MethodPost && req.URL.Path == "/generate"
	if generate && t.job != nil && t.s.jobs.cancelRequested(t.job) {
		return nil, errJobCancelled
	}
	r := req.Clone(context.WithValue(req.Context(), internalCallKey{}, true))
	r.Host = t.host
	rec := httptest.NewRecorder()
	t.s.ServeHTTP(rec, r)
	if generate && rec.Code == http.StatusAccepted && t.job != nil && t.job.onRun != nil {
		var body struct {
			RunID string `json:"run_id"`
		}
		if json.Unmarshal(rec.Body.Bytes(), &body) == nil && body.RunID != "" {
			t.job.onRun(body.RunID)
		}
	}
	return rec.Result(), nil
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
