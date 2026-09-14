package campaign

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"time"
)

// Network reset: POST /api/network/reset runs tools/tier.sh as a console job.
//
// A reset tears the Fabric network down and brings it back with an empty
// ledger, so every election on the old network is gone from the chain (the run
// folders stay; the export bundle is the record). The guards are the feature:
// admin-only in the route table, loopback-only even with auth on, a typed
// confirmation, and a refusal while anything else is using the network.

const (
	jobKindReset = "network-reset"
	// resetConfirm is the exact string the body's confirm must carry.
	resetConfirm = "RESET"
	// networkResetTimeout bounds tools/tier.sh. A bring-up with the images
	// already pulled takes a few minutes; past this the process group is killed.
	networkResetTimeout = 15 * time.Minute
	// networkResetLog is the console-level record of every reset, beside the
	// run folders (never inside one): what was asked, from where, every output
	// line, and the exit code.
	networkResetLog = "network-resets.log"
)

// scriptRunner runs a command in dir with stdout and stderr merged into out,
// one line per Write, and returns its exit code. A cancelled ctx kills it.
type scriptRunner func(ctx context.Context, dir string, out io.Writer, name string, args ...string) (int, error)

// runStreaming is the production scriptRunner.
func runStreaming(ctx context.Context, dir string, out io.Writer, name string, args ...string) (int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	// tier.sh runs network.sh, docker and go underneath it: a timeout must take
	// the whole tree down, not just bash.
	killProcessGroup(cmd)
	cmd.WaitDelay = 5 * time.Second
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	done := make(chan struct{})
	go func() {
		defer close(done)
		copyLines(out, pr)
	}()
	err := cmd.Run()
	_ = pw.Close()
	<-done
	if ctx.Err() != nil {
		return -1, ctx.Err()
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}

// maxScriptLine is the longest output line kept whole; the rest of a longer
// line is cut, and reading carries on with the next one.
const maxScriptLine = 1 << 20

// copyLines writes r to out one line per Write, cutting any line longer than
// maxScriptLine rather than giving up on the output after it.
func copyLines(out io.Writer, r io.Reader) {
	br := bufio.NewReaderSize(r, 64*1024)
	var line []byte
	cut := false
	flush := func() {
		if cut {
			line = append(line, " [line cut at 1 MiB]"...)
		}
		_, _ = out.Write(append(line, '\n'))
		line, cut = line[:0], false
	}
	for {
		chunk, more, err := br.ReadLine()
		if err != nil {
			if len(line) > 0 || cut {
				flush()
			}
			return
		}
		if room := maxScriptLine - len(line); len(chunk) > room {
			chunk, cut = chunk[:room], true
		}
		line = append(line, chunk...)
		if !more {
			flush()
		}
	}
}

// decodeExactKeys decodes a JSON object body into v, accepting only the keys in
// allowed, each spelled exactly and given at most once. encoding/json matches
// keys case-insensitively and lets a later duplicate win, which would let
// {"confirm":"nope","CONFIRM":"RESET"} confirm.
func decodeExactKeys(w http.ResponseWriter, r *http.Request, v any, allowed ...string) error {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return errors.New("the body must be a JSON object")
	}
	seen := make(map[string]bool, len(allowed))
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := t.(string)
		switch {
		case !slices.Contains(allowed, key):
			return fmt.Errorf("unknown field %q: the fields are %v, spelled exactly", key, allowed)
		case seen[key]:
			return fmt.Errorf("field %q is given more than once", key)
		}
		seen[key] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("unexpected data after the JSON object")
	}
	return json.Unmarshal(body, v)
}

// locateTierScript finds tools/tier.sh under the console's repo root, or says
// why this host cannot run it. Pure over its inputs so every refusal is
// testable on any host.
func locateTierScript(goos string, lookPath func(string) (string, error), root string, rootOK bool) (string, error) {
	if goos == "windows" {
		return "", errors.New("network reset runs tools/tier.sh, a bash script that drives Fabric's test-network, " +
			"and this console runs on Windows: run the console inside WSL or Linux to reset the network")
	}
	if _, err := lookPath("bash"); err != nil {
		return "", errors.New("network reset runs tools/tier.sh and bash is not on this console's PATH")
	}
	if !rootOK {
		return "", errors.New("network reset runs tools/tier.sh from the console's repository, " +
			"and this console binary is not inside a git checkout: build and start it with tools/up.sh")
	}
	script := filepath.Join(root, "tools", "tier.sh")
	if _, err := os.Stat(script); err != nil {
		return "", fmt.Errorf("network reset runs %s, which is not there: %v", script, err)
	}
	return script, nil
}

// consoleTierScript is the Server's default tierScript: the repo root is found
// from the console binary, the same way env.go finds git_head_console.
func consoleTierScript() (string, error) {
	root, ok := "", false
	if exe, err := os.Executable(); err == nil {
		root, ok = findGitRoot(filepath.Dir(exe))
	}
	return locateTierScript(runtime.GOOS, exec.LookPath, root, ok)
}

// startExclusiveJob claims the job slot for kind only when no run phase is
// running either, both under s.mu, so no phase can start between the check and
// the claim (claim takes s.mu too). On refusal it has written the 409, naming
// what is busy, and returns nil.
func (s *Server) startExclusiveJob(w http.ResponseWriter, kind string) *job {
	s.mu.Lock()
	busy := s.busyRunsLocked("")
	var j *job
	running := s.jobs.running()
	if running == nil && len(busy) == 0 {
		j, running = s.jobs.start(kind)
	}
	s.mu.Unlock()
	switch {
	case running != nil: // a campaign's own repetition is busy too: name the campaign
		busyResponse(w, running)
		return nil
	case len(busy) > 0:
		writeJSONResp(w, http.StatusConflict, map[string]any{
			"error": fmt.Sprintf("a phase is running on %v: a %s would share the network with it; let it finish or cancel it first",
				busy, kind),
			"busy": busy,
		})
		return nil
	}
	return j
}

// handleNetworkReset serves POST /api/network/reset {voters, positions, confirm}.
func (s *Server) handleNetworkReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	refuse := func(code int, format string, args ...any) {
		writeJSONResp(w, code, map[string]string{"error": fmt.Sprintf(format, args...)})
	}
	// Loopback even with auth on: an admin session reaching the console from
	// another machine still may not destroy the ledger.
	if !isLoopback(r.RemoteAddr) {
		refuse(http.StatusForbidden, "a network reset is accepted only from the console machine itself (loopback)")
		return
	}
	var req struct {
		Voters    int    `json:"voters"`
		Positions int    `json:"positions"`
		Confirm   string `json:"confirm"`
	}
	if err := decodeExactKeys(w, r, &req, "voters", "positions", "confirm"); err != nil {
		refuse(http.StatusBadRequest, "invalid reset body: %v", err)
		return
	}
	switch {
	case req.Confirm != resetConfirm:
		refuse(http.StatusBadRequest, "confirm must be exactly %q: a reset destroys this network's ledger", resetConfirm)
		return
	case req.Voters < 1 || req.Positions < 1:
		refuse(http.StatusBadRequest, "voters and positions must each be >= 1: they size the tier the network is reset for")
		return
	}
	if !s.fabric.Enabled() {
		refuse(http.StatusBadRequest, "%v", errNoFabric())
		return
	}
	script, err := s.tierScript()
	if err != nil {
		refuse(http.StatusNotImplemented, "%v", err)
		return
	}
	j := s.startExclusiveJob(w, jobKindReset)
	if j == nil {
		return
	}
	from := r.RemoteAddr
	go s.jobs.run(j, func() (json.RawMessage, error) {
		return s.runReset(j, script, req.Voters, req.Positions, from)
	}, nil)
	writeJSONResp(w, http.StatusAccepted, map[string]string{"job": j.ID})
}

// runReset is the reset job's body: tools/tier.sh under networkResetTimeout,
// every output line into the job log and the console log.
func (s *Server) runReset(j *job, script string, voters, positions int, from string) (json.RawMessage, error) {
	logPath := filepath.Join(s.store.Root(), networkResetLog)
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		// A reset destroys a ledger; it does not run unrecorded.
		return nil, fmt.Errorf("reset not run: the console log %s cannot be opened: %w", logPath, err)
	}
	defer logFile.Close()
	start := time.Now()
	fmt.Fprintf(logFile, "%s reset %s start: %d voters x %d positions, requested from %s: bash %s %d %d\n",
		start.UTC().Format(time.RFC3339), j.ID, voters, positions, from, script, voters, positions)

	ctx, cancel := context.WithTimeout(context.Background(), networkResetTimeout)
	defer cancel()
	sink := io.MultiWriter(jobLog{&s.jobs, j}, logFile)
	code, runErr := s.runScript(ctx, filepath.Dir(filepath.Dir(script)), sink,
		"bash", script, strconv.Itoa(voters), strconv.Itoa(positions))
	// The cached /api/trail connection carries the old network's TLS CA and
	// client identity, which cryptogen has just regenerated under the same
	// paths. Dropped whatever the outcome; the next connection re-reads the
	// files (FabricConfig.Connect reads them on every call).
	s.dropChainConn()
	result := map[string]any{"voters": voters, "positions": positions, "log": logPath}

	timedOut := errors.Is(runErr, context.DeadlineExceeded)
	switch {
	case timedOut:
		err = fmt.Errorf("tools/tier.sh did not finish within %s and was killed: the network is in an unknown state, reset again", networkResetTimeout)
	case runErr != nil:
		err = fmt.Errorf("tools/tier.sh could not run: %w", runErr)
	case code != 0:
		err = fmt.Errorf("tools/tier.sh exited with code %d (see the job log): the network is in an unknown state", code)
	default:
		height, chainErr := s.readNewChain()
		if chainErr != nil {
			result["chain_error"] = chainErr.Error()
			err = fmt.Errorf("tools/tier.sh succeeded but this console cannot read the new network (%v): check that its "+
				"--fabric-tls-cert, --fabric-cert and --fabric-key point into the fabric-samples tools/tier.sh used", chainErr)
		} else {
			result["chain_height"] = height
			fmt.Fprintf(sink, "console reads the new network: channel height %d\n", height)
		}
	}
	outcome := "ok"
	if err != nil {
		outcome = err.Error()
	}
	fmt.Fprintf(logFile, "%s reset %s end: exit %d after %s: %s\n",
		time.Now().UTC().Format(time.RFC3339), j.ID, code, time.Since(start).Round(time.Second), outcome)
	result["exit_code"], result["timed_out"], result["duration_ms"] = code, timedOut, time.Since(start).Milliseconds()
	data, _ := json.Marshal(result)
	return data, err
}

// resetCheckTimeout bounds how long a finished reset retries reading the new
// network; resetCheckPoll is the wait between tries. Vars so tests are quick.
var resetCheckTimeout, resetCheckPoll = time.Minute, 2 * time.Second

// readNewChain connects with the console's own Fabric settings and reads the
// channel height, retrying while the new peer settles.
func (s *Server) readNewChain() (uint64, error) {
	deadline := time.Now().Add(resetCheckTimeout)
	for {
		_, led, err := s.dial()
		if err == nil {
			var h uint64
			if h, _, err = led.ChainInfo(); err == nil {
				return h, nil
			}
			s.dropChainConn() // a connection that cannot read is not kept
		}
		if time.Now().After(deadline) {
			return 0, err
		}
		time.Sleep(resetCheckPoll)
	}
}

// dropChainConn closes and forgets the cached /api/trail connection.
func (s *Server) dropChainConn() {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	if s.chainConn != nil {
		_ = s.chainConn.Close()
		s.chainConn = nil
	}
}
