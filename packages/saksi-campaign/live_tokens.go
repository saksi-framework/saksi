package campaign

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// Trustee process tokens. Each live trustee process (saksi-campaign trustee
// --id N) calls the console server to server with its own bearer token. The
// tokens file stores only the SHA-256 of each token, keyed by trustee id; a
// token resolves to exactly one trustee id, and every trustee-token route acts
// as that trustee only.

const errTrusteeToken = "trustee token required"

// minTrusteeTokenBytes is the shortest token hash-token accepts. The file
// holds only hashes, so the length is checked where the token is made.
const minTrusteeTokenBytes = 32

// TrusteeToken is one entry of the --trustee-tokens file.
type TrusteeToken struct {
	TrusteeID   string `json:"trustee_id"`
	TokenSHA256 string `json:"token_sha256"`
}

type trusteeTokens struct {
	ids    []string
	hashes [][32]byte
}

// LoadTrusteeTokens reads and validates a tokens file: a JSON array of
// TrusteeToken, one per trustee id, no hash twice.
func LoadTrusteeTokens(path string) (*trusteeTokens, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trustee tokens file: %w", err)
	}
	return parseTrusteeTokens(data)
}

func parseTrusteeTokens(data []byte) (*trusteeTokens, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var list []TrusteeToken
	if err := dec.Decode(&list); err != nil {
		return nil, fmt.Errorf("trustee tokens file must be a JSON array of {trustee_id, token_sha256}: %w", err)
	}
	if len(list) == 0 {
		return nil, errors.New("trustee tokens file has no entries")
	}
	out := &trusteeTokens{}
	seenID := map[string]bool{}
	seenHash := map[[32]byte]bool{}
	for i, e := range list {
		if !trusteeIDPattern.MatchString(e.TrusteeID) {
			return nil, fmt.Errorf("entry %d: trustee_id %q must be the trustee's wire id: digits, no leading zero", i+1, e.TrusteeID)
		}
		if seenID[e.TrusteeID] {
			return nil, fmt.Errorf("entry %d: trustee_id %q has a token already", i+1, e.TrusteeID)
		}
		raw, err := hex.DecodeString(e.TokenSHA256)
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("entry %d: token_sha256 must be 64 hex digits (make one with `saksi-campaign hash-token`)", i+1)
		}
		var h [32]byte
		copy(h[:], raw)
		if seenHash[h] {
			return nil, fmt.Errorf("entry %d: trustee %s shares a token with another trustee", i+1, e.TrusteeID)
		}
		seenID[e.TrusteeID], seenHash[h] = true, true
		out.ids = append(out.ids, e.TrusteeID)
		out.hashes = append(out.hashes, h)
	}
	return out, nil
}

// has reports whether trustee id has a token.
func (t *trusteeTokens) has(id string) bool {
	for _, x := range t.ids {
		if x == id {
			return true
		}
	}
	return false
}

// match returns the trustee id whose token hashes to the presented one. Every
// entry is compared, in constant time, so the time taken says nothing about
// which entry (if any) matched.
func (t *trusteeTokens) match(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(token))
	found := -1
	for i, h := range t.hashes {
		if subtle.ConstantTimeCompare(sum[:], h[:]) == 1 {
			found = i
		}
	}
	if found < 0 {
		return "", false
	}
	return t.ids[found], true
}

// trusteeFromToken resolves the request's bearer token to a trustee id. False
// when live mode is off, no token was sent, or it matches no trustee.
func (s *Server) trusteeFromToken(r *http.Request) (string, bool) {
	if s.live == nil || s.live.tokens == nil {
		return "", false
	}
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return "", false
	}
	return s.live.tokens.match(strings.TrimSpace(tok))
}

type trusteeTokenKey struct{}

// tokenTrustee is the trustee id authorize resolved from the bearer token, or
// "" when the request carried none (which a trustee-token handler refuses).
func tokenTrustee(r *http.Request) string {
	id, _ := r.Context().Value(trusteeTokenKey{}).(string)
	return id
}

// HashTrusteeToken reads one token line from in and returns its SHA-256 hex,
// the token_sha256 value of a tokens file. The token never comes from argv.
func HashTrusteeToken(in io.Reader) (string, error) {
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read token: %w", err)
	}
	tok := strings.TrimRight(line, "\r\n")
	if len(tok) < minTrusteeTokenBytes {
		return "", fmt.Errorf("a trustee token must be at least %d bytes (try `saksi-campaign new-token`)", minTrusteeTokenBytes)
	}
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:]), nil
}

// NewTrusteeToken returns a fresh random token: 32 bytes, hex.
func NewTrusteeToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
