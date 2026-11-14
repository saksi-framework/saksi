package campaign

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Blind credential issuance. The issuer signs blindly: the console sees the
// voter's blinded commitment and blinded challenge, never the credential.
//
// The rules (each is tested):
//   - only a voter account on the roll, in state open (issuance closes with
//     the election);
//   - at most one open session per account: a new presign discards the old
//     session file before the next is written;
//   - at most one signature per account per election, ever: the account is
//     recorded in private/issued.json (atomic, fsynced) before the signature
//     is returned, and there is no route that clears it;
//   - one issue-presign or issue-sign at a time across every account
//     (issueMu), and few concurrent sessions (liveMaxSessions, liveSessionTTL),
//     which keeps the blind-signature ROS attack out of reach.

// issuedRecord is private/issued.json: the accounts that were given a
// signature, and when. It is the eligibility control.
type issuedRecord map[string]time.Time

// The issuance paths take the run folder from the public snapshot, never
// from L.dir, which only mu guards.

func issuedPath(dir string) string    { return filepath.Join(dir, livePrivateDir, liveIssuedFile) }
func sessionsDirOf(dir string) string { return filepath.Join(dir, livePrivateDir, liveSessionsDir) }
func issuerKeyOf(dir string) string   { return filepath.Join(dir, livePrivateDir, liveIssuerKey) }

func readIssued(dir string) (issuedRecord, error) {
	rec := issuedRecord{}
	data, err := os.ReadFile(issuedPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return rec, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("issued record is unreadable: %w", err)
	}
	return rec, nil
}

func writeIssued(dir string, rec issuedRecord) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(issuedPath(dir), data, 0o600)
}

// sessionPath is account's session file. The name is a hash of the account,
// so no account string reaches a path, and each account has one name.
func sessionPath(dir, account string) string {
	sum := sha256.Sum256([]byte("saksi.live.session.v1\x00" + account))
	return filepath.Join(sessionsDirOf(dir), hex.EncodeToString(sum[:16])+".json")
}

// sweepClaimed removes session files issue-sign claimed but did not get to
// delete (a crash after its rename): they can never be signed with again.
func sweepClaimed(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".claimed.") {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

// openSessions counts session files younger than the TTL, removing the stale
// ones.
func openSessions(dir string, now time.Time) (int, error) {
	sessions := sessionsDirOf(dir)
	entries, err := os.ReadDir(sessions)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > liveSessionTTL {
			_ = os.Remove(filepath.Join(sessions, e.Name()))
			continue
		}
		n++
	}
	return n, nil
}

// errTooMany is 429.
type errTooMany struct{ msg string }

func (e errTooMany) Error() string { return e.msg }

// checkIssuable is the shared gate of presign and sign. It reads the state
// from the public snapshot, never from the live state. Caller holds issueMu.
func (L *liveService) checkIssuable(account string) (*liveSnapshot, error) {
	st := L.snapshot()
	if st == nil {
		return nil, errNotFound{"no live election has been set up"}
	}
	if st.State != LiveOpen {
		return nil, conflictf("credentials are issued while the election is open; it is %s", st.State)
	}
	if u, ok := L.s.auth.users[account]; !ok || u.Role != RoleVoter {
		return nil, errForbidden{"this account is not on the voter roll"}
	}
	issued, err := readIssued(st.Dir)
	if err != nil {
		return nil, err
	}
	if _, done := issued[account]; done {
		return nil, conflictf("this account has been issued its credential for this election already; a lost credential cannot be issued again")
	}
	return st, nil
}

// presign starts (or restarts) account's issuance session.
func (L *liveService) presign(ctx context.Context, account, blindedCommitment string) (map[string]string, error) {
	if !hex64(blindedCommitment) {
		return nil, badRequestf("blinded_commitment must be a 64-hex-digit point")
	}
	L.issueMu.Lock()
	defer L.issueMu.Unlock()
	st, err := L.checkIssuable(account)
	if err != nil {
		return nil, err
	}
	if err := sweepClaimed(sessionsDirOf(st.Dir)); err != nil {
		return nil, err
	}
	path := sessionPath(st.Dir, account)
	// One open session per account: the earlier one is discarded first.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	n, err := openSessions(st.Dir, L.now())
	if err != nil {
		return nil, err
	}
	if n >= liveMaxSessions {
		return nil, errTooMany{"too many credential issuances are open at once; try again in a few minutes"}
	}
	var out struct {
		R string `json:"r"`
	}
	if err := L.opJSON(ctx, "issue-presign", map[string]string{
		"issuer_key_file": issuerKeyOf(st.Dir), "blinded_commitment": blindedCommitment, "session_file": path,
	}, &out); err != nil {
		return nil, badRequestf("%v", err)
	}
	return map[string]string{"r": out.R, "issuer_public_key": st.IssuerPublicKey}, nil
}

// sign completes account's issuance: one signature, recorded before it is
// returned.
func (L *liveService) sign(ctx context.Context, account, ePrime string) (map[string]string, error) {
	if !hex64(ePrime) {
		return nil, badRequestf("e_prime must be a 64-hex-digit scalar")
	}
	L.issueMu.Lock()
	defer L.issueMu.Unlock()
	st, err := L.checkIssuable(account)
	if err != nil {
		return nil, err
	}
	path := sessionPath(st.Dir, account)
	info, err := os.Stat(path)
	if err != nil {
		return nil, conflictf("no issuance session is open for this account; start again with presign")
	}
	if L.now().Sub(info.ModTime()) > liveSessionTTL {
		_ = os.Remove(path)
		return nil, conflictf("the issuance session expired; start again with presign")
	}
	var out struct {
		SIss string `json:"s_iss"`
	}
	signErr := L.opJSON(ctx, "issue-sign", map[string]string{
		"issuer_key_file": issuerKeyOf(st.Dir), "session_file": path, "e_prime": ePrime,
	}, &out)
	_ = sweepClaimed(sessionsDirOf(st.Dir))
	if signErr != nil {
		return nil, badRequestf("%v", signErr)
	}
	// Recorded on disk before the signature leaves: if this write fails the
	// signature is dropped, and the account may try again.
	issued, err := readIssued(st.Dir)
	if err != nil {
		return nil, err
	}
	issued[account] = L.now().UTC()
	if err := writeIssued(st.Dir, issued); err != nil {
		return nil, fmt.Errorf("cannot record the issuance; the signature was not released: %w", err)
	}
	L.mu.Lock()
	if L.st != nil && L.st.RunID == st.RunID {
		L.st.Issued = len(issued)
		err = L.save()
	}
	L.mu.Unlock()
	if err != nil {
		log.Printf("live: %s save after issuance: %v", st.RunID, err)
	}
	return map[string]string{"s_iss": out.SIss, "issuer_public_key": st.IssuerPublicKey}, nil
}
