package campaign

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
//   - only for a list entry whose check-in is signed (live_checkin.go), in
//     state open (issuance closes with the election); the phone shows it by
//     its saksi_checkin cookie. No account, voter or otherwise, can obtain a
//     credential;
//   - at most one open session per entry: a new presign discards the old
//     session file before the next is written;
//   - at most one signature per entry per election, ever: the entry moves to
//     credential_issued in private/checkin.json (atomic, fsynced) before the
//     signature is returned, and there is no route back from that state;
//   - one issue-presign or issue-sign at a time across every entry (issueMu),
//     and few concurrent sessions (liveMaxSessions, liveSessionTTL), which
//     keeps the blind-signature ROS attack out of reach.
//
// The check-in record holds no time, and an issuance does not move
// live.json's updated_at: the ballots are public in arrival order with their
// commit times, so an issuance time per entry would help link entries to
// ballots. (The record file's own mtime still shows the last change.)

// The issuance paths take the run folder from the public snapshot, never
// from L.dir, which only mu guards.

func sessionsDirOf(dir string) string { return filepath.Join(dir, livePrivateDir, liveSessionsDir) }
func issuerKeyOf(dir string) string   { return filepath.Join(dir, livePrivateDir, liveIssuerKey) }

// sessionPath is a list entry's session file. The name is a hash of the
// entry's key, so no name reaches a path, and each entry has one file name.
func sessionPath(dir, key string) string {
	sum := sha256.Sum256([]byte("saksi.live.session.v1\x00" + key))
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

// checkIssuable is the shared gate of presign and sign: the snapshot and the
// sequence number of the entry token's check-in. It reads the election state
// from the public snapshot, never from the live state. Caller holds issueMu.
func (L *liveService) checkIssuable(token string) (*liveSnapshot, int, error) {
	st := L.snapshot()
	if st == nil {
		return nil, 0, errNotFound{"no live election has been set up"}
	}
	if st.State != LiveOpen {
		return nil, 0, conflictf("credentials are issued while the election is open; it is %s", st.State)
	}
	L.ckMu.Lock()
	defer L.ckMu.Unlock()
	b, _, err := L.bookLocked(false)
	if err != nil {
		return nil, 0, err
	}
	i, err := phoneEntryLocked(b, token)
	if err != nil {
		return nil, 0, err
	}
	switch b.rec.Entries[i].State {
	case CheckinSigned:
		return st, b.rows[i].Seq, nil
	case CheckinIssued:
		return nil, 0, errAlreadyIssued
	default:
		return nil, 0, errNotSigned
	}
}

// presign starts (or restarts) the token's entry's issuance session.
func (L *liveService) presign(ctx context.Context, token, blindedCommitment string) (map[string]string, error) {
	if !hex64(blindedCommitment) {
		return nil, badRequestf("blinded_commitment must be a 64-hex-digit point")
	}
	L.issueMu.Lock()
	defer L.issueMu.Unlock()
	st, seq, err := L.checkIssuable(token)
	if err != nil {
		return nil, err
	}
	if err := sweepClaimed(sessionsDirOf(st.Dir)); err != nil {
		return nil, errInternal{"the issuance sessions could not be swept"}
	}
	path := sessionPath(st.Dir, entrySessionKey(seq))
	// One open session per entry: the earlier one is discarded first.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errInternal{"an earlier issuance session could not be removed"}
	}
	n, err := openSessions(st.Dir, L.now())
	if err != nil {
		return nil, errInternal{"the issuance sessions could not be counted"}
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

// sign completes the token's entry's issuance: one signature, recorded before
// it is returned.
func (L *liveService) sign(ctx context.Context, token, ePrime string) (map[string]string, error) {
	if !hex64(ePrime) {
		return nil, badRequestf("e_prime must be a 64-hex-digit scalar")
	}
	L.issueMu.Lock()
	defer L.issueMu.Unlock()
	st, seq, err := L.checkIssuable(token)
	if err != nil {
		return nil, err
	}
	path := sessionPath(st.Dir, entrySessionKey(seq))
	info, err := os.Stat(path)
	if err != nil {
		return nil, conflictf("no issuance session is open for this check-in; start again with presign")
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
	// signature is dropped, and the entry may try again. issueMu is held, so
	// no reset ran since checkIssuable.
	L.ckMu.Lock()
	b := L.ck
	i := seq - 1
	if b == nil || b.dir != st.Dir || b.rec.Entries[i].State != CheckinSigned {
		L.ckMu.Unlock()
		return nil, errInternal{"the check-in changed during issuance; the signature was not released"}
	}
	e := b.rec.Entries[i]
	e.State = CheckinIssued
	if err := b.set(i, e, "", ""); err != nil {
		L.ckMu.Unlock()
		return nil, errInternal{"the issuance could not be recorded; the signature was not released"}
	}
	L.publishCheckinLocked()
	L.ckMu.Unlock()

	// The entry is credential_issued on disk, so the signature is released
	// now, whatever else happens. The count in live.json is only a copy of
	// the check-in record's: it is saved here when mu is free, and otherwise
	// by the transition that holds mu (every save takes the count from the
	// published check-in counts, saveUntimed). The reply never waits on mu,
	// which a Close holds across a chain submit that can stall for minutes:
	// a phone that timed out there could never be issued again.
	if L.mu.TryLock() {
		if L.st != nil && L.st.RunID == st.RunID {
			// No timestamp: updated_at keeps the last transition's time.
			err = L.saveUntimed()
		}
		L.mu.Unlock()
		if err != nil {
			log.Printf("live: %s save after issuance: %v", st.RunID, err)
		}
	}
	return map[string]string{"s_iss": out.SIss, "issuer_public_key": st.IssuerPublicKey}, nil
}
