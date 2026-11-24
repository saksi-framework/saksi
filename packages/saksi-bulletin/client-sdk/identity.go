package clientsdk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hyperledger/fabric-gateway/pkg/identity"
)

// Role names which of a connection's identities signs a transaction.
//
// The chaincode refuses CreateElection, RegisterPrecinctMachine and
// CloseElection from anyone but an administrator (gate "admin"), and refuses a
// SubmitBallot whose caller is not the election's registered precinct machine
// (gate "caller"). A connection can therefore hold up to three identities: the
// default one, an administrator, and the precinct machine.
type Role string

const (
	// RoleDefault signs every transaction no other role claims (DKG
	// transcript, partial decryptions, tally, and every query).
	RoleDefault Role = "default"
	// RoleAdmin signs CreateElection, RegisterPrecinctMachine and CloseElection.
	RoleAdmin Role = "admin"
	// RoleMachine signs SubmitBallot: it is the precinct's registered machine.
	RoleMachine Role = "machine"
)

// RoleFor is the role whose identity signs chaincode function fn.
func RoleFor(fn string) Role {
	switch fn {
	case "CreateElection", "RegisterPrecinctMachine", "CloseElection":
		return RoleAdmin
	case "SubmitBallot":
		return RoleMachine
	}
	return RoleDefault
}

// Identity is one signing identity: an X.509 certificate and its private key,
// both PEM files, under an MSP. An empty MSPID means the connection's MSPID.
type Identity struct {
	MSPID    string
	CertPath string
	KeyPath  string
}

// CertFingerprint is the precinct-machine fingerprint of a PEM certificate:
// the SHA-256 of its DER bytes, as 64 lower-case hex digits. It is the value
// the chaincode computes from the caller's certificate, and the argument
// RegisterPrecinctMachine takes.
func CertFingerprint(certPEM []byte) (string, error) {
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

// CertFileFingerprint is CertFingerprint of the PEM file at path.
func CertFileFingerprint(path string) (string, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read certificate: %w", err)
	}
	fp, err := CertFingerprint(pem)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return fp, nil
}

// TestNetworkUser resolves another user of the same organization in a
// cryptogen (fabric-samples test-network) layout. certPath is any user's
// certificate, <org>/users/<name>@<domain>/msp/signcerts/<file>; user is the
// other user's name ("Admin", "User1", "User2", ...). It returns the first
// file in that user's msp/signcerts and msp/keystore, the way the test
// network's scripts pick them.
func TestNetworkUser(certPath, user string) (cert, key string, err error) {
	signcerts := filepath.Dir(certPath)
	msp := filepath.Dir(signcerts)
	who := filepath.Dir(msp)
	users := filepath.Dir(who)
	at := strings.LastIndex(filepath.Base(who), "@")
	if filepath.Base(signcerts) != "signcerts" || filepath.Base(msp) != "msp" ||
		filepath.Base(users) != "users" || at < 0 {
		return "", "", fmt.Errorf("%s is not in a test-network layout (<org>/users/<name>@<domain>/msp/signcerts/)", certPath)
	}
	domain := filepath.Base(who)[at+1:]
	dir := filepath.Join(users, user+"@"+domain, "msp")
	if cert, err = firstFile(filepath.Join(dir, "signcerts")); err != nil {
		return "", "", err
	}
	if key, err = firstFile(filepath.Join(dir, "keystore")); err != nil {
		return "", "", err
	}
	return cert, key, nil
}

func firstFile(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return "", fmt.Errorf("no file in %s", dir)
	}
	sort.Strings(names)
	return filepath.Join(dir, names[0]), nil
}

// routedContract sends each transaction to the contract of the identity whose
// role RoleFor names, falling back to the default identity when that role has
// none.
type routedContract struct {
	byRole map[Role]Contract
}

func (r routedContract) pick(fn string) Contract {
	if c, ok := r.byRole[RoleFor(fn)]; ok {
		return c
	}
	return r.byRole[RoleDefault]
}

func (r routedContract) SubmitTransaction(name string, args ...string) ([]byte, error) {
	return r.pick(name).SubmitTransaction(name, args...)
}

func (r routedContract) EvaluateTransaction(name string, args ...string) ([]byte, error) {
	return r.pick(name).EvaluateTransaction(name, args...)
}

// TestNetworkRoleUser is the test-network user each role defaults to:
// Admin@<org> (cryptogen NodeOU "admin") for RoleAdmin, User1@<org> for
// RoleMachine.
func TestNetworkRoleUser(role Role) string {
	if role == RoleAdmin {
		return "Admin"
	}
	return "User1"
}

// FillTestNetworkRoles sets cfg.Admin and cfg.Machine, where they are unset,
// to the test-network users TestNetworkRoleUser names in cfg.CertPath's
// organization. It returns one note per role it could not resolve; that role
// then stays unset, so the default identity signs its transactions.
func FillTestNetworkRoles(cfg *ConnectionConfig) []string {
	var notes []string
	for _, r := range []struct {
		role Role
		dst  **Identity
	}{{RoleAdmin, &cfg.Admin}, {RoleMachine, &cfg.Machine}} {
		if *r.dst != nil || cfg.CertPath == "" {
			continue
		}
		cert, key, err := TestNetworkUser(cfg.CertPath, TestNetworkRoleUser(r.role))
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s identity not resolved (%v); the default identity signs its transactions", r.role, err))
			continue
		}
		*r.dst = &Identity{MSPID: cfg.MSPID, CertPath: cert, KeyPath: key}
	}
	return notes
}
