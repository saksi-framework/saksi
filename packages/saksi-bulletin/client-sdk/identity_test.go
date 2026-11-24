package clientsdk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// selfSigned returns a fresh certificate as PEM plus its DER bytes.
func selfSigned(t *testing.T, cn string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), der
}

func TestCertFingerprintIsSHA256OfDER(t *testing.T) {
	p, der := selfSigned(t, "User1@org1.example.com")
	sum := sha256.Sum256(der)
	want := hex.EncodeToString(sum[:])
	got, err := CertFingerprint(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("fingerprint = %s, want %s", got, want)
	}
	if got != strings.ToLower(got) || len(got) != 64 {
		t.Fatalf("fingerprint %q is not 64 lower-case hex digits", got)
	}
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, p, 0o600); err != nil {
		t.Fatal(err)
	}
	if fromFile, err := CertFileFingerprint(path); err != nil || fromFile != want {
		t.Fatalf("CertFileFingerprint = %q, %v; want %q", fromFile, err, want)
	}
}

func TestCertFingerprintRejectsNonCertificate(t *testing.T) {
	if _, err := CertFingerprint([]byte("not a pem")); err == nil {
		t.Fatal("garbage accepted as a certificate")
	}
	if _, err := CertFileFingerprint(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("a missing file gave a fingerprint")
	}
}

func TestRoleFor(t *testing.T) {
	for fn, want := range map[string]Role{
		"CreateElection":          RoleAdmin,
		"RegisterPrecinctMachine": RoleAdmin,
		"CloseElection":           RoleAdmin,
		"SubmitBallot":            RoleMachine,
		"PublishDKGTranscript":    RoleDefault,
		"SubmitPartialDecryption": RoleDefault,
		"PublishTally":            RoleDefault,
		"GetElection":             RoleDefault,
	} {
		if got := RoleFor(fn); got != want {
			t.Errorf("RoleFor(%s) = %s, want %s", fn, got, want)
		}
	}
}

func TestRoutedContractSendsEachFunctionToItsIdentity(t *testing.T) {
	def, adm, mach := &fakeContract{}, &fakeContract{}, &fakeContract{}
	rc := routedContract{byRole: map[Role]Contract{RoleDefault: def, RoleAdmin: adm, RoleMachine: mach}}
	b := NewBulletinClient(rc)
	if err := b.CreateElection("aa"); err != nil {
		t.Fatal(err)
	}
	if err := b.RegisterPrecinctMachine("e1", strings.Repeat("ab", 32)); err != nil {
		t.Fatal(err)
	}
	if adm.submitName != "RegisterPrecinctMachine" || def.submitName != "" {
		t.Fatalf("admin saw %q, default saw %q", adm.submitName, def.submitName)
	}
	if err := b.SubmitBallot("bb"); err != nil {
		t.Fatal(err)
	}
	if mach.submitName != "SubmitBallot" {
		t.Fatalf("machine saw %q, want SubmitBallot", mach.submitName)
	}
	if err := b.PublishTally("cc"); err != nil {
		t.Fatal(err)
	}
	if def.submitName != "PublishTally" {
		t.Fatalf("default saw %q, want PublishTally", def.submitName)
	}
	if err := b.CloseElection("e1"); err != nil {
		t.Fatal(err)
	}
	if adm.submitName != "CloseElection" {
		t.Fatalf("admin saw %q, want CloseElection", adm.submitName)
	}
}

func TestRoutedContractFallsBackToDefault(t *testing.T) {
	def := &fakeContract{}
	b := NewBulletinClient(routedContract{byRole: map[Role]Contract{RoleDefault: def}})
	if err := b.CreateElection("aa"); err != nil || def.submitName != "CreateElection" {
		t.Fatalf("CreateElection without an admin identity went to %q (%v)", def.submitName, err)
	}
	if err := b.SubmitBallot("bb"); err != nil || def.submitName != "SubmitBallot" {
		t.Fatalf("SubmitBallot without a machine identity went to %q (%v)", def.submitName, err)
	}
}

func TestRegisterAndGetPrecinctMachine(t *testing.T) {
	fc := &fakeContract{}
	b := NewBulletinClient(fc)
	fp := strings.Repeat("0a", 32)
	if err := b.RegisterPrecinctMachine("election-2026-p01", fp); err != nil {
		t.Fatal(err)
	}
	if fc.submitName != "RegisterPrecinctMachine" || len(fc.submitArgs) != 2 ||
		fc.submitArgs[0] != "election-2026-p01" || fc.submitArgs[1] != fp {
		t.Fatalf("submitted %s%v", fc.submitName, fc.submitArgs)
	}
	if err := b.RegisterPrecinctMachine("", fp); err == nil {
		t.Fatal("empty election id accepted")
	}
	if err := b.RegisterPrecinctMachine("e", ""); err == nil {
		t.Fatal("empty fingerprint accepted")
	}
	fc.evalReturn = []byte(fp)
	got, err := b.GetPrecinctMachine("election-2026-p01")
	if err != nil || got != fp || fc.submitName != "GetPrecinctMachine" {
		t.Fatalf("GetPrecinctMachine = %q, %v via %s", got, err, fc.submitName)
	}
}

// writeMSP lays out <org>/users/<who>/msp/{signcerts,keystore} as cryptogen does.
func writeMSP(t *testing.T, org, who string) (cert, key string) {
	t.Helper()
	msp := filepath.Join(org, "users", who, "msp")
	for _, d := range []string{"signcerts", "keystore"} {
		if err := os.MkdirAll(filepath.Join(msp, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cert = filepath.Join(msp, "signcerts", who+"-cert.pem")
	key = filepath.Join(msp, "keystore", "priv_sk")
	for _, f := range []string{cert, key} {
		if err := os.WriteFile(f, []byte(who), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return cert, key
}

func TestTestNetworkUser(t *testing.T) {
	org := filepath.Join(t.TempDir(), "peerOrganizations", "org1.example.com")
	user1Cert, _ := writeMSP(t, org, "User1@org1.example.com")
	adminCert, adminKey := writeMSP(t, org, "Admin@org1.example.com")

	cert, key, err := TestNetworkUser(user1Cert, "Admin")
	if err != nil {
		t.Fatal(err)
	}
	if cert != adminCert || key != adminKey {
		t.Fatalf("Admin resolved to %s / %s, want %s / %s", cert, key, adminCert, adminKey)
	}
	// From the admin's own cert back to User1.
	if c, _, err := TestNetworkUser(adminCert, "User1"); err != nil || c != user1Cert {
		t.Fatalf("User1 from the admin cert = %q, %v", c, err)
	}
	if _, _, err := TestNetworkUser(user1Cert, "User9"); err == nil {
		t.Fatal("a user the network never issued was resolved")
	}
	if _, _, err := TestNetworkUser(filepath.Join(t.TempDir(), "cert.pem"), "Admin"); err == nil {
		t.Fatal("a cert outside the test-network layout was resolved")
	}
}

func TestFillTestNetworkRoles(t *testing.T) {
	org := filepath.Join(t.TempDir(), "org1.example.com")
	user1Cert, user1Key := writeMSP(t, org, "User1@org1.example.com")
	adminCert, adminKey := writeMSP(t, org, "Admin@org1.example.com")
	user2Cert, _ := writeMSP(t, org, "User2@org1.example.com")

	cfg := ConnectionConfig{MSPID: "Org1MSP", CertPath: user2Cert}
	if err := FillTestNetworkRoles(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Admin == nil || cfg.Admin.CertPath != adminCert || cfg.Admin.KeyPath != adminKey || cfg.Admin.MSPID != "Org1MSP" {
		t.Fatalf("admin = %+v", cfg.Admin)
	}
	if cfg.Machine == nil || cfg.Machine.CertPath != user1Cert || cfg.Machine.KeyPath != user1Key {
		t.Fatalf("machine = %+v", cfg.Machine)
	}

	// An explicit identity is kept.
	mine := &Identity{CertPath: "m.pem", KeyPath: "m.key"}
	cfg = ConnectionConfig{CertPath: user2Cert, Machine: mine}
	if err := FillTestNetworkRoles(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Machine != mine {
		t.Fatalf("explicit machine replaced by %+v", cfg.Machine)
	}

	// Outside the layout: both roles unresolved, an error naming each.
	cfg = ConnectionConfig{CertPath: filepath.Join(t.TempDir(), "cert.pem")}
	err := FillTestNetworkRoles(&cfg)
	var ur *UnresolvedRolesError
	if !errors.As(err, &ur) || len(ur.Roles) != 2 || ur.Roles[0].Role != RoleAdmin || ur.Roles[1].Role != RoleMachine {
		t.Fatalf("err = %v, want both roles unresolved", err)
	}
	if !strings.Contains(err.Error(), "Admin@<org>") || !strings.Contains(err.Error(), "User1@<org>") {
		t.Fatalf("error %q does not name the users looked for", err)
	}

	// Admin folder missing, machine resolvable: only the admin is reported.
	org2 := filepath.Join(t.TempDir(), "org1.example.com")
	c1, _ := writeMSP(t, org2, "User1@org1.example.com")
	cfg = ConnectionConfig{CertPath: c1}
	if err := FillTestNetworkRoles(&cfg); !errors.As(err, &ur) || len(ur.Roles) != 1 || ur.Roles[0].Role != RoleAdmin {
		t.Fatalf("err = %v, want only the admin unresolved", err)
	}

	// No default certificate: nothing to resolve.
	cfg = ConnectionConfig{}
	if err := FillTestNetworkRoles(&cfg); err != nil || cfg.Admin != nil {
		t.Fatalf("empty config: %v %+v", err, cfg.Admin)
	}
}

// TestCertFingerprintMatchesSharedVector pins CertFingerprint to
// saksi-protocol/test-vectors/machine-fingerprint-v1.json, the vector the
// chaincode's callerOf is checked against too.
func TestCertFingerprintMatchesSharedVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "saksi-protocol", "test-vectors", "machine-fingerprint-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		CertPEM     string `json:"cert_pem"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	got, err := CertFingerprint([]byte(v.CertPEM))
	if err != nil {
		t.Fatal(err)
	}
	if got != v.Fingerprint {
		t.Fatalf("CertFingerprint %s, vector %s", got, v.Fingerprint)
	}
}
