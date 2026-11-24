package clientsdk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeIdentity writes a fresh self-signed certificate and its PKCS#8 key.
func writeIdentity(t *testing.T, dir, name string) Identity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	id := Identity{CertPath: filepath.Join(dir, name+".pem"), KeyPath: filepath.Join(dir, name+".key")}
	if err := os.WriteFile(id.CertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(id.KeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0o600); err != nil {
		t.Fatal(err)
	}
	return id
}

// Connect does not dial (grpc.NewClient is lazy), so the identity wiring can
// be checked without a peer.
func TestConnectBuildsOneGatewayPerRole(t *testing.T) {
	dir := t.TempDir()
	tls := writeIdentity(t, dir, "tlsca")
	user := writeIdentity(t, dir, "user1")
	admin := writeIdentity(t, dir, "admin")
	machine := writeIdentity(t, dir, "user2")
	base := ConnectionConfig{PeerEndpoint: "localhost:1", GatewayPeer: "peer0", TLSCertPath: tls.CertPath,
		MSPID: "Org1MSP", CertPath: user.CertPath, KeyPath: user.KeyPath, Channel: "saksi", Chaincode: "cc"}

	cfg := base
	cfg.Admin, cfg.Machine = &admin, &machine
	conn, err := Connect(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if len(conn.gateways) != 3 {
		t.Fatalf("%d gateways, want 3", len(conn.gateways))
	}
	want, _ := CertFileFingerprint(machine.CertPath)
	if conn.MachineFingerprint() != want || conn.Ledger().MachineFingerprint() != want {
		t.Fatalf("machine fingerprint %s, want the machine cert's %s", conn.MachineFingerprint(), want)
	}
	for role, id := range map[Role]Identity{RoleDefault: user, RoleAdmin: admin, RoleMachine: machine} {
		got, _ := CertFingerprint(conn.gateways[role].Identity().Credentials())
		exp, _ := CertFileFingerprint(id.CertPath)
		if got != exp {
			t.Errorf("%s gateway signs as %s, want %s", role, got, exp)
		}
	}

	// No roles: one gateway, and the default identity is the machine.
	conn2, err := Connect(base)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	if want, _ := CertFileFingerprint(user.CertPath); len(conn2.gateways) != 1 || conn2.MachineFingerprint() != want {
		t.Fatalf("%d gateways, machine %s; want 1 and the default cert's %s", len(conn2.gateways), conn2.MachineFingerprint(), want)
	}

	// A broken role identity fails the whole connection, naming the role.
	cfg = base
	cfg.Admin = &Identity{CertPath: filepath.Join(dir, "missing.pem"), KeyPath: admin.KeyPath}
	if _, err := Connect(cfg); err == nil {
		t.Fatal("a missing admin certificate connected")
	} else if got := err.Error(); len(got) < 5 || got[:5] != "admin" {
		t.Fatalf("error %q does not name the admin identity", got)
	}
}
