package campaign

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestMSP(t *testing.T, org, who string) (cert, key string) {
	t.Helper()
	msp := filepath.Join(org, "users", who, "msp")
	for _, d := range []string{"signcerts", "keystore"} {
		if err := os.MkdirAll(filepath.Join(msp, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cert = filepath.Join(msp, "signcerts", "cert.pem")
	key = filepath.Join(msp, "keystore", "priv_sk")
	for _, f := range []string{cert, key} {
		if err := os.WriteFile(f, []byte(who), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return cert, key
}

func TestResolveTestNetworkRoles(t *testing.T) {
	org := filepath.Join(t.TempDir(), "org1.example.com")
	u1c, u1k := writeTestMSP(t, org, "User1@org1.example.com")
	adc, adk := writeTestMSP(t, org, "Admin@org1.example.com")
	u2c, u2k := writeTestMSP(t, org, "User2@org1.example.com")

	c := FabricConfig{MSPID: "Org1MSP", Cert: u1c, Key: u1k}
	if err := c.ResolveTestNetworkRoles(); err != nil {
		t.Fatal(err)
	}
	if c.AdminCert != adc || c.AdminKey != adk || c.MachineCert != u1c || c.MachineKey != u1k {
		t.Fatalf("resolved %+v", c)
	}

	// An explicit machine (precinct B's User2) is kept; the admin is still filled.
	c = FabricConfig{MSPID: "Org1MSP", Cert: u1c, Key: u1k, MachineCert: u2c, MachineKey: u2k}
	if err := c.ResolveTestNetworkRoles(); err != nil {
		t.Fatal(err)
	}
	if c.MachineCert != u2c || c.AdminCert != adc {
		t.Fatalf("resolved %+v", c)
	}

	// No Fabric configured: nothing to resolve, nothing noted.
	var off FabricConfig
	if err := off.ResolveTestNetworkRoles(); err != nil || off.AdminCert != "" {
		t.Fatalf("offline config resolved: %+v %v", off, err)
	}
}

// An identity that cannot be resolved stops the console at start-up, with an
// error naming the role and the flag and environment variable that set it;
// it never silently falls back to --fabric-cert.
func TestResolveTestNetworkRolesFailsLoud(t *testing.T) {
	// Outside the layout: both roles missing.
	c := FabricConfig{Cert: filepath.Join(t.TempDir(), "c.pem")}
	err := c.ResolveTestNetworkRoles()
	if err == nil {
		t.Fatal("unresolvable roles accepted")
	}
	for _, want := range []string{"admin:", "machine:", "--fabric-admin-cert", "SAKSI_FABRIC_ADMIN_CERT", "--fabric-machine-cert", "SAKSI_FABRIC_MACHINE_CERT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %q:\n%v", want, err)
		}
	}
	if c.AdminCert != "" || c.MachineCert != "" {
		t.Fatalf("a failed resolution set identities: %+v", c)
	}

	// Admin@org1 missing (an org without it): only the admin is named.
	org := filepath.Join(t.TempDir(), "org1.example.com")
	u1c, u1k := writeTestMSP(t, org, "User1@org1.example.com")
	c = FabricConfig{Cert: u1c, Key: u1k}
	err = c.ResolveTestNetworkRoles()
	if err == nil || !strings.Contains(err.Error(), "--fabric-admin-cert") || strings.Contains(err.Error(), "machine:") {
		t.Fatalf("err = %v, want only the admin named", err)
	}

	// Given explicitly, the missing admin is no longer a problem.
	c = FabricConfig{Cert: u1c, Key: u1k, AdminCert: u1c, AdminKey: u1k}
	if err := c.ResolveTestNetworkRoles(); err != nil {
		t.Fatal(err)
	}
}

func TestFabricConfigCheckRoles(t *testing.T) {
	if err := (FabricConfig{}).CheckRoles(); err != nil {
		t.Fatal(err)
	}
	if err := (FabricConfig{AdminCert: "a"}).CheckRoles(); err == nil {
		t.Fatal("admin cert without key accepted")
	}
	if err := (FabricConfig{MachineKey: "k"}).CheckRoles(); err == nil {
		t.Fatal("machine key without cert accepted")
	}
}

func TestFabricRoleFlags(t *testing.T) {
	org := filepath.Join(t.TempDir(), "org1.example.com")
	u1c, u1k := writeTestMSP(t, org, "User1@org1.example.com")
	adc, adk := writeTestMSP(t, org, "Admin@org1.example.com")
	u2c, u2k := writeTestMSP(t, org, "User2@org1.example.com")
	t.Setenv("SAKSI_FABRIC_MACHINE_CERT", u2c)
	t.Setenv("SAKSI_FABRIC_MACHINE_KEY", u2k)

	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	rf := FabricRoleFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	c := FabricConfig{MSPID: "Org1MSP", Cert: u1c, Key: u1k}
	if err := rf.Apply(&c); err != nil {
		t.Fatal(err)
	}
	if c.AdminCert != adc || c.AdminKey != adk || c.MachineCert != u2c || c.MachineKey != u2k {
		t.Fatalf("applied %+v", c)
	}

	fs = flag.NewFlagSet("t", flag.ContinueOnError)
	rf = FabricRoleFlags(fs)
	if err := fs.Parse([]string{"--fabric-admin-cert", adc}); err != nil {
		t.Fatal(err)
	}
	if err := rf.Apply(&FabricConfig{Cert: u1c}); err == nil {
		t.Fatal("--fabric-admin-cert without its key accepted")
	}
}
