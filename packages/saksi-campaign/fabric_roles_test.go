package campaign

import (
	"flag"
	"os"
	"path/filepath"
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
	if notes := c.ResolveTestNetworkRoles(); len(notes) != 0 {
		t.Fatalf("notes %v", notes)
	}
	if c.AdminCert != adc || c.AdminKey != adk || c.MachineCert != u1c || c.MachineKey != u1k {
		t.Fatalf("resolved %+v", c)
	}

	// An explicit machine (precinct B's User2) is kept; the admin is still filled.
	c = FabricConfig{MSPID: "Org1MSP", Cert: u1c, Key: u1k, MachineCert: u2c, MachineKey: u2k}
	c.ResolveTestNetworkRoles()
	if c.MachineCert != u2c || c.AdminCert != adc {
		t.Fatalf("resolved %+v", c)
	}

	// No Fabric configured: nothing to resolve, nothing noted.
	var off FabricConfig
	if notes := off.ResolveTestNetworkRoles(); notes != nil || off.AdminCert != "" {
		t.Fatalf("offline config resolved: %+v %v", off, notes)
	}

	// Outside the layout: the roles stay on Cert/Key, with a note each.
	c = FabricConfig{Cert: filepath.Join(t.TempDir(), "c.pem")}
	if notes := c.ResolveTestNetworkRoles(); len(notes) != 2 || c.AdminCert != "" || c.MachineCert != "" {
		t.Fatalf("outside layout: %+v %v", c, notes)
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
	if _, err := rf.Apply(&c); err != nil {
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
	if _, err := rf.Apply(&FabricConfig{Cert: u1c}); err == nil {
		t.Fatal("--fabric-admin-cert without its key accepted")
	}
}
