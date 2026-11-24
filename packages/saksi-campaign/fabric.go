package campaign

import (
	"flag"
	"fmt"
	"os"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

// FabricConfig holds the connection material for on-chain mode. Zero-value =
// on-chain mode unavailable; the offline path never touches it.
type FabricConfig struct {
	PeerEndpoint string
	GatewayPeer  string
	TLSCert      string
	MSPID        string
	Cert         string
	Key          string
	Channel      string
	Chaincode    string
	// AdminCert and AdminKey are the administrator identity that signs
	// CreateElection, RegisterPrecinctMachine and CloseElection (the
	// chaincode's admin gate). Empty = Cert/Key sign them.
	AdminCert string
	AdminKey  string
	// MachineCert and MachineKey are the precinct machine that signs every
	// SubmitBallot; each election this console creates registers this
	// certificate's fingerprint. Empty = Cert/Key are the machine.
	MachineCert string
	MachineKey  string
	// PeerVolume is the host path of the peer's ledger volume. Optional: set
	// it to have the ballot window record on-disk ledger growth
	// (perf.csv's ledger_bytes_delta). Not part of Enabled() — a missing
	// volume path costs a column, not a connection.
	PeerVolume string
}

// Enabled reports whether every field needed to reach a live network is set.
func (c FabricConfig) Enabled() bool {
	return c.PeerEndpoint != "" && c.GatewayPeer != "" && c.TLSCert != "" &&
		c.MSPID != "" && c.Cert != "" && c.Key != "" && c.Channel != "" && c.Chaincode != ""
}

// Connect opens a gateway connection for this config. Its Bulletin client and
// Ledger sign each transaction with the identity clientsdk.RoleFor names.
func (c FabricConfig) Connect() (*clientsdk.Connection, error) {
	cfg := clientsdk.ConnectionConfig{
		PeerEndpoint: c.PeerEndpoint,
		GatewayPeer:  c.GatewayPeer,
		TLSCertPath:  c.TLSCert,
		MSPID:        c.MSPID,
		CertPath:     c.Cert,
		KeyPath:      c.Key,
		Channel:      c.Channel,
		Chaincode:    c.Chaincode,
	}
	if c.AdminCert != "" {
		cfg.Admin = &clientsdk.Identity{CertPath: c.AdminCert, KeyPath: c.AdminKey}
	}
	if c.MachineCert != "" {
		cfg.Machine = &clientsdk.Identity{CertPath: c.MachineCert, KeyPath: c.MachineKey}
	}
	return clientsdk.Connect(cfg)
}

// CheckRoles refuses a role given half (a certificate without its key, or
// the reverse).
func (c FabricConfig) CheckRoles() error {
	if (c.AdminCert == "") != (c.AdminKey == "") {
		return fmt.Errorf("--fabric-admin-cert and --fabric-admin-key go together")
	}
	if (c.MachineCert == "") != (c.MachineKey == "") {
		return fmt.Errorf("--fabric-machine-cert and --fabric-machine-key go together")
	}
	return nil
}

// ResolveTestNetworkRoles fills an unset administrator and precinct machine
// from the test-network layout around Cert: Admin@<org> and User1@<org>
// (clientsdk.FillTestNetworkRoles). It returns a note per role it could not
// resolve; that role then stays on Cert/Key.
func (c *FabricConfig) ResolveTestNetworkRoles() []string {
	if c.Cert == "" {
		return nil
	}
	cfg := clientsdk.ConnectionConfig{MSPID: c.MSPID, CertPath: c.Cert}
	if c.AdminCert != "" {
		cfg.Admin = &clientsdk.Identity{CertPath: c.AdminCert, KeyPath: c.AdminKey}
	}
	if c.MachineCert != "" {
		cfg.Machine = &clientsdk.Identity{CertPath: c.MachineCert, KeyPath: c.MachineKey}
	}
	notes := clientsdk.FillTestNetworkRoles(&cfg)
	if cfg.Admin != nil {
		c.AdminCert, c.AdminKey = cfg.Admin.CertPath, cfg.Admin.KeyPath
	}
	if cfg.Machine != nil {
		c.MachineCert, c.MachineKey = cfg.Machine.CertPath, cfg.Machine.KeyPath
	}
	return notes
}

// RoleFlags are the --fabric-admin-* and --fabric-machine-* flags, shared by
// every binary that creates elections or submits ballots.
type RoleFlags struct {
	AdminCert, AdminKey, MachineCert, MachineKey *string
}

// FabricRoleFlags registers the administrator and precinct-machine identity
// flags on fs. Each defaults to its environment variable; left empty, Apply
// resolves it from the test-network layout around --fabric-cert.
func FabricRoleFlags(fs *flag.FlagSet) RoleFlags {
	return RoleFlags{
		AdminCert: fs.String("fabric-admin-cert", os.Getenv("SAKSI_FABRIC_ADMIN_CERT"),
			"administrator certificate that signs CreateElection, RegisterPrecinctMachine and CloseElection (env SAKSI_FABRIC_ADMIN_CERT; default Admin@<org> beside --fabric-cert)"),
		AdminKey: fs.String("fabric-admin-key", os.Getenv("SAKSI_FABRIC_ADMIN_KEY"),
			"private key for --fabric-admin-cert (env SAKSI_FABRIC_ADMIN_KEY)"),
		MachineCert: fs.String("fabric-machine-cert", os.Getenv("SAKSI_FABRIC_MACHINE_CERT"),
			"precinct-machine certificate that signs every ballot; each election created here registers it (env SAKSI_FABRIC_MACHINE_CERT; default User1@<org> beside --fabric-cert)"),
		MachineKey: fs.String("fabric-machine-key", os.Getenv("SAKSI_FABRIC_MACHINE_KEY"),
			"private key for --fabric-machine-cert (env SAKSI_FABRIC_MACHINE_KEY)"),
	}
}

// Apply sets the flags' identities on c, checks each is given whole, and
// fills the unset ones from the test-network layout (ResolveTestNetworkRoles).
// It returns that resolution's notes.
func (f RoleFlags) Apply(c *FabricConfig) ([]string, error) {
	c.AdminCert, c.AdminKey = *f.AdminCert, *f.AdminKey
	c.MachineCert, c.MachineKey = *f.MachineCert, *f.MachineKey
	if err := c.CheckRoles(); err != nil {
		return nil, err
	}
	return c.ResolveTestNetworkRoles(), nil
}
