package clientsdk

import (
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// ConnectionConfig describes how to reach a peer's gateway and which identity to
// act as. The paths point at the MSP material issued by the network's CA.
type ConnectionConfig struct {
	// PeerEndpoint is the gateway peer's host:port (e.g. "localhost:7051").
	PeerEndpoint string
	// GatewayPeer is the peer's TLS server name (its certificate CN/SAN), used
	// to override the authority when it differs from the endpoint host.
	GatewayPeer string
	// TLSCertPath is the PEM file holding the peer's TLS CA certificate.
	TLSCertPath string
	// MSPID is the membership service provider id of the acting organization.
	MSPID string
	// CertPath is the PEM file holding the client identity's X.509 certificate.
	CertPath string
	// KeyPath is the PEM file holding the client identity's private key.
	KeyPath string
	// Channel is the Fabric channel the bulletin board runs on.
	Channel string
	// Chaincode is the deployed chaincode (contract) name.
	Chaincode string
	// Admin, when set, signs CreateElection, RegisterPrecinctMachine and
	// CloseElection (RoleFor). The chaincode accepts those only from an
	// administrator (MSP Org1MSP, certificate OU "admin"). Nil = the default
	// identity signs them.
	Admin *Identity
	// Machine, when set, signs SubmitBallot: it is the precinct machine an
	// administrator registers for each election. Nil = the default identity
	// signs ballots and is the machine.
	Machine *Identity
}

// Connection is an open gateway connection. Call Close when finished.
type Connection struct {
	gateway   *client.Gateway // the default identity's
	grpcConn  *grpc.ClientConn
	channel   string
	chaincode string
	// gateways holds one gateway per role that has its own identity
	// (RoleDefault always; RoleAdmin and RoleMachine when configured). They
	// share grpcConn.
	gateways map[Role]*client.Gateway
	// machineFP is the fingerprint of the certificate that signs SubmitBallot.
	machineFP string

	// Bulletin is the ready-to-use bulletin-board client.
	Bulletin *BulletinClient
}

// Gateway exposes the underlying fabric-gateway client so callers can reach
// networks and system chaincodes (e.g. qscc) the BulletinClient doesn't wrap.
func (c *Connection) Gateway() *client.Gateway { return c.gateway }

// Close releases every gateway and the underlying gRPC connection.
func (c *Connection) Close() error {
	for _, g := range c.gateways {
		g.Close()
	}
	return c.grpcConn.Close()
}

// MachineFingerprint is the fingerprint (CertFingerprint) of the certificate
// that signs this connection's ballots: the Machine identity's, or the
// default identity's when no Machine is configured. It is what an election's
// RegisterPrecinctMachine must name for this connection's ballots to pass the
// chaincode's caller gate.
func (c *Connection) MachineFingerprint() string { return c.machineFP }

// As returns a bulletin client bound to exactly one role's identity, with no
// routing: every transaction it sends is signed by that identity (the default
// one when the role has none). Bulletin is the routed client most callers
// want; As exists for tests and harnesses that must act as a given identity.
func (c *Connection) As(role Role) *BulletinClient {
	return NewBulletinClient(c.contractFor(role))
}

// contractFor is role's contract, or the default identity's.
func (c *Connection) contractFor(role Role) *client.Contract {
	g, ok := c.gateways[role]
	if !ok {
		g = c.gateway
	}
	return g.GetNetwork(c.channel).GetContract(c.chaincode)
}

// Connect dials the peer gateway, authenticates with the configured
// identities, and returns a Connection whose Bulletin client targets the
// configured channel and chaincode. Bulletin (and Ledger) route each
// transaction to the identity RoleFor names.
func Connect(cfg ConnectionConfig) (*Connection, error) {
	grpcConn, err := newGRPCConnection(cfg)
	if err != nil {
		return nil, err
	}
	c := &Connection{
		grpcConn:  grpcConn,
		channel:   cfg.Channel,
		chaincode: cfg.Chaincode,
		gateways:  map[Role]*client.Gateway{},
	}
	fail := func(err error) (*Connection, error) {
		for _, g := range c.gateways {
			g.Close()
		}
		_ = grpcConn.Close()
		return nil, err
	}
	roles := []struct {
		role Role
		id   *Identity
	}{
		{RoleDefault, &Identity{MSPID: cfg.MSPID, CertPath: cfg.CertPath, KeyPath: cfg.KeyPath}},
		{RoleAdmin, cfg.Admin},
		{RoleMachine, cfg.Machine},
	}
	for _, r := range roles {
		if r.id == nil {
			continue
		}
		id := *r.id
		if id.MSPID == "" {
			id.MSPID = cfg.MSPID
		}
		g, err := newGateway(grpcConn, id)
		if err != nil {
			if r.role != RoleDefault {
				err = fmt.Errorf("%s identity: %w", r.role, err)
			}
			return fail(err)
		}
		c.gateways[r.role] = g
	}
	c.gateway = c.gateways[RoleDefault]

	machineCert := cfg.CertPath
	if cfg.Machine != nil {
		machineCert = cfg.Machine.CertPath
	}
	if c.machineFP, err = CertFileFingerprint(machineCert); err != nil {
		return fail(fmt.Errorf("machine fingerprint: %w", err))
	}

	byRole := map[Role]Contract{}
	for role := range c.gateways {
		byRole[role] = c.contractFor(role)
	}
	c.Bulletin = NewBulletinClient(routedContract{byRole: byRole})
	return c, nil
}

// newGateway opens a gateway for one identity over the shared gRPC connection.
func newGateway(grpcConn *grpc.ClientConn, idc Identity) (*client.Gateway, error) {
	id, err := newIdentity(idc)
	if err != nil {
		return nil, err
	}
	sign, err := newSign(idc)
	if err != nil {
		return nil, err
	}
	gateway, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(grpcConn),
		client.WithEvaluateTimeout(30*time.Second),
		client.WithSubmitTimeout(30*time.Second),
		client.WithCommitStatusTimeout(2*time.Minute),
	)
	if err != nil {
		return nil, fmt.Errorf("connect gateway: %w", err)
	}
	return gateway, nil
}

func newGRPCConnection(cfg ConnectionConfig) (*grpc.ClientConn, error) {
	pem, err := os.ReadFile(cfg.TLSCertPath)
	if err != nil {
		return nil, fmt.Errorf("read TLS cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates parsed from %s", cfg.TLSCertPath)
	}
	creds := credentials.NewClientTLSFromCert(pool, cfg.GatewayPeer)
	conn, err := grpc.NewClient(cfg.PeerEndpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("dial peer gateway %s: %w", cfg.PeerEndpoint, err)
	}
	return conn, nil
}

func newIdentity(cfg Identity) (*identity.X509Identity, error) {
	pem, err := os.ReadFile(cfg.CertPath)
	if err != nil {
		return nil, fmt.Errorf("read identity cert: %w", err)
	}
	cert, err := identity.CertificateFromPEM(pem)
	if err != nil {
		return nil, fmt.Errorf("parse identity cert: %w", err)
	}
	id, err := identity.NewX509Identity(cfg.MSPID, cert)
	if err != nil {
		return nil, fmt.Errorf("build identity: %w", err)
	}
	return id, nil
}

func newSign(cfg Identity) (identity.Sign, error) {
	pem, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	key, err := identity.PrivateKeyFromPEM(pem)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	sign, err := identity.NewPrivateKeySign(key)
	if err != nil {
		return nil, fmt.Errorf("build signer: %w", err)
	}
	return sign, nil
}
