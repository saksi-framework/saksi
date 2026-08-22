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
}

// Connection is an open gateway connection. Call Close when finished.
type Connection struct {
	gateway  *client.Gateway
	grpcConn *grpc.ClientConn

	// Bulletin is the ready-to-use bulletin-board client.
	Bulletin *BulletinClient
}

// Gateway exposes the underlying fabric-gateway client so callers can reach
// networks and system chaincodes (e.g. qscc) the BulletinClient doesn't wrap.
// THROWAWAY (QSCC spike): promoted to a designed API in the audit-trail work.
func (c *Connection) Gateway() *client.Gateway { return c.gateway }

// Close releases the gateway and the underlying gRPC connection.
func (c *Connection) Close() error {
	c.gateway.Close()
	return c.grpcConn.Close()
}

// Connect dials the peer gateway, authenticates with the configured identity,
// and returns a Connection whose Bulletin client targets the configured channel
// and chaincode.
func Connect(cfg ConnectionConfig) (*Connection, error) {
	grpcConn, err := newGRPCConnection(cfg)
	if err != nil {
		return nil, err
	}

	id, err := newIdentity(cfg)
	if err != nil {
		_ = grpcConn.Close()
		return nil, err
	}
	sign, err := newSign(cfg)
	if err != nil {
		_ = grpcConn.Close()
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
		_ = grpcConn.Close()
		return nil, fmt.Errorf("connect gateway: %w", err)
	}

	contract := gateway.GetNetwork(cfg.Channel).GetContract(cfg.Chaincode)
	return &Connection{
		gateway:  gateway,
		grpcConn: grpcConn,
		Bulletin: NewBulletinClient(contract),
	}, nil
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

func newIdentity(cfg ConnectionConfig) (*identity.X509Identity, error) {
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

func newSign(cfg ConnectionConfig) (identity.Sign, error) {
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
