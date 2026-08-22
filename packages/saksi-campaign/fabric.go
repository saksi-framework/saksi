package campaign

import (
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
}

// Enabled reports whether every field needed to reach a live network is set.
func (c FabricConfig) Enabled() bool {
	return c.PeerEndpoint != "" && c.GatewayPeer != "" && c.TLSCert != "" &&
		c.MSPID != "" && c.Cert != "" && c.Key != "" && c.Channel != "" && c.Chaincode != ""
}

// Connect opens a gateway connection for this config.
func (c FabricConfig) Connect() (*clientsdk.Connection, error) {
	return clientsdk.Connect(clientsdk.ConnectionConfig{
		PeerEndpoint: c.PeerEndpoint,
		GatewayPeer:  c.GatewayPeer,
		TLSCertPath:  c.TLSCert,
		MSPID:        c.MSPID,
		CertPath:     c.Cert,
		KeyPath:      c.Key,
		Channel:      c.Channel,
		Chaincode:    c.Chaincode,
	})
}
