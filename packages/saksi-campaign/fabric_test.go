package campaign

import "testing"

func TestFabricConfigEnabled(t *testing.T) {
	if (FabricConfig{}).Enabled() {
		t.Fatal("empty config must be disabled")
	}
	full := FabricConfig{
		PeerEndpoint: "localhost:7051", GatewayPeer: "peer0.org1.example.com",
		TLSCert: "/tls/ca.crt", MSPID: "Org1MSP", Cert: "/msp/cert.pem", Key: "/msp/key.pem",
		Channel: "saksi", Chaincode: "saksi-bulletin",
	}
	if !full.Enabled() {
		t.Fatal("full config must be enabled")
	}
	if (FabricConfig{PeerEndpoint: "localhost:7051"}).Enabled() {
		t.Fatal("partial config must be disabled")
	}
}
