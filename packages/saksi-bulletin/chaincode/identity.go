package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const (
	// adminMSPID is the MSP whose administrators may set up and close
	// elections and register precinct machines. ElectionParameters records no
	// owning organisation, so the admin org is fixed here: Org1MSP is the org
	// that runs the console on the test network (network.sh, saksi-campaign
	// --fabric-msp-id default).
	adminMSPID = "Org1MSP"
	// adminOU is the NodeOU that cryptogen (and a Fabric CA with NodeOUs
	// enabled) writes into an administrator's certificate subject.
	adminOU = "admin"
	// machineIndex keys the registered precinct machine (certificate
	// fingerprint) by electionID: one machine per election.
	machineIndex = "machine"
	// fingerprintHexLen is the length of a lower-case hex SHA-256 digest.
	fingerprintHexLen = 64
)

// callerIdentity is what the gates need to know about the submitting client.
type callerIdentity struct {
	MSPID string
	// OUs are the certificate subject's OrganizationalUnit values.
	OUs []string
	// Fingerprint is the lower-case hex SHA-256 of the certificate's DER bytes.
	Fingerprint string
}

// callerOf reads the submitting client's identity from the transaction
// context. Tests inject an identity by overriding GetClientIdentity on their
// fake context.
func callerOf(ctx contractapi.TransactionContextInterface) (callerIdentity, error) {
	id := ctx.GetClientIdentity()
	if id == nil {
		return callerIdentity{}, fmt.Errorf("no client identity on the transaction")
	}
	msp, err := id.GetMSPID()
	if err != nil {
		return callerIdentity{}, fmt.Errorf("read caller MSP id: %w", err)
	}
	cert, err := id.GetX509Certificate()
	if err != nil {
		return callerIdentity{}, fmt.Errorf("read caller certificate: %w", err)
	}
	if cert == nil {
		return callerIdentity{}, fmt.Errorf("caller has no X.509 certificate")
	}
	sum := sha256.Sum256(cert.Raw)
	return callerIdentity{
		MSPID:       msp,
		OUs:         slices.Clone(cert.Subject.OrganizationalUnit),
		Fingerprint: hex.EncodeToString(sum[:]),
	}, nil
}

// requireAdmin refuses the transaction (gate `admin`) unless the caller is an
// administrator of adminMSPID: MSP id equal to it and OU `admin` in the
// certificate.
func requireAdmin(ctx contractapi.TransactionContextInterface, action string) error {
	caller, err := callerOf(ctx)
	if err != nil {
		return rejectAt("admin", "%s needs an administrator: %w", action, err)
	}
	if caller.MSPID != adminMSPID || !slices.Contains(caller.OUs, adminOU) {
		return rejectAt("admin", "%s needs an administrator of %s (OU %q); caller is MSP %q with OUs %v",
			action, adminMSPID, adminOU, caller.MSPID, caller.OUs)
	}
	return nil
}

// isFingerprintHex reports whether s is exactly 64 lower-case hex digits.
func isFingerprintHex(s string) bool {
	if len(s) != fingerprintHexLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
