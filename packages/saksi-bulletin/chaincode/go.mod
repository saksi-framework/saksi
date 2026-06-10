module github.com/saksi-framework/saksi/packages/saksi-bulletin/chaincode

go 1.22

require (
	github.com/hyperledger/fabric-contract-api-go v1.2.2
	github.com/saksi-framework/saksi/packages/saksi-protocol/go v0.0.0
)

replace github.com/saksi-framework/saksi/packages/saksi-protocol/go => ../../saksi-protocol/go
