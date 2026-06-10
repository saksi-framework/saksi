// Command saksi-bulletin is the chaincode entrypoint for the BalotaChain
// bulletin board. It wraps the SmartContract in a Fabric chaincode server and
// starts it; the Fabric peer invokes the registered transactions.
package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/saksi-framework/saksi/packages/saksi-bulletin/chaincode"
)

func main() {
	cc, err := contractapi.NewChaincode(&chaincode.SmartContract{})
	if err != nil {
		log.Panicf("create saksi-bulletin chaincode: %v", err)
	}
	if err := cc.Start(); err != nil {
		log.Panicf("start saksi-bulletin chaincode: %v", err)
	}
}
