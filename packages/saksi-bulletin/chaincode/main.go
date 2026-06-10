package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func main() {
	cc, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		log.Panicf("create saksi-bulletin chaincode: %v", err)
	}
	if err := cc.Start(); err != nil {
		log.Panicf("start saksi-bulletin chaincode: %v", err)
	}
}
