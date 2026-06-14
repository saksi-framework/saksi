module github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk

go 1.22.0

toolchain go1.23.4

require (
	github.com/hyperledger/fabric-gateway v1.7.1
	github.com/saksi-framework/saksi/packages/saksi-protocol/go v0.0.0
	google.golang.org/grpc v1.69.2
	google.golang.org/protobuf v1.36.0
)

require (
	github.com/hyperledger/fabric-protos-go-apiv2 v0.3.4 // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241015192408-796eee8c2d53 // indirect
)

replace github.com/saksi-framework/saksi/packages/saksi-protocol/go => ../../saksi-protocol/go
