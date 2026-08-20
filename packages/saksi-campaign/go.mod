module github.com/saksi-framework/saksi/packages/saksi-campaign

go 1.23

replace github.com/saksi-framework/saksi/packages/saksi-protocol/go => ../saksi-protocol/go

require (
	github.com/saksi-framework/saksi/packages/saksi-protocol/go v0.0.0-00010101000000-000000000000
	google.golang.org/protobuf v1.36.12
)
