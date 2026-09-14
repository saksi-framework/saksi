package clientsdk

import (
	"strings"

	"github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	"google.golang.org/grpc/status"
)

// ErrorText is err's message followed by the messages the endorsing peers
// attached to it.
//
// The Fabric Gateway reports a chaincode rejection as a gRPC status whose own
// message is generic ("failed to endorse transaction, see attached details for
// more info"). The chaincode's actual words — and the "gate=<id>:" prefix its
// rejections carry — travel only in the status details, one gateway
// ErrorDetail per endorser, so a caller that needs to know WHY a transaction
// was refused has to read them from there. Wrapping with %w keeps them
// reachable: status.FromError unwraps.
func ErrorText(err error) string {
	if err == nil {
		return ""
	}
	parts := []string{err.Error()}
	if st, ok := status.FromError(err); ok {
		for _, d := range st.Details() {
			if ed, ok := d.(*gateway.ErrorDetail); ok && ed.GetMessage() != "" {
				parts = append(parts, ed.GetMessage())
			}
		}
	}
	return strings.Join(parts, "; ")
}
