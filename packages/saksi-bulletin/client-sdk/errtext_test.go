package clientsdk

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The gateway's own message never names the chaincode's reason; the endorser
// detail does. ErrorText must surface it through the wrapping every caller adds.
func TestErrorTextSurfacesEndorserDetailsThroughWrapping(t *testing.T) {
	st, err := status.New(codes.Aborted, "failed to endorse transaction, see attached details for more info").
		WithDetails(&gateway.ErrorDetail{
			Address: "peer0.org1.example.com:7051", MspId: "Org1MSP",
			Message: `chaincode response 500, gate=cds: contest "president/cand0" CDS well-formedness proof failed`,
		})
	if err != nil {
		t.Fatal(err)
	}
	wrapped := fmt.Errorf("submit SubmitBallot: %w", st.Err())

	got := ErrorText(wrapped)
	if !strings.Contains(got, "gate=cds: ") || !strings.HasPrefix(got, "submit SubmitBallot: ") {
		t.Fatalf("ErrorText = %q, want the wrapper's text followed by the endorser's gate message", got)
	}
}

func TestErrorTextOfAPlainError(t *testing.T) {
	if got := ErrorText(errors.New("boom")); got != "boom" {
		t.Fatalf("ErrorText = %q, want boom", got)
	}
	if ErrorText(nil) != "" {
		t.Fatal("ErrorText(nil) must be empty")
	}
}
