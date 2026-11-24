package main

import (
	"strings"
	"testing"

	saksiprotocolv1 "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
)

// Identities used across the R14 gate tests. Each newIdentity call is a
// distinct certificate, so two calls with the same subject still differ.
func org1Admin(t *testing.T) *fakeIdentity {
	return newIdentity(t, adminMSPID, "Admin@org1.example.com", adminOU)
}
func org1Client(t *testing.T) *fakeIdentity {
	return newIdentity(t, adminMSPID, "User1@org1.example.com", "client")
}
func org2Admin(t *testing.T) *fakeIdentity {
	return newIdentity(t, "Org2MSP", "Admin@org2.example.com", adminOU)
}

// errMust checks an error's gate and, when sub is non-empty, that its
// message contains sub. An empty gate means the call must succeed.
func errMust(t *testing.T, label string, err error, gate, sub string) {
	t.Helper()
	if gate == "" {
		if err != nil {
			t.Errorf("%s: unexpected error: %v", label, err)
		}
		return
	}
	if got := gateIDOf(err); got != gate {
		t.Errorf("%s: refused at %q, want %q (err: %v)", label, got, gate, err)
		return
	}
	if sub != "" && !strings.Contains(err.Error(), sub) {
		t.Errorf("%s: error %q does not contain %q", label, err, sub)
	}
}

// B1: only an Org1 administrator may create an election.
func TestCreateElectionAdminGate(t *testing.T) {
	for _, c := range []struct {
		name string
		id   *fakeIdentity
		gate string
	}{
		{"org1 admin creates", org1Admin(t), ""},
		{"org1 client refused (B1)", org1Client(t), "admin"},
		{"org2 admin refused", org2Admin(t), "admin"},
		{"admin OU under no MSP refused", newIdentity(t, "", "x", adminOU), "admin"},
		{"no identity refused", nil, "admin"},
	} {
		sc, ctx := &SmartContract{}, newContext()
		ctx.identity = c.id
		err := sc.CreateElection(ctx, mustMarshalParams(t, validElectionParams()))
		errMust(t, c.name, err, c.gate, "")
		_, getErr := sc.GetElection(ctx, "election-2026")
		if created := getErr == nil; created != (c.gate == "") {
			t.Errorf("%s: election stored = %v, want %v", c.name, created, c.gate == "")
		}
	}
}

func TestCloseElectionAdminGate(t *testing.T) {
	for _, c := range []struct {
		name string
		id   *fakeIdentity
		gate string
	}{
		{"org1 admin closes", org1Admin(t), ""},
		{"org1 client refused", org1Client(t), "admin"},
		{"org2 admin refused", org2Admin(t), "admin"},
		{"the precinct machine itself refused", newIdentity(t, adminMSPID, "machine-p01", "client"), "admin"},
	} {
		sc, ctx := &SmartContract{}, newContext()
		withElection(t, sc, ctx)
		err := sc.CloseElection(ctx.as(c.id), "election-2026")
		errMust(t, c.name, err, c.gate, "")
		status, _ := sc.GetElectionStatus(ctx, "election-2026")
		want := electionStatusOpen
		if c.gate == "" {
			want = electionStatusClosed
		}
		if status != want {
			t.Errorf("%s: status = %q, want %q", c.name, status, want)
		}
	}
}

func TestRegisterPrecinctMachine(t *testing.T) {
	machine := newIdentity(t, adminMSPID, "machine-p01", "client")
	other := newIdentity(t, adminMSPID, "machine-p02", "client")
	fp := machine.fingerprint()

	// bareElection creates election-2026 as admin without registering a machine.
	bareElection := func(t *testing.T) (*SmartContract, *fakeContext) {
		sc, ctx := &SmartContract{}, newContext()
		if err := sc.CreateElection(ctx, mustMarshalParams(t, validElectionParams())); err != nil {
			t.Fatalf("CreateElection: %v", err)
		}
		return sc, ctx
	}

	for _, c := range []struct {
		name  string
		setup func(t *testing.T, sc *SmartContract, ctx *fakeContext)
		as    *fakeIdentity // nil: the default admin
		elect string
		fp    string
		gate  string
		sub   string
	}{
		{name: "register before the first ballot", fp: fp},
		{name: "after close refused", fp: fp, gate: "machine-window", sub: "closed",
			setup: func(t *testing.T, sc *SmartContract, ctx *fakeContext) {
				if err := sc.CloseElection(ctx, "election-2026"); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "after a ballot is recorded refused", fp: fp, gate: "machine-window", sub: "already has ballots",
			setup: func(t *testing.T, _ *SmartContract, ctx *fakeContext) {
				seedBallots(t, ctx, "election-2026", 1) // a ballot from an older build
			}},
		{name: "double register refused", fp: other.fingerprint(), gate: "machine-duplicate", sub: "already registered",
			setup: func(t *testing.T, sc *SmartContract, ctx *fakeContext) {
				if err := sc.RegisterPrecinctMachine(ctx, "election-2026", fp); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "same machine twice refused", fp: fp, gate: "machine-duplicate",
			setup: func(t *testing.T, sc *SmartContract, ctx *fakeContext) {
				if err := sc.RegisterPrecinctMachine(ctx, "election-2026", fp); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "upper-case hex refused", fp: strings.ToUpper(fp), gate: "shape", sub: "lower-case hex"},
		{name: "63 digits refused", fp: fp[:63], gate: "shape"},
		{name: "65 digits refused", fp: fp + "0", gate: "shape"},
		{name: "non-hex refused", fp: "g" + fp[1:], gate: "shape"},
		{name: "empty fingerprint refused", fp: "", gate: "shape"},
		{name: "empty election id refused", elect: "-", fp: fp, gate: "shape"},
		{name: "unknown election refused", elect: "no-such-election", fp: fp, gate: "election-exists"},
		{name: "org1 client refused", as: org1Client(t), fp: fp, gate: "admin"},
		{name: "machine registering itself refused", as: machine, fp: fp, gate: "admin"},
		{name: "org2 admin refused", as: org2Admin(t), fp: fp, gate: "admin"},
	} {
		t.Run(c.name, func(t *testing.T) {
			sc, ctx := bareElection(t)
			if c.setup != nil {
				c.setup(t, sc, ctx)
			}
			before, _ := sc.GetPrecinctMachine(ctx, "election-2026")
			elect := "election-2026"
			switch c.elect {
			case "":
			case "-":
				elect = ""
			default:
				elect = c.elect
			}
			if c.as != nil {
				ctx.as(c.as)
			}
			errMust(t, c.name, sc.RegisterPrecinctMachine(ctx, elect, c.fp), c.gate, c.sub)
			got, _ := sc.GetPrecinctMachine(ctx, "election-2026")
			want := before
			if c.gate == "" {
				want = c.fp
			}
			if got != want {
				t.Errorf("binding = %q, want %q", got, want)
			}
		})
	}
}

func TestGetPrecinctMachineMissingIsError(t *testing.T) {
	sc, ctx := &SmartContract{}, newContext()
	withElection(t, sc, ctx)
	if _, err := sc.GetPrecinctMachine(newContext(), "election-2026"); err == nil || !strings.Contains(err.Error(), "no precinct machine") {
		t.Fatalf("expected a no-machine error, got %v", err)
	}
	if fp, err := sc.GetPrecinctMachine(ctx, "election-2026"); err != nil || fp != testOperator().fingerprint() {
		t.Fatalf("GetPrecinctMachine = %q, %v; want the operator fingerprint", fp, err)
	}
}

// The caller gate: only the registered machine's certificate may submit the
// election's ballots, and it is checked before every older gate.
func TestSubmitBallotCallerGate(t *testing.T) {
	machine := newIdentity(t, adminMSPID, "machine-p01", "client")
	otherPrecinct := newIdentity(t, adminMSPID, "machine-p02", "client")
	// sameSubject has the machine's subject but its own key: a different cert.
	sameSubject := newIdentity(t, adminMSPID, "machine-p01", "client")

	for _, c := range []struct {
		name     string
		register bool
		as       *fakeIdentity
		ballot   func(*saksiprotocolv1.Ballot)
		gate     string
		sub      string
	}{
		{name: "registered machine submits", register: true, as: machine},
		{name: "other cert refused", register: true, as: org1Client(t), gate: "caller", sub: "is not this precinct's machine"},
		{name: "admin cert refused", register: true, as: org1Admin(t), gate: "caller", sub: "is not this precinct's machine"},
		{name: "same subject, other key refused", register: true, as: sameSubject, gate: "caller", sub: "is not this precinct's machine"},
		{name: "other precinct's machine refused", register: true, as: otherPrecinct, gate: "caller", sub: "is not this precinct's machine"},
		{name: "no identity refused", register: true, as: nil, gate: "caller", sub: "cannot identify the caller"},
		{name: "no registration refused", register: false, as: machine, gate: "caller", sub: "no precinct machine is registered"},
		{name: "caller before shape", register: true, as: org1Client(t), gate: "caller",
			ballot: func(b *saksiprotocolv1.Ballot) { b.Version = 99 }},
		{name: "machine still meets shape", register: true, as: machine, gate: "shape",
			ballot: func(b *saksiprotocolv1.Ballot) { b.Version = 99 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			sc, ctx := &SmartContract{}, newContext()
			// Another precinct's election, bound to its own machine.
			p02 := validElectionParams()
			p02.ElectionId = "election-2026-p02"
			createElectionFor(t, sc, ctx, mustMarshalParams(t, p02), otherPrecinct)
			if c.register {
				withCDSElectionMachine(t, sc, ctx, nil, machine)
			} else {
				_, contestID, _, _, _, _, _ := loadCDSVector(t)
				p := &saksiprotocolv1.ElectionParameters{
					Version: saksiprotocolv1.WireVersion, ElectionId: "election-2026",
					ContestIds: []string{contestID}, TrusteeIds: []string{"t1"}, Threshold: 1,
				}
				if err := sc.CreateElection(ctx, mustMarshalParams(t, p)); err != nil {
					t.Fatal(err)
				}
			}
			ballot := validCDSBallot(t)
			if c.ballot != nil {
				c.ballot(ballot)
			}
			ctx.identity = c.as
			errMust(t, c.name, sc.SubmitBallot(ctx, mustMarshal(t, ballot)), c.gate, c.sub)
		})
	}
}
