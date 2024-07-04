package attest

import (
	"fmt"

	"github.com/docker/attest/pkg/policy"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

type Outcome string

const (
	OutcomeSuccess  Outcome = "success"
	OutcomeFailure  Outcome = "failure"
	OutcomeNoPolicy Outcome = "no_policy"
)

func (o Outcome) StringForVSA() (string, error) {
	switch o {
	case OutcomeSuccess:
		return "PASSED", nil
	case OutcomeFailure:
		return "FAILED", nil
	default:
		return "", fmt.Errorf("unknown outcome: %s", o)
	}
}

type VerificationResult struct {
	Outcome    Outcome
	Policy     *policy.Policy
	Input      *policy.PolicyInput
	VSA        *intoto.Statement
	Violations []policy.Violation
}
