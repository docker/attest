package attest

import (
	"github.com/docker/attest/pkg/policy"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

const (
	InTotoReferenceLifecycleStage = "vnd.docker.lifecycle-stage"
	LifecycleStageExperimental    = "experimental"
)

type SigningOptions struct {
	Replace bool
}

type Outcome string

const (
	OutcomeSuccess  Outcome = "success"
	OutcomeFailure  Outcome = "failure"
	OutcomeNoPolicy Outcome = "no_policy"
)

func (o Outcome) String() string {
	switch o {
	case OutcomeSuccess:
		return "PASSED"
	case OutcomeFailure:
		return "FAILED"
	default:
		return "UNKNOWN"
	}
}

type VerificationResult struct {
	Outcome    Outcome
	Policy     *policy.Policy
	Input      *policy.PolicyInput
	VSA        *intoto.Statement
	Violations []policy.Violation
}
