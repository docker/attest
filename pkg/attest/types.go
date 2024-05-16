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

type PolicyResult struct {
	// rolled up summary of policy evaluation
	Success    bool
	Policy     *policy.Policy
	Input      *policy.PolicyInput
	VSA        *intoto.Statement
	Violations []policy.Violation
}
