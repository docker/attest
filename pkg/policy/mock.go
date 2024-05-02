package policy

import (
	"context"

	"github.com/docker/attest/pkg/oci"
	"github.com/open-policy-agent/opa/rego"
)

type MockPolicyEvaluator struct {
	EvaluateFunc func(ctx context.Context, resolver oci.AttestationResolver, policy []*PolicyFile, input *PolicyInput) (*rego.ResultSet, error)
}

func (pe *MockPolicyEvaluator) Evaluate(ctx context.Context, resolver oci.AttestationResolver, policy []*PolicyFile, input *PolicyInput) (*rego.ResultSet, error) {
	if pe.EvaluateFunc != nil {
		return pe.EvaluateFunc(ctx, resolver, policy, input)
	}
	return AllowedResult(), nil
}

func GetMockPolicy() PolicyEvaluator {
	return &MockPolicyEvaluator{
		EvaluateFunc: func(ctx context.Context, resolver oci.AttestationResolver, pfs []*PolicyFile, input *PolicyInput) (*rego.ResultSet, error) {
			return AllowedResult(), nil
		},
	}
}

func AllowedResult() *rego.ResultSet {
	return &rego.ResultSet{
		{
			Bindings: rego.Vars{},
			Expressions: []*rego.ExpressionValue{
				{
					Value: true,
				},
			},
		},
	}
}
