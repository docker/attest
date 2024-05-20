package policy

import (
	"context"

	"github.com/docker/attest/pkg/oci"
	"github.com/open-policy-agent/opa/rego"
)

type MockPolicyEvaluator struct {
	EvaluateFunc func(ctx context.Context, resolver oci.AttestationResolver, pctx *Policy, input *PolicyInput) (*rego.ResultSet, error)
}

func (pe *MockPolicyEvaluator) Evaluate(ctx context.Context, resolver oci.AttestationResolver, pctx *Policy, input *PolicyInput) (*rego.ResultSet, error) {
	if pe.EvaluateFunc != nil {
		return pe.EvaluateFunc(ctx, resolver, pctx, input)
	}
	return AllowedResult(), nil
}

func GetMockPolicy() PolicyEvaluator {
	return &MockPolicyEvaluator{
		EvaluateFunc: func(ctx context.Context, resolver oci.AttestationResolver, pctx *Policy, input *PolicyInput) (*rego.ResultSet, error) {
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
