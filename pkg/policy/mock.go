package policy

import (
	"context"

	"github.com/docker/attest/pkg/oci"
)

type MockPolicyEvaluator struct {
	EvaluateFunc func(ctx context.Context, resolver oci.AttestationResolver, pctx *Policy, input *PolicyInput) (*Result, error)
}

func (pe *MockPolicyEvaluator) Evaluate(ctx context.Context, resolver oci.AttestationResolver, pctx *Policy, input *PolicyInput) (*Result, error) {
	if pe.EvaluateFunc != nil {
		return pe.EvaluateFunc(ctx, resolver, pctx, input)
	}
	return AllowedResult(), nil
}

func GetMockPolicy() PolicyEvaluator {
	return &MockPolicyEvaluator{
		EvaluateFunc: func(ctx context.Context, resolver oci.AttestationResolver, pctx *Policy, input *PolicyInput) (*Result, error) {
			return AllowedResult(), nil
		},
	}
}

func AllowedResult() *Result {
	return &Result{
		Success: true,
	}
}
