package policy

import (
	"context"

	"github.com/docker/attest/pkg/oci"
)

type MockPolicyEvaluator struct {
	EvaluateFunc func(ctx context.Context, resolver oci.AttestationResolver, pctx *Policy, input *Input) (*Result, error)
}

func (pe *MockPolicyEvaluator) Evaluate(ctx context.Context, resolver oci.AttestationResolver, pctx *Policy, input *Input) (*Result, error) {
	if pe.EvaluateFunc != nil {
		return pe.EvaluateFunc(ctx, resolver, pctx, input)
	}
	return AllowedResult(), nil
}

func GetMockPolicy() Evaluator {
	return &MockPolicyEvaluator{
		EvaluateFunc: func(_ context.Context, _ oci.AttestationResolver, _ *Policy, _ *Input) (*Result, error) {
			return AllowedResult(), nil
		},
	}
}

func AllowedResult() *Result {
	return &Result{
		Success: true,
	}
}
