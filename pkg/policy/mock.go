package policy

import (
	"context"

	"github.com/docker/attest/pkg/oci"
)

type MockPolicyEvaluator struct {
	EvaluateFunc func(ctx context.Context, resolver oci.AttestationResolver, pctx *Policy, input *PolicyInput) (*VerificationResult, error)
}

func (pe *MockPolicyEvaluator) Evaluate(ctx context.Context, resolver oci.AttestationResolver, pctx *Policy, input *PolicyInput) (*VerificationResult, error) {
	if pe.EvaluateFunc != nil {
		return pe.EvaluateFunc(ctx, resolver, pctx, input)
	}
	return AllowedResult(), nil
}

func GetMockPolicy() PolicyEvaluator {
	return &MockPolicyEvaluator{
		EvaluateFunc: func(ctx context.Context, resolver oci.AttestationResolver, pctx *Policy, input *PolicyInput) (*VerificationResult, error) {
			return AllowedResult(), nil
		},
	}
}

func AllowedResult() *VerificationResult {
	return &VerificationResult{
		Success: true,
	}
}
