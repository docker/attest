package policy

import (
	"context"
	"fmt"

	"github.com/docker/attest/pkg/oci"
	"github.com/open-policy-agent/opa/rego"
)

type policyEvaluatorCtxKeyType struct{}

var PolicyEvaluatorCtxKey policyEvaluatorCtxKeyType

// sets PolicyEvaluator in context
func WithPolicyEvaluator(ctx context.Context, pe PolicyEvaluator) context.Context {
	return context.WithValue(ctx, PolicyEvaluatorCtxKey, pe)
}

// gets PolicyEvaluator from context, defaults to Rego PolicyEvaluator if not set
func GetPolicyEvaluator(ctx context.Context) (PolicyEvaluator, error) {
	t, ok := ctx.Value(PolicyEvaluatorCtxKey).(PolicyEvaluator)
	if !ok {
		return nil, fmt.Errorf("no policy evaluator client set on context (set one with policy.WithPolicyEvaluator)")
	}
	return t, nil
}

type PolicyEvaluator interface {
	Evaluate(ctx context.Context, resolver oci.AttestationResolver, policy []*PolicyFile, input *PolicyInput) (*rego.ResultSet, error)
}
