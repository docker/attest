package policy

import (
	"context"
	"fmt"

	"github.com/docker/attest/pkg/oci"
)

type policyEvaluatorCtxKeyType struct{}

var PolicyEvaluatorCtxKey policyEvaluatorCtxKeyType

// sets PolicyEvaluator in context.
func WithPolicyEvaluator(ctx context.Context, pe Evaluator) context.Context {
	return context.WithValue(ctx, PolicyEvaluatorCtxKey, pe)
}

// gets PolicyEvaluator from context, defaults to Rego PolicyEvaluator if not set.
func GetPolicyEvaluator(ctx context.Context) (Evaluator, error) {
	t, ok := ctx.Value(PolicyEvaluatorCtxKey).(Evaluator)
	if !ok {
		return nil, fmt.Errorf("no policy evaluator client set on context (set one with policy.WithPolicyEvaluator)")
	}
	return t, nil
}

type Evaluator interface {
	Evaluate(ctx context.Context, resolver oci.AttestationResolver, pctx *Policy, input *Input) (*Result, error)
}
