package policy

import (
	"context"

	"github.com/docker/attest/pkg/attestation"
)

type Evaluator interface {
	Evaluate(ctx context.Context, resolver attestation.Resolver, pctx *Policy, input *Input) (*Result, error)
}
