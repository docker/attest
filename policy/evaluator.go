package policy

import (
	"context"

	"github.com/docker/attest/attestation"
)

type Evaluator interface {
	Evaluate(ctx context.Context, resolver attestation.Resolver, pctx *Policy, input *Input) (*Result, error)
}
