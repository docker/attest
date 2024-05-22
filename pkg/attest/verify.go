package attest

import (
	"context"
	"fmt"
	"time"

	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/policy"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

func Verify(ctx context.Context, opts *policy.PolicyOptions, resolver oci.AttestationResolver) (result *VerificationResult, err error) {
	pctx, err := policy.ResolvePolicy(ctx, resolver, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve policy: %w", err)
	}

	if pctx == nil {
		return &VerificationResult{
			Outcome: OutcomeNoPolicy,
		}, nil
	}

	result, err = VerifyAttestations(ctx, resolver, pctx)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}
	return result, nil
}

func ToPolicyResult(p *policy.Policy, input *policy.PolicyInput, result *policy.Result) (*VerificationResult, error) {
	dgst, err := oci.SplitDigest(input.Digest)
	if err != nil {
		return nil, fmt.Errorf("failed to split digest: %w", err)
	}
	subject := intoto.Subject{
		Name:   input.Purl,
		Digest: *dgst,
	}
	resourceUri, err := attestation.ToVSAResourceURI(subject)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource uri: %w", err)
	}

	var outcome Outcome
	if result.Success {
		outcome = OutcomeSuccess
	} else {
		outcome = OutcomeFailure
	}

	outcomeStr, err := outcome.StringForVSA()
	if err != nil {
		return nil, err
	}

	return &VerificationResult{
		Policy:     p,
		Outcome:    outcome,
		Violations: result.Violations,
		VSA: &intoto.Statement{
			StatementHeader: intoto.StatementHeader{
				PredicateType: attestation.VSAPredicateType,
				Type:          intoto.StatementInTotoV01,
				Subject:       result.Summary.Subjects,
			},
			Predicate: attestation.VSAPredicate{
				Verifier: attestation.VSAVerifier{
					ID: result.Summary.Verifier,
				},
				TimeVerified:       time.Now().UTC().Format(time.RFC3339),
				ResourceUri:        resourceUri,
				Policy:             attestation.VSAPolicy{URI: result.Summary.PolicyURI},
				VerificationResult: outcomeStr,
				VerifiedLevels:     result.Summary.SLSALevels,
			},
		},
	}, nil
}

func VerifyAttestations(ctx context.Context, resolver oci.AttestationResolver, pctx *policy.Policy) (*VerificationResult, error) {
	digest, err := resolver.ImageDigest(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get image digest: %w", err)
	}
	name, err := resolver.ImageName(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get image name: %w", err)
	}
	purl, canonical, err := oci.RefToPURL(name, resolver.ImagePlatformStr())
	if err != nil {
		return nil, fmt.Errorf("failed to convert ref to purl: %w", err)
	}
	input := &policy.PolicyInput{
		Digest:      digest,
		Purl:        purl,
		IsCanonical: canonical,
	}

	evaluator, err := policy.GetPolicyEvaluator(ctx)
	if err != nil {
		return nil, err
	}
	result, err := evaluator.Evaluate(ctx, resolver, pctx, input)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}
	return ToPolicyResult(pctx, input, result)
}
