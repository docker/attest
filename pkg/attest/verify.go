package attest

import (
	"context"
	"fmt"
	"time"

	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/policy"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/open-policy-agent/opa/rego"
)

func Verify(ctx context.Context, opts *policy.PolicyOptions, resolver oci.AttestationResolver) (result *PolicyResult, err error) {
	pctx, err := policy.ResolvePolicy(ctx, resolver, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve policy: %w", err)
	}

	// no policy for image -> success
	if pctx == nil {
		return &PolicyResult{
			Success: true,
		}, nil
	}
	result, err = VerifyAttestations(ctx, resolver, pctx)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}
	return result, nil
}

func ToPolicyResult(p *policy.Policy, input *policy.PolicyInput, rs rego.ResultSet) (*PolicyResult, error) {
	//TODO - extract all the VSA stuff from resultset instead of hard coding it
	dgst, err := oci.SplitDigest(input.Digest)
	if err != nil {
		return nil, fmt.Errorf("failed to split digest: %w", err)
	}
	// come from policy output (interection of all the subjects in the image's attestations)
	subject := intoto.Subject{
		Name:   input.Purl,
		Digest: *dgst,
	}
	// this is OK to come from attest library
	//TODO confirm our interpretation
	resourceUri, err := attestation.ToVSAResourceURI(subject)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource uri: %w", err)
	}

	if len(rs) == 0 {
		return nil, fmt.Errorf("no policy evaluation result")
	}
	binding, ok := rs[0].Bindings["x"]
	if !ok {
		return nil, fmt.Errorf("failed to extract verification result")
	}
	result, ok := binding.(policy.VerificationResult)
	if !ok {
		return nil, fmt.Errorf("failed to extract verification result")
	}

	successStr := "FAILED"
	if result.Success {
		successStr = "PASSED"
	}

	return &PolicyResult{
		Policy:     p,
		Success:    result.Success,
		Violations: result.Violations,
		Summary: &intoto.Statement{
			StatementHeader: intoto.StatementHeader{
				PredicateType: attestation.VSAPredicateType,
				Type:          intoto.StatementInTotoV01,
				Subject:       result.Summary.Subjects,
			},
			Predicate: attestation.VSAPredicate{
				Verifier: attestation.VSAVerifier{
					ID: result.Summary.Verifier,
				},
				TimeVerified: time.Now().UTC().Format(time.RFC3339),
				ResourceUri:  resourceUri,
				// this will be a git uri to the policy commit
				Policy:             attestation.VSAPolicy{URI: "http://docker.com/official/policy/v0.1"},
				VerificationResult: successStr,
				VerifiedLevels:     []string{result.Summary.SLSALevel},
			},
		},
	}, nil
}

func VerifyAttestations(ctx context.Context, resolver oci.AttestationResolver, pctx *policy.Policy) (*PolicyResult, error) {
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
	rs, err := evaluator.Evaluate(ctx, resolver, pctx, input)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}
	return ToPolicyResult(pctx, input, rs)
}
