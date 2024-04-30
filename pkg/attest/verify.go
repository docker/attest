package attest

import (
	"context"
	"fmt"

	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/policy"
)

func VerifyAttestations(ctx context.Context, resolver oci.AttestationResolver, files []*policy.PolicyFile) error {
	digest, err := resolver.ImageDigest(ctx)
	if err != nil {
		return fmt.Errorf("failed to get image digest: %w", err)
	}
	name, err := resolver.ImageName(ctx)
	if err != nil {
		return fmt.Errorf("failed to get image name: %w", err)
	}
	purl, canonical, err := oci.RefToPURL(name, resolver.ImagePlatformStr())
	if err != nil {
		return fmt.Errorf("failed to convert ref to purl: %w", err)
	}
	input := &policy.PolicyInput{
		Digest:      digest,
		Purl:        purl,
		IsCanonical: canonical,
	}

	evaluator, err := policy.GetPolicyEvaluator(ctx)
	if err != nil {
		return err
	}
	rs, err := evaluator.Evaluate(ctx, resolver, files, input)
	if err != nil {
		return fmt.Errorf("policy evaluation failed: %w", err)
	}
	if !rs.Allowed() {
		return fmt.Errorf("policy evaluation failed: %s", fmt.Sprint(rs))
	}

	return nil
}

func Verify(ctx context.Context, opts *policy.PolicyOptions, resolver oci.AttestationResolver) (policyFound bool, err error) {
	policyFiles, err := policy.ResolvePolicy(ctx, resolver, opts)
	if err != nil {
		return false, fmt.Errorf("failed to resolve policy: %w", err)
	}

	// no policy for image -> success
	if policyFiles == nil {
		return false, nil
	}

	// policy found -> verify
	return true, VerifyAttestations(ctx, resolver, policyFiles)
}
