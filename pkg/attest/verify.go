package attest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/config"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/policy"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

func Verify(ctx context.Context, src *oci.ImageSpec, opts *policy.PolicyOptions) (result *VerificationResult, err error) {
	// so that we can resolve mapping from the image name earlier
	detailsResolver, err := policy.CreateImageDetailsResolver(src)
	if err != nil {
		return nil, fmt.Errorf("failed to create image details resolver: %w", err)
	}
	if opts.AttestationStyle == "" {
		opts.AttestationStyle = config.AttestationStyleReferrers
	}
	if opts.ReferrersRepo != "" && opts.AttestationStyle != config.AttestationStyleReferrers {
		return nil, fmt.Errorf("referrers repo specified but attestation source not set to referrers")
	}
	pctx, err := policy.ResolvePolicy(ctx, detailsResolver, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve policy: %w", err)
	}

	if pctx == nil {
		return &VerificationResult{
			Outcome: OutcomeNoPolicy,
		}, nil
	}
	// this is overriding the mapping with a referrers config. Useful for testing if nothing else
	if opts.ReferrersRepo != "" {
		pctx.Mapping.Attestations = &config.AttestationConfig{
			Repo:  opts.ReferrersRepo,
			Style: config.AttestationStyleReferrers,
		}
	} else if opts.AttestationStyle == config.AttestationStyleAttached {
		pctx.Mapping.Attestations = &config.AttestationConfig{
			Repo:  opts.ReferrersRepo,
			Style: config.AttestationStyleAttached,
		}
	}
	// because we have a mapping now, we can select a resolver based on its contents (ie. referrers or attached)
	resolver, err := policy.CreateAttestationResolver(detailsResolver, pctx.Mapping)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation resolver: %w", err)
	}
	result, err = VerifyAttestations(ctx, resolver, pctx)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}
	return result, nil
}

func toVerificationResult(p *policy.Policy, input *policy.PolicyInput, result *policy.Result) (*VerificationResult, error) {
	dgst, err := oci.SplitDigest(input.Digest)
	if err != nil {
		return nil, fmt.Errorf("failed to split digest: %w", err)
	}
	subject := intoto.Subject{
		Name:   input.Purl,
		Digest: dgst,
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
		Input:      input,
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
	desc, err := resolver.ImageDescriptor(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get image descriptor: %w", err)
	}
	digest := desc.Digest.String()
	name, err := resolver.ImageName(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get image name: %w", err)
	}
	platform, err := resolver.ImagePlatform(ctx)
	if err != nil {
		return nil, err
	}

	if pctx.ResolvedName != "" {
		// this means the name we have is not the one we want to use for policy evaluation
		// so we need to replace it with the one we resolved during policy resolution.
		// this can happen if the name is an alias for another image, e.g. if it is a mirror
		ref, err := reference.ParseNormalizedNamed(name)
		if err != nil {
			return nil, fmt.Errorf("failed to parse image name: %w", err)
		}
		oldName := ref.Name()
		name = strings.Replace(name, oldName, pctx.ResolvedName, 1)
	}

	purl, canonical, err := oci.RefToPURL(name, platform)
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
	verificationResult, err := toVerificationResult(pctx, input, result)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to policy result: %w", err)
	}
	verificationResult.SubjectDescriptor = desc
	return verificationResult, nil
}

func NewAttestationManifest(subject *v1.Descriptor) (*attestation.AttestationManifest, error) {
	subjectDigest := subject.Digest.String()
	subject.Annotations = map[string]string{
		"vnd.docker.reference.digest": subjectDigest,
		"vnd.docker.reference.type":   "attestation-manifest"}

	return &attestation.AttestationManifest{
		OriginalDescriptor: &v1.Descriptor{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
		},
		OriginalLayers:    []*attestation.AttestationLayer{},
		SubjectDescriptor: subject,
	}, nil
}
