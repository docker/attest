package attest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/docker/attest/attestation"
	"github.com/docker/attest/config"
	"github.com/docker/attest/oci"
	"github.com/docker/attest/policy"
	"github.com/docker/attest/tuf"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

type Verifier interface {
	Verify(ctx context.Context, src *oci.ImageSpec) (result *VerificationResult, err error)
}

type tufVerifier struct {
	opts      *policy.Options
	tufClient tuf.Downloader
}

func NewVerifier(opts *policy.Options) (Verifier, error) {
	err := populateDefaultOptions(opts)
	if err != nil {
		return nil, err
	}
	var tufClient tuf.Downloader
	if !opts.DisableTUF {
		tufClient, err = tuf.NewClient(opts.TUFClientOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to create TUF client: %w", err)
		}
	}
	return &tufVerifier{
		opts:      opts,
		tufClient: tufClient,
	}, nil
}

func (verifier *tufVerifier) Verify(ctx context.Context, src *oci.ImageSpec) (result *VerificationResult, err error) {
	// so that we can resolve mapping from the image name earlier
	detailsResolver, err := policy.CreateImageDetailsResolver(src)
	if err != nil {
		return nil, fmt.Errorf("failed to create image details resolver: %w", err)
	}
	imageName, err := detailsResolver.ImageName(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve image name: %w", err)
	}
	policyResolver := policy.NewResolver(verifier.tufClient, verifier.opts)
	resolvedPolicy, err := policyResolver.ResolvePolicy(ctx, imageName)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve policy: %w", err)
	}

	if resolvedPolicy == nil {
		return &VerificationResult{
			Outcome: OutcomeNoPolicy,
		}, nil
	}
	// this is overriding the mapping with a referrers config. Useful for testing if nothing else
	if verifier.opts.ReferrersRepo != "" {
		resolvedPolicy.Mapping.Attestations = &config.AttestationConfig{
			Repo:  verifier.opts.ReferrersRepo,
			Style: config.AttestationStyleReferrers,
		}
	} else if verifier.opts.AttestationStyle == config.AttestationStyleAttached {
		resolvedPolicy.Mapping.Attestations = &config.AttestationConfig{
			Repo:  verifier.opts.ReferrersRepo,
			Style: config.AttestationStyleAttached,
		}
	}
	// because we have a mapping now, we can select a resolver based on its contents (ie. referrers or attached)
	resolver, err := policy.CreateAttestationResolver(detailsResolver, resolvedPolicy.Mapping)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation resolver: %w", err)
	}
	evaluator := policy.NewRegoEvaluator(verifier.opts.Debug)
	result, err = VerifyAttestations(ctx, resolver, evaluator, resolvedPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}
	return result, nil
}

func Verify(ctx context.Context, src *oci.ImageSpec, opts *policy.Options) (result *VerificationResult, err error) {
	verifier, err := NewVerifier(opts)
	if err != nil {
		return nil, err
	}
	return verifier.Verify(ctx, src)
}

func populateDefaultOptions(opts *policy.Options) (err error) {
	if opts.LocalPolicyDir == "" && opts.DisableTUF {
		return fmt.Errorf("local policy dir must be set if not using TUF")
	}
	if opts.LocalTargetsDir == "" {
		opts.LocalTargetsDir, err = defaultLocalTargetsDir()
		if err != nil {
			return err
		}
	}
	if opts.DisableTUF && opts.TUFClientOptions != nil {
		return fmt.Errorf("TUF client options set but TUF disabled")
	} else if opts.TUFClientOptions == nil && !opts.DisableTUF {
		opts.TUFClientOptions = tuf.NewDockerDefaultClientOptions(opts.LocalTargetsDir)
	}

	if opts.AttestationStyle == "" {
		opts.AttestationStyle = config.AttestationStyleReferrers
	}
	if opts.ReferrersRepo != "" && opts.AttestationStyle != config.AttestationStyleReferrers {
		return fmt.Errorf("referrers repo specified but attestation source not set to referrers")
	}
	return nil
}

func defaultLocalTargetsDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}
	return filepath.Join(homeDir, ".docker", "tuf"), nil
}

func toVerificationResult(p *policy.Policy, input *policy.Input, result *policy.Result) (*VerificationResult, error) {
	dgst, err := oci.SplitDigest(input.Digest)
	if err != nil {
		return nil, fmt.Errorf("failed to split digest: %w", err)
	}
	subject := intoto.Subject{
		Name:   input.PURL,
		Digest: dgst,
	}
	resourceURI, err := attestation.ToVSAResourceURI(subject)
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

	vsaPolicy := attestation.VSAPolicy{URI: result.Summary.PolicyURI, DownloadLocation: p.URI, Digest: p.Digest}

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
				ResourceURI:        resourceURI,
				Policy:             vsaPolicy,
				VerificationResult: outcomeStr,
				VerifiedLevels:     result.Summary.SLSALevels,
			},
		},
	}, nil
}

func VerifyAttestations(ctx context.Context, resolver attestation.Resolver, evaluator policy.Evaluator, resolvedPolicy *policy.Policy) (*VerificationResult, error) {
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

	if resolvedPolicy.ResolvedName != "" {
		// this means the name we have is not the one we want to use for policy evaluation
		// so we need to replace it with the one we resolved during policy resolution.
		// this can happen if the name is an alias for another image, e.g. if it is a mirror
		ref, err := reference.ParseNormalizedNamed(name)
		if err != nil {
			return nil, fmt.Errorf("failed to parse image name: %w", err)
		}
		oldName := ref.Name()
		name = strings.Replace(name, oldName, resolvedPolicy.ResolvedName, 1)
	}

	ref, err := reference.ParseNormalizedNamed(name)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ref %q: %w", ref, err)
	}
	purl, canonical, err := oci.RefToPURL(ref, platform)
	if err != nil {
		return nil, fmt.Errorf("failed to convert ref to purl: %w", err)
	}
	var tag string
	if !canonical {
		// unlike the function name indicates, this adds latest if no tag is present
		ref = reference.TagNameOnly(ref)
	}

	if tagged, ok := ref.(reference.Tagged); ok {
		tag = tagged.Tag()
	}
	input := &policy.Input{
		Digest:         digest,
		PURL:           purl,
		Platform:       platform.String(),
		Domain:         reference.Domain(ref),
		NormalizedName: reference.Path(ref),
		FamiliarName:   reference.FamiliarName(ref),
	}
	// rego has null strings
	if tag != "" {
		input.Tag = tag
	}
	result, err := evaluator.Evaluate(ctx, resolver, resolvedPolicy, input)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}
	verificationResult, err := toVerificationResult(resolvedPolicy, input, result)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to policy result: %w", err)
	}
	verificationResult.SubjectDescriptor = desc
	return verificationResult, nil
}