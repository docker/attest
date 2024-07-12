package policy

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/distribution/reference"
	"github.com/docker/attest/pkg/config"
	"github.com/docker/attest/pkg/oci"
)

func resolveLocalPolicy(opts *PolicyOptions, mapping *config.PolicyMapping, imageName string, matchedName string) (*Policy, error) {
	if opts.LocalPolicyDir == "" {
		return nil, fmt.Errorf("local policy dir not set")
	}
	files := make([]*PolicyFile, 0, len(mapping.Files))
	for _, f := range mapping.Files {
		filename := f.Path
		filePath := path.Join(opts.LocalPolicyDir, filename)
		fileContents, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read policy file %s: %w", filename, err)
		}
		files = append(files, &PolicyFile{
			Path:    filename,
			Content: fileContents,
		})
	}
	policy := &Policy{
		InputFiles: files,
		Mapping:    mapping,
	}
	if imageName != matchedName {
		policy.ResolvedName = matchedName
	}
	return policy, nil
}

func resolveTufPolicy(opts *PolicyOptions, mapping *config.PolicyMapping, imageName string, matchedName string) (*Policy, error) {
	files := make([]*PolicyFile, 0, len(mapping.Files))
	for _, f := range mapping.Files {
		filename := f.Path
		_, fileContents, err := opts.TufClient.DownloadTarget(filename, filepath.Join(opts.LocalTargetsDir, filename))
		if err != nil {
			return nil, fmt.Errorf("failed to download policy file %s: %w", filename, err)
		}
		files = append(files, &PolicyFile{
			Path:    filename,
			Content: fileContents,
		})
	}
	policy := &Policy{
		InputFiles: files,
		Mapping:    mapping,
	}
	if imageName != matchedName {
		policy.ResolvedName = matchedName
	}
	return policy, nil
}

type matchType string

const (
	matchTypePolicy        matchType = "policy"
	matchTypeMatchNoPolicy matchType = "match_no_policy"
	matchTypeNoMatch       matchType = "no_match"
)

type policyMatch struct {
	matchType   matchType
	policy      *config.PolicyMapping
	rule        *config.PolicyRule
	matchedName string
}

func findPolicyMatch(imageName string, mappings *config.PolicyMappings) (*policyMatch, error) {
	if mappings == nil {
		return &policyMatch{matchType: matchTypeNoMatch, matchedName: imageName}, nil
	}
	return findPolicyMatchImpl(imageName, mappings, make(map[*config.PolicyRule]bool))
}

func findPolicyMatchImpl(imageName string, mappings *config.PolicyMappings, matched map[*config.PolicyRule]bool) (*policyMatch, error) {
	for _, rule := range mappings.Rules {
		if rule.Pattern.MatchString(imageName) {
			switch {
			case rule.PolicyId == "" && rule.Rewrite == "":
				return nil, fmt.Errorf("rule %s has neither policy-id nor rewrite", rule.Pattern)
			case rule.PolicyId != "" && rule.Rewrite != "":
				return nil, fmt.Errorf("rule %s has both policy-id and rewrite", rule.Pattern)
			case rule.PolicyId != "":
				policy := mappings.Policies[rule.PolicyId]
				if policy != nil {
					return &policyMatch{
						matchType:   matchTypePolicy,
						policy:      policy,
						rule:        rule,
						matchedName: imageName,
					}, nil
				}
				return &policyMatch{
					matchType:   matchTypeMatchNoPolicy,
					rule:        rule,
					matchedName: imageName,
				}, nil
			case rule.Rewrite != "":
				if matched[rule] {
					return nil, fmt.Errorf("rewrite loop detected")
				}
				matched[rule] = true
				imageName = rule.Pattern.ReplaceAllString(imageName, rule.Rewrite)
				return findPolicyMatchImpl(imageName, mappings, matched)
			}
		}
	}
	return &policyMatch{matchType: matchTypeNoMatch, matchedName: imageName}, nil
}

func resolvePolicyById(opts *PolicyOptions) (*Policy, error) {
	if opts.PolicyId != "" {
		localMappings, err := config.LoadLocalMappings(opts.LocalPolicyDir)
		if err != nil {
			return nil, fmt.Errorf("failed to load local policy mappings: %w", err)
		}
		if localMappings != nil {
			policy := localMappings.Policies[opts.PolicyId]
			if policy != nil {
				return resolveLocalPolicy(opts, policy, "", "")
			}
		}

		// must check tuf
		tufMappings, err := config.LoadTufMappings(opts.TufClient, opts.LocalTargetsDir)
		if err != nil {
			return nil, fmt.Errorf("failed to load tuf policy mappings by id: %w", err)
		}
		policy := tufMappings.Policies[opts.PolicyId]
		if policy != nil {
			return resolveTufPolicy(opts, policy, "", "")
		}
		return nil, fmt.Errorf("policy with id %s not found", opts.PolicyId)
	}
	return nil, nil
}

func ResolvePolicy(ctx context.Context, detailsResolver oci.ImageDetailsResolver, opts *PolicyOptions) (*Policy, error) {
	p, err := resolvePolicyById(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve policy by id: %w", err)
	}
	if p != nil {
		return p, nil
	}
	imageName, err := detailsResolver.ImageName(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get image name: %w", err)
	}
	imageName, err = normalizeImageName(imageName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image name: %w", err)
	}
	localMappings, err := config.LoadLocalMappings(opts.LocalPolicyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load local policy mappings: %w", err)
	}
	match, err := findPolicyMatch(imageName, localMappings)
	if err != nil {
		return nil, err
	}
	if match.matchType == matchTypePolicy {
		return resolveLocalPolicy(opts, match.policy, imageName, match.matchedName)
	}
	// must check tuf
	tufMappings, err := config.LoadTufMappings(opts.TufClient, opts.LocalTargetsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load tuf policy mappings as fallback: %w", err)
	}

	// it's a mirror of a tuf policy
	if match.matchType == matchTypeMatchNoPolicy {
		for _, mapping := range tufMappings.Policies {
			if mapping.Id == match.rule.PolicyId {
				return resolveTufPolicy(opts, mapping, imageName, match.matchedName)
			}
		}
	}

	// try to resolve a tuf policy directly
	match, err = findPolicyMatch(imageName, tufMappings)
	if err != nil {
		return nil, err
	}
	if match.matchType == matchTypePolicy {
		return resolveTufPolicy(opts, match.policy, imageName, match.matchedName)
	}
	return nil, nil
}

func normalizeImageName(imageName string) (string, error) {
	named, err := reference.ParseNormalizedNamed(imageName)
	if err != nil {
		return "", fmt.Errorf("failed to parse image name: %w", err)
	}
	return named.Name(), nil
}

func CreateImageDetailsResolver(imageSource *oci.ImageSpec) (oci.ImageDetailsResolver, error) {
	switch imageSource.Type {
	case oci.OCI:
		return oci.NewOCILayoutAttestationResolver(imageSource)
	case oci.Docker:
		return oci.NewRegistryImageDetailsResolver(imageSource)
	}
	return nil, fmt.Errorf("unsupported image source type: %s", imageSource.Type)
}

func CreateAttestationResolver(resolver oci.ImageDetailsResolver, mapping *config.PolicyMapping) (oci.AttestationResolver, error) {
	switch resolver := resolver.(type) {
	case *oci.RegistryImageDetailsResolver:
		if mapping.Attestations != nil && mapping.Attestations.Style == config.AttestationStyleAttached {
			return oci.NewRegistryAttestationResolver(resolver)
		} else {
			if mapping.Attestations != nil && mapping.Attestations.Repo != "" {
				return oci.NewReferrersAttestationResolver(resolver, oci.WithReferrersRepo(mapping.Attestations.Repo))
			} else {
				return oci.NewReferrersAttestationResolver(resolver)
			}
		}
	case *oci.OCILayoutResolver:
		return resolver, nil
	default:
		return nil, fmt.Errorf("unsupported image details resolver type: %T", resolver)
	}
}
