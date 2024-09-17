package policy

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/distribution/reference"
	"github.com/docker/attest/internal/util"
	"github.com/docker/attest/mapping"
	"github.com/docker/attest/tuf"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type Resolver struct {
	tufClient tuf.Downloader
	opts      *Options
}

func NewResolver(tufClient tuf.Downloader, opts *Options) *Resolver {
	return &Resolver{
		tufClient: tufClient,
		opts:      opts,
	}
}

func (r *Resolver) ResolvePolicy(_ context.Context, imageName string, platform *v1.Platform) (*Policy, error) {
	p, err := r.resolvePolicyByID()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve policy by id: %w", err)
	}
	if p != nil {
		return p, nil
	}
	imageName, err = normalizeImageName(imageName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image name: %w", err)
	}
	localMappings, err := mapping.LoadLocalMappings(r.opts.LocalPolicyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load local policy mappings: %w", err)
	}
	match, err := localMappings.FindPolicyMatch(imageName, platform)
	if err != nil {
		return nil, err
	}
	if match.MatchType == mapping.MatchTypePolicy {
		return r.resolveLocalPolicy(match.Policy, imageName, match.MatchedName)
	}
	if !r.opts.DisableTUF {
		tufMappings, err := mapping.LoadTUFMappings(r.tufClient, r.opts.LocalTargetsDir)
		if err != nil {
			return nil, fmt.Errorf("failed to load tuf policy mappings as fallback: %w", err)
		}

		// it's a mirror of a tuf policy
		if match.MatchType == mapping.MatchTypeMatchNoPolicy {
			for _, mapping := range tufMappings.Policies {
				if mapping.ID == match.Rule.PolicyID {
					return r.resolveTUFPolicy(mapping, imageName, match.MatchedName)
				}
			}
		}

		// try to resolve a tuf policy directly
		match, err = tufMappings.FindPolicyMatch(imageName, platform)
		if err != nil {
			return nil, err
		}
		if match.MatchType == mapping.MatchTypePolicy {
			return r.resolveTUFPolicy(match.Policy, imageName, match.MatchedName)
		}
	}
	return nil, nil
}

func (r *Resolver) resolveLocalPolicy(mapping *mapping.PolicyMapping, imageName string, matchedName string) (*Policy, error) {
	if r.opts.LocalPolicyDir == "" {
		return nil, fmt.Errorf("local policy dir not set")
	}
	var URI string
	var digest map[string]string
	files := make([]*File, 0, len(mapping.Files))
	for _, f := range mapping.Files {
		filename := f.Path
		filePath := path.Join(r.opts.LocalPolicyDir, filename)
		fileContents, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read policy file %s: %w", filename, err)
		}
		files = append(files, &File{
			Path:    filename,
			Content: fileContents,
		})
		// if the file is a policy file, store the URI and digest
		if filepath.Ext(filename) == ".rego" {
			// TODO: support multiple rego files, need some way to identify the main policy file
			if URI != "" {
				return nil, fmt.Errorf("multiple policy files found in policy mapping")
			}
			URI = filePath
			digest = map[string]string{"sha256": util.SHA256Hex(fileContents)}
		}
	}
	if URI == "" {
		return nil, fmt.Errorf("no policy file found in policy mapping")
	}
	policy := &Policy{
		InputFiles: files,
		Mapping:    mapping,
		URI:        URI,
		Digest:     digest,
	}
	if imageName != matchedName {
		policy.ResolvedName = matchedName
	}
	return policy, nil
}

func (r *Resolver) resolveTUFPolicy(mapping *mapping.PolicyMapping, imageName string, matchedName string) (*Policy, error) {
	var URI string
	var digest map[string]string
	files := make([]*File, 0, len(mapping.Files))
	for _, f := range mapping.Files {
		filename := f.Path
		file, err := r.tufClient.DownloadTarget(filename, filepath.Join(r.opts.LocalTargetsDir, filename))
		if err != nil {
			return nil, fmt.Errorf("failed to download policy file %s: %w", filename, err)
		}
		files = append(files, &File{
			Path:    filename,
			Content: file.Data,
		})
		// if the file is a policy file, store the URI and digest
		if filepath.Ext(filename) == ".rego" {
			// TODO: support multiple rego files, need some way to identify the main policy file
			if URI != "" {
				return nil, fmt.Errorf("multiple policy files found in policy mapping")
			}
			URI = file.TargetURI
			digest = map[string]string{"sha256": file.Digest}
		}
	}
	if URI == "" {
		return nil, fmt.Errorf("no policy file found in policy mapping")
	}
	policy := &Policy{
		InputFiles: files,
		Mapping:    mapping,
		URI:        URI,
		Digest:     digest,
	}
	if imageName != matchedName {
		policy.ResolvedName = matchedName
	}
	return policy, nil
}

func (r *Resolver) resolvePolicyByID() (*Policy, error) {
	if r.opts.PolicyID != "" {
		localMappings, err := mapping.LoadLocalMappings(r.opts.LocalPolicyDir)
		if err != nil {
			return nil, fmt.Errorf("failed to load local policy mappings: %w", err)
		}
		if localMappings != nil {
			policy := localMappings.Policies[r.opts.PolicyID]
			if policy != nil {
				return r.resolveLocalPolicy(policy, "", "")
			}
		}

		if !r.opts.DisableTUF {
			tufMappings, err := mapping.LoadTUFMappings(r.tufClient, r.opts.LocalTargetsDir)
			if err != nil {
				return nil, fmt.Errorf("failed to load tuf policy mappings by id: %w", err)
			}
			policy := tufMappings.Policies[r.opts.PolicyID]
			if policy != nil {
				return r.resolveTUFPolicy(policy, "", "")
			}
		}
		return nil, fmt.Errorf("policy with id %s not found", r.opts.PolicyID)
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
