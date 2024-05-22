package policy

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/distribution/reference"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/tuf"
	intoto "github.com/in-toto/in-toto-golang/in_toto"

	goyaml "gopkg.in/yaml.v3"
)

const (
	PolicyMappingFileName = "mapping.yaml"
)

type Summary struct {
	Subjects   []intoto.Subject `json:"subjects"`
	SLSALevels []string         `json:"slsa_levels"`
	Verifier   string           `json:"verifier"`
	PolicyURI  string           `json:"policy_uri"`
}

type Violation struct {
	Type        string            `json:"type"`
	Description string            `json:"description"`
	Attestation *intoto.Statement `json:"attestation"`
	Details     map[string]any    `json:"details"`
}

type Result struct {
	Success    bool        `json:"success"`
	Violations []Violation `json:"violations"`
	Summary    Summary     `json:"summary"`
}

type PolicyMappings struct {
	Version  string          `json:"version"`
	Kind     string          `json:"kind"`
	Policies []PolicyMapping `json:"policies"`
	Mirrors  []PolicyMirror  `json:"mirrors"`
}

type PolicyMapping struct {
	Id          string              `json:"id"`
	Description string              `json:"description"`
	Origin      PolicyOrigin        `json:"origin"`
	Files       []PolicyMappingFile `json:"files"`
}

type PolicyMappingFile struct {
	Path string `json:"path"`
}

type PolicyMirror struct {
	PolicyId string     `yaml:"policy-id"`
	Mirror   MirrorSpec `json:"mirror"`
}

type MirrorSpec struct {
	Domains []string `json:"domains"`
	Prefix  string   `json:"prefix"`
}

type PolicyOrigin struct {
	Name   string `json:"name"`
	Prefix string `json:"prefix"`
	Domain string `json:"domain"`
}

type PolicyOptions struct {
	TufClient       tuf.TUFClient
	LocalTargetsDir string
	LocalPolicyDir  string
}

type Policy struct {
	InputFiles []*PolicyFile
	Query      string
}

type PolicyInput struct {
	Digest      string `json:"digest"`
	Purl        string `json:"purl"`
	IsCanonical bool   `json:"isCanonical"`
}

type PolicyFile struct {
	Path    string
	Content []byte
}

func resolveLocalPolicy(opts *PolicyOptions, mapping *PolicyMapping) (*Policy, error) {
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
	}
	return policy, nil
}

func LoadLocalMappings(opts *PolicyOptions) (*PolicyMappings, error) {
	if opts.LocalPolicyDir == "" {
		return nil, nil
	}
	mappings := &PolicyMappings{}
	path := path.Join(opts.LocalPolicyDir, PolicyMappingFileName)
	mappingFile, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy mapping file %s: %w", path, err)
	}
	err = goyaml.Unmarshal(mappingFile, mappings)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy mapping file %s: %w", path, err)
	}
	return mappings, nil
}

func resolveTufPolicy(opts *PolicyOptions, mapping *PolicyMapping) (*Policy, error) {
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
	}
	return policy, nil
}

func loadTufMappings(tufClient tuf.TUFClient, localTargetsDir string) (*PolicyMappings, error) {
	filename := PolicyMappingFileName
	_, fileContents, err := tufClient.DownloadTarget(filename, filepath.Join(localTargetsDir, filename))
	if err != nil {
		return nil, fmt.Errorf("failed to download policy file %s: %w", filename, err)
	}
	mappings := &PolicyMappings{}

	err = goyaml.Unmarshal(fileContents, mappings)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy mapping file %s: %w", filename, err)
	}
	return mappings, nil
}

func findPolicyMatch(named reference.Named, mappings *PolicyMappings) (*PolicyMapping, *PolicyMirror) {
	if mappings != nil {
		for _, mapping := range mappings.Policies {
			if mapping.Origin.Domain == reference.Domain(named) &&
				strings.HasPrefix(reference.Path(named), mapping.Origin.Prefix) {
				return &mapping, nil
			}
		}
		// now search mirrors
		for _, mirror := range mappings.Mirrors {
			if slices.Contains(mirror.Mirror.Domains, reference.Domain(named)) &&
				strings.HasPrefix(reference.Path(named), mirror.Mirror.Prefix) {
				for _, mapping := range mappings.Policies {
					if mapping.Id == mirror.PolicyId {
						return &mapping, nil
					}
				}
				return nil, &mirror
			}
		}
	}
	return nil, nil
}

func ResolvePolicy(ctx context.Context, resolver oci.AttestationResolver, opts *PolicyOptions) (*Policy, error) {
	imageName, err := resolver.ImageName(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get image name: %w", err)
	}
	named, err := reference.ParseNormalizedNamed(imageName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image name: %w", err)
	}
	localMappings, err := LoadLocalMappings(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to load local policy mappings: %w", err)
	}
	mapping, mirror := findPolicyMatch(named, localMappings)
	if mapping != nil {
		return resolveLocalPolicy(opts, mapping)
	}
	// must check tuf
	tufMappings, err := loadTufMappings(opts.TufClient, opts.LocalTargetsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load tuf policy mappings: %w", err)
	}

	// it's a mirror of a tuf policy
	if mirror != nil {
		for _, mapping := range tufMappings.Policies {
			if mapping.Id == mirror.PolicyId {
				return resolveTufPolicy(opts, &mapping)
			}
		}
	}

	// try to resolve a tuf policy directly
	mapping, _ = findPolicyMatch(named, tufMappings)
	if mapping == nil {
		return nil, nil
	}
	return resolveTufPolicy(opts, mapping)
}
