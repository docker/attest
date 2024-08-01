package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/docker/attest/pkg/tuf"
	"sigs.k8s.io/yaml"
)

const (
	MappingFilename = "mapping.yaml"
)

func LoadLocalMappings(configDir string) (*PolicyMappings, error) {
	if configDir == "" {
		return nil, nil
	}
	mappings := &policyMappingsFile{}
	path := filepath.Join(configDir, MappingFilename)
	mappingFile, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read local policy mapping file %s: %w", path, err)
	}
	err = yaml.Unmarshal(mappingFile, mappings)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy mapping file %s: %w", path, err)
	}
	return expandMappingFile(mappings)
}

func LoadTUFMappings(tufClient tuf.Downloader, localTargetsDir string) (*PolicyMappings, error) {
	if tufClient == nil {
		return nil, fmt.Errorf("tuf client not set")
	}
	filename := MappingFilename
	_, fileContents, err := tufClient.DownloadTarget(filename, filepath.Join(localTargetsDir, filename))
	if err != nil {
		return nil, fmt.Errorf("failed to download policy mapping file %s: %w", filename, err)
	}
	mappings := &policyMappingsFile{}

	err = yaml.Unmarshal(fileContents, mappings)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy mapping file %s: %w", filename, err)
	}
	return expandMappingFile(mappings)
}

func expandMappingFile(mappingFile *policyMappingsFile) (*PolicyMappings, error) {
	policies := make(map[string]*PolicyMapping)
	for _, policy := range mappingFile.Policies {
		policies[policy.ID] = policy
	}

	var rules []*PolicyRule
	for _, rule := range mappingFile.Rules {
		r, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, err
		}
		rules = append(rules, &PolicyRule{
			Pattern:     r,
			PolicyID:    rule.PolicyID,
			Replacement: rule.Replacement,
		})
	}

	return &PolicyMappings{
		Version:  mappingFile.Version,
		Kind:     mappingFile.Kind,
		Policies: policies,
		Rules:    rules,
	}, nil
}
