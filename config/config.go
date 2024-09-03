package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/docker/attest/tuf"
	"sigs.k8s.io/yaml"
)

const (
	MappingFilename = "mapping.yaml"
)

func validateMappingsFile(mappings *policyMappingsFile) error {
	var validationErrors []error
	if mappings.Kind != "policy-mapping" {
		validationErrors = append(validationErrors, fmt.Errorf("file is not of kind policy-mapping: %s", mappings.Kind))
	}
	if mappings.Version != "v1" {
		validationErrors = append(validationErrors, fmt.Errorf("unsupported policy mapping file version: %s", mappings.Version))
	}
	for _, rule := range mappings.Rules {
		if rule.Pattern == "" {
			validationErrors = append(validationErrors, fmt.Errorf("rule missing pattern: %s", rule))
		}
		if rule.PolicyID == "" && rule.Replacement == "" {
			validationErrors = append(validationErrors, fmt.Errorf("rule must have policy-id or replacement: %s", rule))
		}
		if rule.PolicyID != "" && rule.Replacement != "" {
			validationErrors = append(validationErrors, fmt.Errorf("rule cannot have both policy-id and replacement: %s", rule))
		}
	}
	for _, policy := range mappings.Policies {
		if policy.ID == "" {
			validationErrors = append(validationErrors, fmt.Errorf("policy missing id: %s", policy.ID))
		}
		if len(policy.Files) == 0 {
			validationErrors = append(validationErrors, fmt.Errorf("policy missing files: %v", policy))
		}
		for _, file := range policy.Files {
			if file.Path == "" {
				validationErrors = append(validationErrors, fmt.Errorf("file missing path: %s", file))
			}
		}
	}

	if len(validationErrors) > 0 {
		return errors.Join(validationErrors...)
	}

	return nil
}

func parsePolicyMappingsFile(data []byte) (*PolicyMappings, error) {
	mappings := &policyMappingsFile{}
	err := yaml.Unmarshal(data, mappings)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy mapping file: %w", err)
	}
	err = validateMappingsFile(mappings)
	if err != nil {
		return nil, fmt.Errorf("invalid policy mapping file: %w", err)
	}
	return expandMappingFile(mappings)
}

func LoadLocalMappings(configDir string) (*PolicyMappings, error) {
	if configDir == "" {
		return nil, nil
	}
	path := filepath.Join(configDir, MappingFilename)
	mappingFile, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read local policy mapping file %s: %w", path, err)
	}
	return parsePolicyMappingsFile(mappingFile)
}

func LoadTUFMappings(tufClient tuf.Downloader, localTargetsDir string) (*PolicyMappings, error) {
	if tufClient == nil {
		return nil, fmt.Errorf("tuf client not set")
	}
	filename := MappingFilename
	file, err := tufClient.DownloadTarget(filename, filepath.Join(localTargetsDir, filename))
	if err != nil {
		return nil, fmt.Errorf("failed to download policy mapping file %s: %w", filename, err)
	}
	return parsePolicyMappingsFile(file.Data)
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
