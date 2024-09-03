package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func newMapping() *policyMappingsFile {
	return &policyMappingsFile{
		Version: "v1",
		Kind:    "policy-mapping",
		Policies: []*PolicyMapping{
			{
				ID: "docker-official-images",
				Files: []PolicyMappingFile{
					{
						Path: "docker.io/library/alpine",
					},
				},
			},
		},
		Rules: []*policyRuleFile{
			{
				Pattern:  "docker.io/library/alpine",
				PolicyID: "docker-official-images",
			},
		},
	}
}

func TestMappingsFileValidation(t *testing.T) {
	mappings := newMapping()
	err := validateMappingsFile(mappings)
	require.NoError(t, err)

	mappings = newMapping()
	mappings.Kind = "not-policy-mapping"
	err = validateMappingsFile(mappings)
	require.ErrorContains(t, err, "file is not of kind policy-mapping: not-policy-mapping")

	mappings = newMapping()
	mappings.Version = "v2"
	err = validateMappingsFile(mappings)
	require.ErrorContains(t, err, "unsupported policy mapping file version: v2")

	mappings = newMapping()
	mappings.Rules[0].Pattern = ""
	err = validateMappingsFile(mappings)
	require.ErrorContains(t, err, "rule missing pattern")

	mappings = newMapping()
	mappings.Rules[0].PolicyID = ""
	err = validateMappingsFile(mappings)
	require.ErrorContains(t, err, "rule must have policy-id or replacement")

	mappings = newMapping()
	mappings.Rules[0].PolicyID = "docker-official-images"
	mappings.Rules[0].Replacement = "docker.io/library/alpine"
	err = validateMappingsFile(mappings)
	require.ErrorContains(t, err, "rule cannot have both policy-id and replacement")

	mappings = newMapping()
	mappings.Policies[0].ID = ""
	err = validateMappingsFile(mappings)
	require.ErrorContains(t, err, "policy missing id")

	mappings = newMapping()
	mappings.Policies[0].Files = nil
	err = validateMappingsFile(mappings)
	require.ErrorContains(t, err, "policy missing files")

	mappings = newMapping()
	mappings.Policies[0].Files[0].Path = ""
	err = validateMappingsFile(mappings)
	require.ErrorContains(t, err, "file missing path")

	// multiple errors
	mappings.Policies[0].ID = ""
	err = validateMappingsFile(mappings)
	require.ErrorContains(t, err, "policy missing id: \nfile missing path: {}")
}
