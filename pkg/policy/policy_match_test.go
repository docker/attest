package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/attest/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestFindPolicyMatch(t *testing.T) {
	testCases := []struct {
		name        string
		imageName   string
		mappingFile string

		expectError       bool
		expectedMatchType matchType
		expectedPolicyID  string
		expectedImageName string
	}{
		{
			name:        "alpine",
			mappingFile: "doi.yaml",
			imageName:   "docker.io/library/alpine",

			expectedMatchType: matchTypePolicy,
			expectedPolicyID:  "docker-official-images",
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:        "no match",
			mappingFile: "doi.yaml",
			imageName:   "docker.io/something/else",

			expectedMatchType: matchTypeNoMatch,
			expectedImageName: "docker.io/something/else",
		},
		{
			name:        "match, no policy",
			mappingFile: "local.yaml",
			imageName:   "docker.io/library/alpine",

			expectedMatchType: matchTypeMatchNoPolicy,
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:        "simple rewrite",
			mappingFile: "simple-rewrite.yaml",
			imageName:   "mycoolmirror.org/library/alpine",

			expectedMatchType: matchTypePolicy,
			expectedPolicyID:  "docker-official-images",
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:        "rewrite no match",
			mappingFile: "rewrite-to-no-match.yaml",
			imageName:   "mycoolmirror.org/library/alpine",

			expectedMatchType: matchTypeNoMatch,
			expectedImageName: "badredirect.org/alpine",
		},
		{
			name:        "rewrite to match, no policy",
			mappingFile: "rewrite-to-local.yaml",
			imageName:   "mycoolmirror.org/library/alpine",

			expectedMatchType: matchTypeMatchNoPolicy,
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:        "multiple rewrites",
			mappingFile: "rewrite-multiple.yaml",
			imageName:   "myevencoolermirror.org/library/alpine",

			expectedMatchType: matchTypePolicy,
			expectedPolicyID:  "docker-official-images",
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:        "invalid rewrites",
			mappingFile: "rewrite-invalid.yaml",
			imageName:   "mycoolmirror.org/library/alpine",

			expectError:       true,
			expectedMatchType: matchTypePolicy,
			expectedPolicyID:  "docker-official-images",
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:        "rewrite loop",
			mappingFile: "rewrite-loop.yaml",
			imageName:   "yin/alpine",

			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mappings := new(config.PolicyMappings)
			fileBytes, err := os.ReadFile(filepath.Join("testdata", "mappings", tc.mappingFile))
			require.NoError(t, err)
			err = yaml.Unmarshal(fileBytes, mappings)
			require.NoError(t, err)
			match, err := findPolicyMatch(tc.imageName, mappings)
			if tc.expectError {
				require.Error(t, err)
				// TODO: check error matches expected error message
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedMatchType, match.matchType)
			if match.matchType == matchTypePolicy {
				if assert.NotNil(t, match.policy) {
					assert.Equal(t, tc.expectedPolicyID, match.policy.Id)
				}
			}
			assert.Equal(t, tc.expectedImageName, match.imageName)

		})

	}
}
