package policy

import (
	"path/filepath"
	"testing"

	"github.com/docker/attest/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindPolicyMatch(t *testing.T) {
	testCases := []struct {
		name       string
		imageName  string
		mappingDir string

		expectError       bool
		expectedMatchType matchType
		expectedPolicyID  string
		expectedImageName string
	}{
		{
			name:       "alpine",
			mappingDir: "doi",
			imageName:  "docker.io/library/alpine",

			expectedMatchType: matchTypePolicy,
			expectedPolicyID:  "docker-official-images",
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:       "no match",
			mappingDir: "doi",
			imageName:  "docker.io/something/else",

			expectedMatchType: matchTypeNoMatch,
			expectedImageName: "docker.io/something/else",
		},
		{
			name:       "match, no policy",
			mappingDir: "local",
			imageName:  "docker.io/library/alpine",

			expectedMatchType: matchTypeMatchNoPolicy,
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:       "simple rewrite",
			mappingDir: "simple-rewrite",
			imageName:  "mycoolmirror.org/library/alpine",

			expectedMatchType: matchTypePolicy,
			expectedPolicyID:  "docker-official-images",
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:       "rewrite no match",
			mappingDir: "rewrite-to-no-match",
			imageName:  "mycoolmirror.org/library/alpine",

			expectedMatchType: matchTypeNoMatch,
			expectedImageName: "badredirect.org/alpine",
		},
		{
			name:       "rewrite to match, no policy",
			mappingDir: "rewrite-to-local",
			imageName:  "mycoolmirror.org/library/alpine",

			expectedMatchType: matchTypeMatchNoPolicy,
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:       "multiple rewrites",
			mappingDir: "rewrite-multiple",
			imageName:  "myevencoolermirror.org/library/alpine",

			expectedMatchType: matchTypePolicy,
			expectedPolicyID:  "docker-official-images",
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:       "invalid rewrites",
			mappingDir: "rewrite-invalid",
			imageName:  "mycoolmirror.org/library/alpine",

			expectError:       true,
			expectedMatchType: matchTypePolicy,
			expectedPolicyID:  "docker-official-images",
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:       "rewrite loop",
			mappingDir: "rewrite-loop",
			imageName:  "yin/alpine",

			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mappings, err := config.LoadLocalMappings(filepath.Join("testdata", "mappings", tc.mappingDir))
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
			assert.Equal(t, tc.expectedImageName, match.matchedName)
		})
	}
}
