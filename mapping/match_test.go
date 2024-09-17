package mapping

import (
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindPolicyMatch(t *testing.T) {
	defaultPlatform, err := v1.ParsePlatform("linux/amd64")
	require.NoError(t, err)
	testCases := []struct {
		name       string
		imageName  string
		mappingDir string

		expectError        bool
		expectLoadingError bool
		expectedMatchType  matchType
		expectedPolicyID   string
		expectedImageName  string
		platform           string
	}{
		{
			name:       "alpine",
			mappingDir: "doi",
			imageName:  "docker.io/library/alpine",

			expectedMatchType: MatchTypePolicy,
			expectedPolicyID:  "docker-official-images",
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:       "no match",
			mappingDir: "doi",
			imageName:  "docker.io/something/else",

			expectedMatchType: MatchTypeNoMatch,
			expectedImageName: "docker.io/something/else",
		},
		{
			name:       "match, no policy",
			mappingDir: "local",
			imageName:  "docker.io/library/alpine",

			expectedMatchType: MatchTypeMatchNoPolicy,
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:       "simple rewrite",
			mappingDir: "simple-rewrite",
			imageName:  "mycoolmirror.org/library/alpine",

			expectedMatchType: MatchTypePolicy,
			expectedPolicyID:  "docker-official-images",
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:       "rewrite no match",
			mappingDir: "rewrite-to-no-match",
			imageName:  "mycoolmirror.org/library/alpine",

			expectedMatchType: MatchTypeNoMatch,
			expectedImageName: "badredirect.org/alpine",
		},
		{
			name:       "rewrite to match, no policy",
			mappingDir: "rewrite-to-local",
			imageName:  "mycoolmirror.org/library/alpine",

			expectedMatchType: MatchTypeMatchNoPolicy,
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:       "multiple rewrites",
			mappingDir: "rewrite-multiple",
			imageName:  "myevencoolermirror.org/library/alpine",

			expectedMatchType: MatchTypePolicy,
			expectedPolicyID:  "docker-official-images",
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:       "rewrite loop",
			mappingDir: "rewrite-loop",
			imageName:  "yin/alpine",

			expectError: true,
		},
		{
			name:              "alpine with platform",
			mappingDir:        "doi",
			imageName:         "docker.io/library/alpine",
			platform:          "linux/amd64",
			expectedMatchType: MatchTypePolicy,
			expectedPolicyID:  "docker-official-images",
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:              "alpine with platform",
			mappingDir:        "doi-platform",
			imageName:         "docker.io/library/alpine",
			platform:          "linux/amd64",
			expectedMatchType: MatchTypePolicy,
			expectedPolicyID:  "docker-official-images",
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:              "alpine with no matching platform",
			mappingDir:        "doi-platform",
			imageName:         "docker.io/library/alpine",
			platform:          "linux/arm64",
			expectedMatchType: MatchTypeNoMatch,
			expectedPolicyID:  "docker-official-images",
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:              "alpine with platform",
			mappingDir:        "doi-platform",
			imageName:         "docker.io/library/alpine",
			platform:          "linux/amd64",
			expectedMatchType: MatchTypePolicy,
			expectedPolicyID:  "docker-official-images",
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:               "alpine with invalid platform in mapping",
			mappingDir:         "doi-platform-broken",
			imageName:          "docker.io/library/alpine",
			platform:           "linux/amd64",
			expectLoadingError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mappings, err := LoadLocalMappings(filepath.Join("testdata", "mappings", tc.mappingDir))
			if tc.expectLoadingError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			platform := defaultPlatform
			if tc.platform != "" {
				platform, err = v1.ParsePlatform(tc.platform)
				require.NoError(t, err)
			}
			match, err := mappings.FindPolicyMatch(tc.imageName, platform)
			if tc.expectError {
				require.Error(t, err)
				// TODO: check error matches expected error message
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedMatchType, match.MatchType)
			if match.MatchType == MatchTypePolicy {
				if assert.NotNil(t, match.Policy) {
					assert.Equal(t, tc.expectedPolicyID, match.Policy.ID)
				}
			}
			assert.Equal(t, tc.expectedImageName, match.MatchedName)
		})
	}
}
