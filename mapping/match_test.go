/*
   Copyright Docker attest authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

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
		name               string
		imageName          string
		mappingDir         string
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
		{
			name:              "firefox with > 1 platforms in policy",
			mappingDir:        "doi-platform",
			imageName:         "docker.io/mozilla/firefox",
			platform:          "linux/arm64",
			expectedMatchType: MatchTypePolicy,
			expectedPolicyID:  "docker-official-images",
			expectedImageName: "docker.io/mozilla/firefox",
		},
		{
			name:              "firefox with > 1 platforms in policy (no match)",
			mappingDir:        "doi-platform",
			imageName:         "docker.io/mozilla/firefox",
			platform:          "macOs/arm64",
			expectedMatchType: MatchTypeNoMatch,
			expectedPolicyID:  "docker-official-images",
		},
		{
			name:              "rewrite and platform",
			mappingDir:        "doi-platform",
			imageName:         "mycoolmirror.org/library/alpine",
			platform:          "linux/amd64",
			expectedMatchType: MatchTypePolicy,
			expectedPolicyID:  "docker-official-images",
			expectedImageName: "docker.io/library/alpine",
		},
		{
			name:              "rewrite and platform mismatch",
			mappingDir:        "doi-platform",
			imageName:         "mycoolmirror.org/library/alpine",
			platform:          "macOs/amd64",
			expectedMatchType: MatchTypeNoMatch,
			expectedPolicyID:  "docker-official-images",
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
			if match.MatchType == MatchTypeMatchNoPolicy || match.MatchType == MatchTypePolicy {
				assert.Equal(t, tc.expectedImageName, match.MatchedName)
			}
		})
	}
}
