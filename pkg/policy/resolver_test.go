package policy_test

import (
	"context"
	"testing"

	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/pkg/policy"
	"github.com/docker/attest/pkg/tuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolvePolicy(t *testing.T) {
	localPolicyPath := "testdata/policies/allow"
	tufPolicyPath := "testdata/policies/allow-canonical"
	noLocalPolicyPath := "testdata/policies/no-policy"
	testPolicyID := "docker-official-images"
	testImageName := "localhost:5001/test/repo:tag"

	testCases := []struct {
		name              string
		policyPath        string
		policyID          string
		localOverridesTUF bool // if a policy is provided locally, it should override TUF
		DisableTUF        bool
	}{
		{name: "resolve by id (TUF only)", policyID: testPolicyID, DisableTUF: false},
		{name: "resolve by id (local mapping, TUF policy)", policyPath: noLocalPolicyPath, policyID: testPolicyID, DisableTUF: false},
		{name: "resolve by id (local mapping, local policy, no TUF)", policyPath: localPolicyPath, policyID: testPolicyID, DisableTUF: true},
		{name: "resolve by id (local mapping, local policy)", policyPath: localPolicyPath, policyID: testPolicyID, DisableTUF: false, localOverridesTUF: true},
		{name: "resolve by match (TUF only)", DisableTUF: false},
		{name: "resolve by match (local mapping, TUF policy)", policyPath: noLocalPolicyPath, DisableTUF: false},
		{name: "resolve by match (local mapping, local policy, no TUF)", policyPath: localPolicyPath, DisableTUF: true},
		{name: "resolve by match (local mapping, local policy)", policyPath: localPolicyPath, DisableTUF: false, localOverridesTUF: true},
	}

	var tufClient tuf.Downloader
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := &policy.Options{}
			tempDir := test.CreateTempDir(t, "", "tuf-dest")
			if !tc.DisableTUF {
				tufClient = tuf.NewMockTufClient(tufPolicyPath)
			}
			if tc.policyID != "" {
				opts.PolicyID = tc.policyID
			}
			if tc.policyPath != "" {
				opts.LocalPolicyDir = tc.policyPath
			}
			opts.DisableTUF = tc.DisableTUF
			opts.LocalTargetsDir = tempDir
			resolver := policy.NewResolver(tufClient, opts)
			policy, err := resolver.ResolvePolicy(context.Background(), testImageName)
			require.NoError(t, err)
			assert.NotNil(t, policy)
			if tc.DisableTUF || tc.localOverridesTUF {
				assert.Contains(t, policy.URI, localPolicyPath)
			} else {
				assert.Contains(t, policy.URI, tufPolicyPath)
			}
		})
	}
}
