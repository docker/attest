package policy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/config"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/policy"
	"github.com/docker/attest/pkg/tuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadAttestation(t *testing.T, path string) *attestation.Envelope {
	ex, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var env = new(attestation.Envelope)
	err = json.Unmarshal(ex, env)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestRegoEvaluator_Evaluate(t *testing.T) {
	ctx, _ := test.Setup(t)
	errorStr := "failed to resolve policy by id: policy with id non-existent-policy-id not found"
	TestDataPath := filepath.Join("..", "..", "test", "testdata")
	ExampleAttestation := filepath.Join(TestDataPath, "example_attestation.json")

	re := policy.NewRegoEvaluator(true)

	defaultResolver := test.MockResolver{
		Envs: []*attestation.Envelope{loadAttestation(t, ExampleAttestation)},
	}

	testCases := []struct {
		repo          string
		expectSuccess bool
		isCanonical   bool
		resolver      oci.AttestationResolver
		policy        *policy.PolicyOptions
		policyId      string
		errorStr      string
	}{
		{repo: "testdata/mock-tuf-allow", expectSuccess: true, isCanonical: false, resolver: defaultResolver},
		{repo: "testdata/mock-tuf-allow", expectSuccess: true, isCanonical: false, resolver: defaultResolver, policyId: "docker-official-images"},
		{repo: "testdata/mock-tuf-allow", expectSuccess: false, isCanonical: false, resolver: defaultResolver, policyId: "non-existent-policy-id", errorStr: errorStr},
		{repo: "testdata/mock-tuf-deny", expectSuccess: false, isCanonical: false, resolver: defaultResolver},
		{repo: "testdata/mock-tuf-verify-sig", expectSuccess: true, isCanonical: false, resolver: defaultResolver},
		{repo: "testdata/mock-tuf-wrong-key", expectSuccess: false, isCanonical: false, resolver: defaultResolver},
		{repo: "testdata/mock-tuf-allow-canonical", expectSuccess: true, isCanonical: true, resolver: defaultResolver},
		{repo: "testdata/mock-tuf-allow-canonical", expectSuccess: false, isCanonical: false, resolver: defaultResolver},
	}

	for _, tc := range testCases {
		t.Run(tc.repo, func(t *testing.T) {
			input := &policy.PolicyInput{
				Digest:      "sha256:test-digest",
				Purl:        "test-purl",
				IsCanonical: tc.isCanonical,
			}

			tufClient := tuf.NewMockTufClient(tc.repo, test.CreateTempDir(t, "", "tuf-dest"))
			if tc.policy == nil {
				tc.policy = &policy.PolicyOptions{
					TufClient:       tufClient,
					LocalTargetsDir: test.CreateTempDir(t, "", "tuf-targets"),
					PolicyId:        tc.policyId,
				}
			}
			imageName, err := tc.resolver.ImageName(ctx)
			require.NoError(t, err)
			platform, err := tc.resolver.ImagePlatform(ctx)
			require.NoError(t, err)
			src, err := oci.ParseImageSpec(imageName, oci.WithPlatform(platform.String()))
			require.NoError(t, err)
			resolver, err := policy.CreateImageDetailsResolver(src)
			require.NoError(t, err)
			policy, err := policy.ResolvePolicy(ctx, resolver, tc.policy)
			if tc.errorStr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorStr)
				return
			}
			require.NoErrorf(t, err, "failed to resolve policy")
			require.NotNil(t, policy, "policy should not be nil")
			result, err := re.Evaluate(ctx, tc.resolver, policy, input)
			require.NoErrorf(t, err, "Evaluate failed")

			if tc.expectSuccess {
				assert.True(t, result.Success, "Evaluate should have succeeded")
			} else {
				assert.False(t, result.Success, "Evaluate should have failed")
			}
		})
	}

}

func TestLoadingMappings(t *testing.T) {
	policyMappings, err := config.LoadLocalMappings(filepath.Join("testdata", "mock-tuf-allow"))
	require.NoError(t, err)
	assert.Equal(t, len(policyMappings.Rules), 3)
	for _, mirror := range policyMappings.Rules {
		if mirror.PolicyId != "" {
			assert.Equal(t, "docker-official-images", mirror.PolicyId)
		}
	}
}
