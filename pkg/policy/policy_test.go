package policy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/pkg/attestation"
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

	TestDataPath := filepath.Join("..", "..", "test", "testdata")
	ExampleAttestation := filepath.Join(TestDataPath, "example_attestation.json")

	re := policy.NewRegoEvaluator(true)

	defaultInput := &policy.PolicyInput{
		Digest:      "sha256:test-digest",
		Purl:        "test-purl",
		IsCanonical: true,
	}

	defaultResolver := oci.MockResolver{
		Envs: []*attestation.Envelope{loadAttestation(t, ExampleAttestation)},
	}

	testCases := []struct {
		repo          string
		expectSuccess bool
		input         *policy.PolicyInput
		resolver      oci.AttestationResolver
		policy        *policy.PolicyOptions
	}{
		{repo: "testdata/mock-tuf-allow", expectSuccess: true, input: defaultInput, resolver: defaultResolver},
		{repo: "testdata/mock-tuf-deny", expectSuccess: false, input: defaultInput, resolver: defaultResolver},
		{repo: "testdata/mock-tuf-verify-sig", expectSuccess: true, input: defaultInput, resolver: defaultResolver},
		{repo: "testdata/mock-tuf-wrong-key", expectSuccess: false, input: defaultInput, resolver: defaultResolver},
	}

	for _, tc := range testCases {
		t.Run(tc.repo, func(t *testing.T) {
			tufClient := tuf.NewMockTufClient(tc.repo, test.CreateTempDir(t, "", "tuf-dest"))
			if tc.policy == nil {
				tc.policy = &policy.PolicyOptions{
					TufClient:       tufClient,
					LocalTargetsDir: test.CreateTempDir(t, "", "tuf-targets"),
				}
			}

			policy, err := policy.ResolvePolicy(ctx, tc.resolver, tc.policy)
			assert.NoErrorf(t, err, "failed to resolve policy")
			result, err := re.Evaluate(ctx, tc.resolver, policy, tc.input)
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
	opts := &policy.PolicyOptions{
		LocalPolicyDir: filepath.Join("testdata", "mock-tuf-allow"),
	}
	policyMappings, err := policy.LoadLocalMappings(opts)
	require.NoError(t, err)
	assert.Equal(t, len(policyMappings.Mirrors), 1)
	for _, mirror := range policyMappings.Mirrors {
		assert.Equal(t, "docker-official-images", mirror.PolicyId)
	}
}
