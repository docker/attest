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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadAttestation(t *testing.T, path string) *attestation.Envelope {
	ex, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	env := new(attestation.Envelope)
	err = json.Unmarshal(ex, env)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestRegoEvaluator_Evaluate(t *testing.T) {
	ctx, _ := test.Setup(t)
	resolveErrorStr := "failed to resolve policy by id: policy with id non-existent-policy-id not found"
	TestDataPath := filepath.Join("..", "..", "test", "testdata")
	ExampleAttestation := filepath.Join(TestDataPath, "example_attestation.json")

	re := policy.NewRegoEvaluator(true)

	defaultResolver := attestation.MockResolver{
		Envs: []*attestation.Envelope{loadAttestation(t, ExampleAttestation)},
	}

	testCases := []struct {
		policyPath      string
		expectSuccess   bool
		isCanonical     bool
		resolver        attestation.Resolver
		opts            *policy.Options
		policyID        string
		resolveErrorStr string
	}{
		{policyPath: "testdata/policies/allow", expectSuccess: true, resolver: defaultResolver},
		{policyPath: "testdata/policies/allow", expectSuccess: true, resolver: defaultResolver, policyID: "docker-official-images"},
		{policyPath: "testdata/policies/allow", resolver: defaultResolver, policyID: "non-existent-policy-id", resolveErrorStr: resolveErrorStr},
		{policyPath: "testdata/policies/deny", resolver: defaultResolver},
		{policyPath: "testdata/policies/verify-sig", expectSuccess: true, resolver: defaultResolver},
		{policyPath: "testdata/policies/wrong-key", resolver: defaultResolver},
		{policyPath: "testdata/policies/allow-canonical", expectSuccess: true, isCanonical: true, resolver: defaultResolver},
		{policyPath: "testdata/policies/allow-canonical", resolver: defaultResolver},
		{policyPath: "testdata/policies/no-rego", resolver: defaultResolver, resolveErrorStr: "no policy file found in policy mapping"},
	}

	for _, tc := range testCases {
		t.Run(tc.policyPath, func(t *testing.T) {
			input := &policy.Input{
				Digest: "sha256:test-digest",
				PURL:   "test-purl",
			}
			if !tc.isCanonical {
				input.Tag = "test"
			}

			if tc.opts == nil {
				tc.opts = &policy.Options{
					LocalTargetsDir: test.CreateTempDir(t, "", "tuf-targets"),
					PolicyID:        tc.policyID,
					LocalPolicyDir:  tc.policyPath,
					DisableTUF:      true,
				}
			}
			imageName, err := tc.resolver.ImageName(ctx)
			require.NoError(t, err)
			resolver := policy.NewResolver(nil, tc.opts)
			policy, err := resolver.ResolvePolicy(ctx, imageName)
			if tc.resolveErrorStr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.resolveErrorStr)
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
	policyMappings, err := config.LoadLocalMappings(filepath.Join("testdata", "policies", "allow"))
	require.NoError(t, err)
	assert.Equal(t, len(policyMappings.Rules), 3)
	for _, mirror := range policyMappings.Rules {
		if mirror.PolicyID != "" {
			assert.Equal(t, "docker-official-images", mirror.PolicyID)
		}
	}
}

func TestCreateAttestationResolver(t *testing.T) {
	mockResolver := attestation.MockResolver{
		Envs: []*attestation.Envelope{},
	}
	layoutResolver := &attestation.LayoutResolver{}
	registryResolver := &oci.RegistryImageDetailsResolver{}

	nilRepoReferrers := &config.PolicyMapping{
		Attestations: &config.AttestationConfig{
			Style: config.AttestationStyleReferrers,
		},
	}
	referrers := &config.PolicyMapping{
		Attestations: &config.AttestationConfig{
			Repo:  "localhost:5000/repo",
			Style: config.AttestationStyleReferrers,
		},
	}
	attached := &config.PolicyMapping{
		Attestations: &config.AttestationConfig{
			Style: config.AttestationStyleAttached,
		},
	}

	testCases := []struct {
		name     string
		resolver oci.ImageDetailsResolver
		mapping  *config.PolicyMapping
		errorStr string
	}{
		{name: "referrers", resolver: layoutResolver, mapping: referrers},
		{name: "referrers (no mapped repo)", resolver: layoutResolver, mapping: nilRepoReferrers},
		{name: "referrers (no mapping)", resolver: layoutResolver, mapping: &config.PolicyMapping{Attestations: nil}},
		{name: "attached (registry)", resolver: registryResolver, mapping: attached},
		{name: "attached (layout)", resolver: layoutResolver, mapping: attached},
		{name: "attached (unsupported)", resolver: mockResolver, mapping: attached, errorStr: "unsupported image details resolver type"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resolver, err := policy.CreateAttestationResolver(tc.resolver, tc.mapping)
			if tc.errorStr == "" {
				require.NoError(t, err)
			} else {
				assert.Contains(t, err.Error(), tc.errorStr)
			}
			if tc.mapping.Attestations == nil {
				return
			}
			switch resolver.(type) {
			case *attestation.ReferrersResolver:
				assert.Equal(t, tc.mapping.Attestations.Style, config.AttestationStyleReferrers)
			case *attestation.RegistryResolver:
				assert.Equal(t, tc.mapping.Attestations.Style, config.AttestationStyleAttached)
			case *attestation.LayoutResolver:
				assert.Equal(t, tc.mapping.Attestations.Style, config.AttestationStyleAttached)
			}
		})
	}
}
