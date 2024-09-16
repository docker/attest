package policy_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/attest/attestation"
	"github.com/docker/attest/config"
	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/oci"
	"github.com/docker/attest/policy"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/package-url/packageurl-go"
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
	TestDataPath := filepath.Join("..", "test", "testdata")
	ExampleAttestation := filepath.Join(TestDataPath, "example_attestation.json")

	verifier, err := attestation.NewVerfier()
	require.NoError(t, err)
	re := policy.NewRegoEvaluator(true, verifier)
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

func TestVerifySubject(t *testing.T) {
	ctx, _ := test.Setup(t)
	defaultResolver := attestation.MockResolver{}
	hostWithPort := packageurl.QualifiersFromMap(map[string]string{"platform": "linux/amd64"})
	withHost := packageurl.NewPackageURL(packageurl.TypeDocker, "localhost:1234", "alpine", "", hostWithPort, "")
	testCases := []struct {
		name        string
		subject     []intoto.Subject
		img         string
		expectError bool
		digest      string
	}{
		{
			name: "library short",
			subject: []intoto.Subject{
				{
					Name: "pkg:docker/alpine@latest?platform=linux%2Famd64",
				},
			},
			img: "alpine",
		},
		{
			name: "with domain and namespace",
			subject: []intoto.Subject{
				{
					Name: "pkg:docker/docker.io/library/alpine@latest?platform=linux%2Famd64",
				},
			},
			img: "alpine",
		},
		{
			name: "with host and port",
			subject: []intoto.Subject{
				{
					Name: withHost.ToString(),
				},
			},
			img: "localhost:1234/alpine",
		},
		{
			name: "with host and port (from image-signer-verifier tests)",
			subject: []intoto.Subject{
				{
					Name: "pkg:docker/registry.local%3A5000/image-signer-verifier-test@10710107227?platform=linux%2Famd64",
				},
			},
			img: "registry.local:5000/image-signer-verifier-test",
		},
		{
			name: "with library",
			subject: []intoto.Subject{
				{
					Name: "pkg:docker/library/alpine@latest?platform=linux%2Famd64",
				},
			},
			img: "alpine",
		},
		{
			name: "library short with tag",
			subject: []intoto.Subject{
				{
					Name: "pkg:docker/alpine@latest?platform=linux%2Famd64",
				},
			},
			img: "alpine:foo",
		},
		{
			name: "library with namespace",
			subject: []intoto.Subject{
				{
					Name: "pkg:docker/alpine@latest?platform=linux%2Famd64",
				},
			},
			img: "library/alpine:foo",
		},
		{
			name: "library with domain",
			subject: []intoto.Subject{
				{
					Name: "pkg:docker/alpine@latest?platform=linux%2Famd64",
				},
			},
			img: "docker.io/library/alpine:foo",
		},
		{
			name: "domain mismatch",
			subject: []intoto.Subject{
				{
					Name: "pkg:docker/alpine@latest?platform=linux%2Famd64",
				},
			},
			img:         "ecr.io/library/alpine:foo",
			expectError: true,
		},
		{
			name: "type mismatch",
			subject: []intoto.Subject{
				{
					Name: "pkg:node/alpine@latest?platform=linux%2Famd64",
				},
			},
			img:         "alpine",
			expectError: true,
		},
		{
			name: "name mismatch",
			subject: []intoto.Subject{
				{
					Name: "pkg:docker/alpine@latest?platform=linux%2Famd64",
				},
			},
			img:         "library/debian:latest",
			expectError: true,
		},
		{
			name: "namespace mismatch",
			subject: []intoto.Subject{
				{
					Name: "pkg:docker/alpine@latest?platform=linux%2Famd64",
				},
			},
			img:         "unsupported/alpine:latest",
			expectError: true,
		},
		{
			name: "digest mismatch",
			subject: []intoto.Subject{
				{
					Name: "pkg:docker/alpine@latest?platform=linux%2Famd64",
				},
			},
			img:         "alpine",
			digest:      "1234",
			expectError: true,
		},
		{
			name: "platform mismatch",
			subject: []intoto.Subject{
				{
					Name: "pkg:docker/alpine@latest?platform=linux%2Farm64",
				},
			},
			img:         "alpine",
			expectError: true,
		},
		{
			name: "malformed purl",
			subject: []intoto.Subject{
				{
					Name: "not-a-purl",
				},
			},
			img:         "alpine",
			expectError: true,
		},
		{
			name: "malformed image in valid purl",
			subject: []intoto.Subject{
				{
					Name: "pkg:docker/alpine,bar@latest?platform=linux%2Famd64",
				},
			},
			img:         "alpine-broken",
			expectError: true,
		},
		{
			name: "malformed image name",
			subject: []intoto.Subject{
				{
					Name: "pkg:docker/alpine@latest?platform=linux%2Famd64",
				},
			},
			img:         "foo bar",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defaultResolver.Image = tc.img
			// make sure we're using a fixed platform vs a detected one
			defaultResolver.PlatformFn = func() (*v1.Platform, error) {
				return &v1.Platform{Architecture: "amd64", OS: "linux"}, nil
			}
			// digest from mock resolver
			tc.subject[0].Digest = map[string]string{"sha256": "da8b190665956ea07890a0273e2a9c96bfe291662f08e2860e868eef69c34620"}
			if tc.digest != "" {
				tc.subject[0].Digest = map[string]string{"sha256": tc.digest}
			}
			err := policy.VerifySubject(ctx, tc.subject, defaultResolver)
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
	defaultResolver.Image = "alpine"
	subject := []intoto.Subject{
		{
			Name:   "pkg:docker/alpine@latest?platform=linux%2Famd64",
			Digest: map[string]string{"sha256": "da8b190665956ea07890a0273e2a9c96bfe291662f08e2860e868eef69c34620"},
		},
	}

	// error getting descriptor
	defaultResolver.DescriptorFn = func() (*v1.Descriptor, error) {
		return nil, fmt.Errorf("error")
	}
	err := policy.VerifySubject(ctx, subject, defaultResolver)
	require.Error(t, err)

	// error getting platform
	defaultResolver.DescriptorFn = nil
	defaultResolver.PlatformFn = func() (*v1.Platform, error) {
		return nil, fmt.Errorf("error")
	}
	err = policy.VerifySubject(ctx, subject, defaultResolver)
	require.Error(t, err)

	// error getting image name
	defaultResolver.PlatformFn = nil
	defaultResolver.Image = ""
	defaultResolver.ImangeNameFn = func() (string, error) {
		return "", fmt.Errorf("error")
	}
	err = policy.VerifySubject(ctx, subject, defaultResolver)
	require.Error(t, err)
}
