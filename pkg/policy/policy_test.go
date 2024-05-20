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
	MockTufRepo := filepath.Join(TestDataPath, "local-policy")
	ExampleAttestation := filepath.Join(TestDataPath, "example_attestation.json")
	VSA := filepath.Join(TestDataPath, "vsa.json")

	re := policy.NewRegoEvaluator(true)

	defaultInput := &policy.PolicyInput{
		Digest:      "sha256:test-digest",
		Purl:        "test-purl",
		IsCanonical: true,
	}

	defaultResolver := oci.MockResolver{
		Envs: []*attestation.Envelope{loadAttestation(t, ExampleAttestation)},
	}

	vsaResolver := oci.MockResolver{
		Envs: []*attestation.Envelope{loadAttestation(t, ExampleAttestation), loadAttestation(t, VSA)},
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
		{repo: MockTufRepo, expectSuccess: true, input: &policy.PolicyInput{
			Digest:      "sha256:da8b190665956ea07890a0273e2a9c96bfe291662f08e2860e868eef69c34620",
			Purl:        "pkg:docker/test-image?digest=sha256%da8b190665956ea07890a0273e2a9c96bfe291662f08e2860e868eef69c34620&platform=linux%2Famd64",
			IsCanonical: true,
		}, resolver: vsaResolver},
		{repo: MockTufRepo, expectSuccess: true, input: &policy.PolicyInput{
			Digest:      "sha256:da8b190665956ea07890a0273e2a9c96bfe291662f08e2860e868eef69c34620",
			Purl:        "pkg:docker/test-image@test?platform=linux%2Famd64",
			IsCanonical: false,
		}, resolver: vsaResolver},
		// not a doi
		{repo: MockTufRepo, expectSuccess: false, input: defaultInput, resolver: vsaResolver, policy: &policy.PolicyOptions{
			LocalPolicyDir: "testdata/mock-tuf-deny",
		}},
		// digest mismatch
		{repo: MockTufRepo, expectSuccess: false, input: &policy.PolicyInput{
			Digest:      "sha256:test-digest-wrong",
			Purl:        "test-purl",
			IsCanonical: false,
		}, resolver: vsaResolver},
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
			rs, err := re.Evaluate(ctx, tc.resolver, policy, tc.input)

			if tc.expectSuccess {
				assert.NoErrorf(t, err, "Evaluate failed")
				assert.True(t, rs.Allowed(), "Evaluate should have succeeded")
			} else {
				assert.False(t, rs.Allowed(), "Evaluate should have failed")
			}
		})
	}

}
