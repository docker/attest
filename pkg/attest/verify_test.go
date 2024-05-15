package attest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/policy"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	ExampleAttestation = filepath.Join("..", "..", "test", "testdata", "example_attestation.json")
)

func TestVerifyAttestations(t *testing.T) {
	ex, err := os.ReadFile(ExampleAttestation)
	assert.NoError(t, err)

	var env = new(attestation.Envelope)
	err = json.Unmarshal(ex, env)
	assert.NoError(t, err)
	resolver := &oci.MockResolver{
		Envs: []*attestation.Envelope{env},
	}

	testCases := []struct {
		name                  string
		policyEvaluationError error
		expectedError         error
	}{
		{"policy ok", nil, nil},
		{"policy error", fmt.Errorf("policy error"), fmt.Errorf("policy evaluation failed: policy error")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			mockPE := policy.MockPolicyEvaluator{
				EvaluateFunc: func(ctx context.Context, resolver oci.AttestationResolver, pctx *policy.Policy, input *policy.PolicyInput) (rego.ResultSet, error) {
					return policy.AllowedResult(), tc.policyEvaluationError
				},
			}

			ctx := policy.WithPolicyEvaluator(context.Background(), &mockPE)
			_, err := VerifyAttestations(ctx, resolver, nil)
			if tc.expectedError != nil {
				if assert.Error(t, err) {
					assert.Equal(t, tc.expectedError.Error(), err.Error())
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVSA(t *testing.T) {
	ctx, signer := test.Setup(t)
	ctx = policy.WithPolicyEvaluator(ctx, policy.NewRegoEvaluator(false))
	policyOpts := &policy.PolicyOptions{
		LocalPolicyDir: LocalPolicyDir,
	}
	// setup an image with signed attestations
	tempDir := test.CreateTempDir(t, "", TestTempDir)
	outputLayout := tempDir

	opts := &SigningOptions{
		Replace: true,
	}
	attIdx, err := oci.AttestationIndexFromPath(UnsignedTestImage)
	assert.NoError(t, err)
	signedIndex, err := Sign(ctx, attIdx.Index, signer, opts)
	assert.NoError(t, err)

	// output signed attestations
	idx := v1.ImageIndex(empty.Index)
	idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
		Add: signedIndex,
		Descriptor: v1.Descriptor{
			Annotations: map[string]string{
				oci.OciReferenceTarget: attIdx.Name,
			},
		},
	})
	_, err = layout.Write(outputLayout, idx)
	assert.NoError(t, err)

	//verify (without vsa should fail)
	resolver := &oci.OCILayoutResolver{
		Path:     outputLayout,
		Platform: "linux/amd64",
	}

	// results, err := Verify(ctx, policyOpts, resolver)
	// assert.NoError(t, err)
	// assert.Equal(t, false, results.Success)

	// mocked vsa query should pass
	policyOpts.LocalPolicyDir = PassPolicyDir
	results, err := Verify(ctx, policyOpts, resolver)
	require.NoError(t, err)
	assert.True(t, results.Success)
	assert.Empty(t, results.Violations)

	// create a signed attestation and add it
	withVSA, err := AddAttestation(ctx, signedIndex, results.Summary, signer, opts)
	assert.NoError(t, err)

	// output signed attestations with vsa
	idx = v1.ImageIndex(empty.Index)
	idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
		Add: withVSA,
		Descriptor: v1.Descriptor{
			Annotations: map[string]string{
				oci.OciReferenceTarget: attIdx.Name,
			},
		},
	})
	tempDir = test.CreateTempDir(t, "", TestTempDir)
	outputLayout = tempDir

	_, err = layout.Write(outputLayout, idx)
	assert.NoError(t, err)
	resolver = &oci.OCILayoutResolver{
		Path:     outputLayout,
		Platform: "linux/amd64",
	}
	// policy requiring VSA (default) should work
	ctx = policy.WithPolicyEvaluator(ctx, policy.NewRegoEvaluator(true))
	policyOpts.LocalPolicyDir = VSAPolicyDir
	results, err = Verify(ctx, policyOpts, resolver)
	require.NoError(t, err)
	assert.Equal(t, true, results.Success)
}
