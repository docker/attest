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
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	ExampleAttestation = filepath.Join("..", "..", "test", "testdata", "example_attestation.json")
)

const (
	LinuxAMD64 = "linux/amd64"
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
				EvaluateFunc: func(ctx context.Context, resolver oci.AttestationResolver, pctx *policy.Policy, input *policy.PolicyInput) (*policy.Result, error) {
					return policy.AllowedResult(), tc.policyEvaluationError
				},
			}

			ctx := policy.WithPolicyEvaluator(context.Background(), &mockPE)
			_, err := VerifyAttestations(ctx, resolver, &policy.Policy{ResolvedName: ""})
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
	ctx = policy.WithPolicyEvaluator(ctx, policy.NewRegoEvaluator(true))
	// setup an image with signed attestations
	outputLayout := test.CreateTempDir(t, "", TestTempDir)

	opts := &attestation.SigningOptions{}
	attIdx, err := oci.IndexFromPath(UnsignedTestImage)
	assert.NoError(t, err)
	signedManifests, err := SignStatements(ctx, attIdx.Index, signer, opts)
	require.NoError(t, err)
	signedIndex := attIdx.Index
	signedIndex, err = attestation.AddImagesToIndex(signedIndex, signedManifests)
	require.NoError(t, err)

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

	// mocked vsa query should pass
	policyOpts := &policy.PolicyOptions{
		LocalPolicyDir: PassPolicyDir,
	}
	src, err := oci.ParseImageSpec("oci://"+outputLayout, oci.WithPlatform(LinuxAMD64))
	require.NoError(t, err)
	results, err := Verify(ctx, src, policyOpts)
	require.NoError(t, err)
	assert.Equal(t, OutcomeSuccess, results.Outcome)
	assert.Empty(t, results.Violations)

	if assert.NotNil(t, results.Input) {
		assert.Equal(t, "sha256:da8b190665956ea07890a0273e2a9c96bfe291662f08e2860e868eef69c34620", results.Input.Digest)
		assert.False(t, results.Input.IsCanonical)
	}

	assert.Equal(t, intoto.StatementInTotoV01, results.VSA.Type)
	assert.Equal(t, attestation.VSAPredicateType, results.VSA.PredicateType)
	assert.Len(t, results.VSA.Subject, 1)

	require.IsType(t, attestation.VSAPredicate{}, results.VSA.Predicate)
	attestationPredicate := results.VSA.Predicate.(attestation.VSAPredicate)

	assert.Equal(t, "PASSED", attestationPredicate.VerificationResult)
	assert.Equal(t, "docker-official-images", attestationPredicate.Verifier.ID)
	assert.Equal(t, []string{"SLSA_BUILD_LEVEL_3"}, attestationPredicate.VerifiedLevels)
	assert.Equal(t, "https://docker.com/official/policy/v0.1", attestationPredicate.Policy.URI)
}

func TestVerificationFailure(t *testing.T) {
	ctx, signer := test.Setup(t)
	ctx = policy.WithPolicyEvaluator(ctx, policy.NewRegoEvaluator(true))
	// setup an image with signed attestations
	outputLayout := test.CreateTempDir(t, "", TestTempDir)

	opts := &attestation.SigningOptions{}
	attIdx, err := oci.IndexFromPath(UnsignedTestImage)
	assert.NoError(t, err)
	signedManifests, err := SignStatements(ctx, attIdx.Index, signer, opts)
	require.NoError(t, err)
	signedIndex := attIdx.Index
	signedIndex, err = attestation.AddImagesToIndex(signedIndex, signedManifests, attestation.WithReplacedLayers(true))
	require.NoError(t, err)

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

	// mocked vsa query should fail
	policyOpts := &policy.PolicyOptions{
		LocalPolicyDir: FailPolicyDir,
	}
	src, err := oci.ParseImageSpec("oci://"+outputLayout, oci.WithPlatform(LinuxAMD64))
	require.NoError(t, err)
	results, err := Verify(ctx, src, policyOpts)
	require.NoError(t, err)
	assert.Equal(t, OutcomeFailure, results.Outcome)
	assert.Len(t, results.Violations, 1)

	violation := results.Violations[0]
	assert.Equal(t, "missing_attestation", violation.Type)
	assert.Equal(t, "Attestation missing for subject", violation.Description)
	assert.Nil(t, violation.Attestation)

	assert.Equal(t, intoto.StatementInTotoV01, results.VSA.Type)
	assert.Equal(t, attestation.VSAPredicateType, results.VSA.PredicateType)
	assert.Len(t, results.VSA.Subject, 1)

	require.IsType(t, attestation.VSAPredicate{}, results.VSA.Predicate)
	attestationPredicate := results.VSA.Predicate.(attestation.VSAPredicate)

	assert.Equal(t, "FAILED", attestationPredicate.VerificationResult)
	assert.Equal(t, "docker-official-images", attestationPredicate.Verifier.ID)
	assert.Equal(t, []string{"SLSA_BUILD_LEVEL_3"}, attestationPredicate.VerifiedLevels)
	assert.Equal(t, "https://docker.com/official/policy/v0.1", attestationPredicate.Policy.URI)
}

func TestSignVerify(t *testing.T) {
	ctx, signer := test.Setup(t)
	ctx = policy.WithPolicyEvaluator(ctx, policy.NewRegoEvaluator(true))
	// setup an image with signed attestations
	outputLayout := test.CreateTempDir(t, "", TestTempDir)

	testCases := []struct {
		name        string
		signTL      bool
		policyDir   string
		imageName   string
		expectError bool
	}{
		{name: "happy path", signTL: true, policyDir: PassNoTLPolicyDir},
		{name: "sign tl, verify no tl", signTL: true, policyDir: PassPolicyDir},
		{name: "no tl", signTL: false, policyDir: PassPolicyDir},
		{name: "mirror", signTL: true, policyDir: PassMirrorPolicyDir, imageName: "mirror.org/library/test-image:test"},
		{name: "mirror no match", signTL: true, policyDir: PassMirrorPolicyDir, imageName: "incorrect.org/library/test-image:test", expectError: true},
	}

	attIdx, err := oci.IndexFromPath(UnsignedTestImage)
	assert.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := &attestation.SigningOptions{
				SkipTL: tc.signTL,
			}

			signedManifests, err := SignStatements(ctx, attIdx.Index, signer, opts)
			require.NoError(t, err)
			signedIndex := attIdx.Index
			signedIndex, err = attestation.AddImagesToIndex(signedIndex, signedManifests, attestation.WithReplacedLayers(true))
			require.NoError(t, err)

			imageName := tc.imageName
			if imageName == "" {
				imageName = attIdx.Name
			}
			// output signed attestations
			idx := v1.ImageIndex(empty.Index)
			idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
				Add: signedIndex,
				Descriptor: v1.Descriptor{
					Annotations: map[string]string{
						oci.OciReferenceTarget: imageName,
					},
				},
			})
			_, err = layout.Write(outputLayout, idx)
			assert.NoError(t, err)

			policyOpts := &policy.PolicyOptions{
				LocalPolicyDir: tc.policyDir,
			}
			src, err := oci.ParseImageSpec("oci://"+outputLayout, oci.WithPlatform(LinuxAMD64))
			require.NoError(t, err)
			results, err := Verify(ctx, src, policyOpts)
			if tc.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, OutcomeSuccess, results.Outcome)
			platform, err := oci.ParsePlatform(LinuxAMD64)
			require.NoError(t, err)
			expectedPURL, _, err := oci.RefToPURL(attIdx.Name, platform)
			require.NoError(t, err)
			assert.Equal(t, expectedPURL, results.Input.Purl)
		})
	}
}
