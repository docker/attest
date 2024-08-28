package attest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/distribution/reference"
	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/config"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/policy"
	"github.com/docker/attest/pkg/tuf"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var ExampleAttestation = filepath.Join("..", "..", "test", "testdata", "example_attestation.json")

const (
	LinuxAMD64 = "linux/amd64"
)

func TestVerifyAttestations(t *testing.T) {
	ex, err := os.ReadFile(ExampleAttestation)
	assert.NoError(t, err)

	env := new(attestation.Envelope)
	err = json.Unmarshal(ex, env)
	assert.NoError(t, err)
	resolver := &attestation.MockResolver{
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
				EvaluateFunc: func(_ context.Context, _ attestation.Resolver, _ *policy.Policy, _ *policy.Input) (*policy.Result, error) {
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
	attIdx, err := oci.IndexFromPath(test.UnsignedTestImage)
	assert.NoError(t, err)
	signedManifests, err := SignStatements(ctx, attIdx.Index, signer, opts)
	require.NoError(t, err)
	signedIndex := attIdx.Index
	signedIndex, err = attestation.UpdateIndexImages(signedIndex, signedManifests)
	require.NoError(t, err)

	// output signed attestations
	spec, err := oci.ParseImageSpec(oci.LocalPrefix+outputLayout, oci.WithPlatform(LinuxAMD64))
	require.NoError(t, err)
	err = oci.SaveIndex([]*oci.ImageSpec{spec}, signedIndex, attIdx.Name)
	assert.NoError(t, err)

	// mocked vsa query should pass
	policyOpts := &policy.Options{
		LocalPolicyDir:   PassPolicyDir,
		AttestationStyle: config.AttestationStyleAttached,
		DisableTUF:       true,
	}
	results, err := Verify(ctx, spec, policyOpts)
	require.NoError(t, err)
	assert.Equal(t, OutcomeSuccess, results.Outcome)
	assert.Empty(t, results.Violations)

	if assert.NotNil(t, results.Input) {
		assert.Equal(t, "sha256:da8b190665956ea07890a0273e2a9c96bfe291662f08e2860e868eef69c34620", results.Input.Digest)
		assert.NotNil(t, results.Input.Tag)
	}

	assert.Equal(t, intoto.StatementInTotoV01, results.VSA.Type)
	assert.Equal(t, attestation.VSAPredicateType, results.VSA.PredicateType)
	assert.Len(t, results.VSA.Subject, 1)

	require.IsType(t, attestation.VSAPredicate{}, results.VSA.Predicate)
	attestationPredicate, ok := results.VSA.Predicate.(attestation.VSAPredicate)
	require.True(t, ok)

	assert.Equal(t, "PASSED", attestationPredicate.VerificationResult)
	assert.Equal(t, "docker-official-images", attestationPredicate.Verifier.ID)
	assert.Equal(t, []string{"SLSA_BUILD_LEVEL_3"}, attestationPredicate.VerifiedLevels)
	assert.Equal(t, PassPolicyDir+"/policy.rego", attestationPredicate.Policy.DownloadLocation)
	assert.Equal(t, "https://docker.com/official/policy/v0.1", attestationPredicate.Policy.URI)
	assert.Equal(t, map[string]string{"sha256": "d71d6b8f49fcba1295b16f5394dd5863a14e4277eb663d66d8c48e392509afe0"}, attestationPredicate.Policy.Digest)
}

func TestVerificationFailure(t *testing.T) {
	ctx, signer := test.Setup(t)
	ctx = policy.WithPolicyEvaluator(ctx, policy.NewRegoEvaluator(true))
	// setup an image with signed attestations
	outputLayout := test.CreateTempDir(t, "", TestTempDir)

	opts := &attestation.SigningOptions{}
	attIdx, err := oci.IndexFromPath(test.UnsignedTestImage)
	assert.NoError(t, err)
	signedManifests, err := SignStatements(ctx, attIdx.Index, signer, opts)
	require.NoError(t, err)
	signedIndex := attIdx.Index
	signedIndex, err = attestation.UpdateIndexImages(signedIndex, signedManifests, attestation.WithReplacedLayers(true))
	require.NoError(t, err)

	// output signed attestations
	spec, err := oci.ParseImageSpec(oci.LocalPrefix+outputLayout, oci.WithPlatform(LinuxAMD64))
	require.NoError(t, err)
	err = oci.SaveIndex([]*oci.ImageSpec{spec}, signedIndex, attIdx.Name)
	assert.NoError(t, err)

	// mocked vsa query should fail
	policyOpts := &policy.Options{
		LocalPolicyDir:   FailPolicyDir,
		AttestationStyle: config.AttestationStyleAttached,
		DisableTUF:       true,
	}
	results, err := Verify(ctx, spec, policyOpts)
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
	attestationPredicate, ok := results.VSA.Predicate.(attestation.VSAPredicate)
	require.True(t, ok)

	assert.Equal(t, "FAILED", attestationPredicate.VerificationResult)
	assert.Equal(t, "docker-official-images", attestationPredicate.Verifier.ID)
	assert.Equal(t, []string{"SLSA_BUILD_LEVEL_3"}, attestationPredicate.VerifiedLevels)
	assert.Equal(t, FailPolicyDir+"/policy.rego", attestationPredicate.Policy.DownloadLocation)
	assert.Equal(t, "https://docker.com/official/policy/v0.1", attestationPredicate.Policy.URI)
	assert.Equal(t, map[string]string{"sha256": "ad045e1bd7cd602d90196acf68f2c57d7b51565d59e6e30e30d94ae86aa16201"}, attestationPredicate.Policy.Digest)
}

func TestSignVerify(t *testing.T) {
	ctx, signer := test.Setup(t)
	ctx = policy.WithPolicyEvaluator(ctx, policy.NewRegoEvaluator(true))
	// setup an image with signed attestations
	outputLayout := test.CreateTempDir(t, "", TestTempDir)

	testCases := []struct {
		name               string
		signTL             bool
		policyDir          string
		imageName          string
		expectedNonSuccess Outcome
	}{
		{name: "happy path", signTL: true, policyDir: PassNoTLPolicyDir},
		{name: "sign tl, verify no tl", signTL: true, policyDir: PassPolicyDir},
		{name: "no tl", signTL: false, policyDir: PassPolicyDir},
		{name: "mirror", signTL: true, policyDir: PassMirrorPolicyDir, imageName: "mirror.org/library/test-image:test"},
		{name: "mirror no match", signTL: true, policyDir: PassMirrorPolicyDir, imageName: "incorrect.org/library/test-image:test", expectedNonSuccess: OutcomeNoPolicy},
		{name: "verify inputs", signTL: false, policyDir: InputsPolicyDir},
	}

	attIdx, err := oci.IndexFromPath(test.UnsignedTestImage)
	assert.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := &attestation.SigningOptions{
				SkipTL: tc.signTL,
			}

			signedManifests, err := SignStatements(ctx, attIdx.Index, signer, opts)
			require.NoError(t, err)
			signedIndex := attIdx.Index
			signedIndex, err = attestation.UpdateIndexImages(signedIndex, signedManifests, attestation.WithReplacedLayers(true))
			require.NoError(t, err)

			imageName := tc.imageName
			if imageName == "" {
				imageName = attIdx.Name
			}
			// output signed attestations
			spec, err := oci.ParseImageSpec(oci.LocalPrefix+outputLayout, oci.WithPlatform(LinuxAMD64))
			require.NoError(t, err)
			err = oci.SaveIndex([]*oci.ImageSpec{spec}, signedIndex, imageName)
			require.NoError(t, err)

			policyOpts := &policy.Options{
				LocalPolicyDir: tc.policyDir,
				DisableTUF:     true,
			}
			results, err := Verify(ctx, spec, policyOpts)
			require.NoError(t, err)
			if tc.expectedNonSuccess != "" {
				assert.Equal(t, tc.expectedNonSuccess, results.Outcome)
				return
			}
			assert.Equal(t, OutcomeSuccess, results.Outcome)
			platform, err := oci.ParsePlatform(LinuxAMD64)
			require.NoError(t, err)

			ref, err := reference.ParseNormalizedNamed(attIdx.Name)
			require.NoError(t, err)
			expectedPURL, _, err := oci.RefToPURL(ref, platform)
			require.NoError(t, err)
			assert.Equal(t, expectedPURL, results.Input.PURL)
		})
	}
}

func TestDefaultOptions(t *testing.T) {
	testCases := []struct {
		name             string
		tufOpts          *tuf.ClientOptions
		localTargetsDir  string
		attestationStyle config.AttestationStyle
		referrersRepo    string
		expectedError    string
		disableTuf       bool
		localPolicyDir   string
	}{
		{name: "empty"},
		{name: "tufClient provided", tufOpts: &tuf.ClientOptions{MetadataSource: "a", TargetsSource: "b"}},
		{name: "localTargetsDir provided", localTargetsDir: test.CreateTempDir(t, "", TestTempDir)},
		{name: "attestationStyle provided", attestationStyle: config.AttestationStyleAttached},
		{name: "referrersRepo provided", referrersRepo: "referrers"},
		{name: "referrersRepo provided with attached", referrersRepo: "referrers", attestationStyle: config.AttestationStyleAttached, expectedError: "referrers repo specified but attestation source not set to referrers"},
		{name: "tuf disabled and no local-policy-dir", disableTuf: true, expectedError: "local policy dir must be set if not using TUF"},
		{name: "tuf disabled but options set", disableTuf: true, tufOpts: &tuf.ClientOptions{MetadataSource: "a", TargetsSource: "b"}, localPolicyDir: "foo", expectedError: "TUF client options set but TUF disabled"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defaultTargets, err := defaultLocalTargetsDir()
			require.NoError(t, err)

			opts := &policy.Options{
				TUFClientOptions: tc.tufOpts,
				LocalTargetsDir:  tc.localTargetsDir,
				AttestationStyle: tc.attestationStyle,
				ReferrersRepo:    tc.referrersRepo,
				DisableTUF:       tc.disableTuf,
				LocalPolicyDir:   tc.localPolicyDir,
			}

			err = populateDefaultOptions(opts)
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Equal(t, tc.expectedError, err.Error())
				return
			}

			require.NoError(t, err)

			if tc.localTargetsDir != "" {
				assert.Equal(t, tc.localTargetsDir, opts.LocalTargetsDir)
			} else {
				assert.Equal(t, defaultTargets, opts.LocalTargetsDir)
			}

			if tc.attestationStyle != "" {
				assert.Equal(t, tc.attestationStyle, opts.AttestationStyle)
			} else {
				assert.Equal(t, config.AttestationStyleReferrers, opts.AttestationStyle)
			}

			if tc.tufOpts != nil {
				assert.Equal(t, tc.tufOpts, opts.TUFClientOptions)
			} else {
				assert.NotNil(t, opts.TUFClientOptions)
			}

			if tc.referrersRepo != "" {
				assert.Equal(t, tc.referrersRepo, opts.ReferrersRepo)
			} else {
				assert.Empty(t, opts.ReferrersRepo)
			}
		})
	}
}
