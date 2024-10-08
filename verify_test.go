package attest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/distribution/reference"
	"github.com/docker/attest/attestation"
	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/mapping"
	"github.com/docker/attest/oci"
	"github.com/docker/attest/policy"
	"github.com/docker/attest/tlog"
	"github.com/docker/attest/tuf"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

var (
	ExampleAttestation = filepath.Join("test", "testdata", "example_attestation.json")
	LocalKeysPolicy    = filepath.Join("test", "testdata", "local-policy-real")
	ExpiresPolicy      = filepath.Join("test", "testdata", "expires")
)

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
	ctx := context.Background()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockPE := policy.MockPolicyEvaluator{
				EvaluateFunc: func(_ context.Context, _ attestation.Resolver, _ *policy.Policy, _ *policy.Input) (*policy.Result, error) {
					return policy.AllowedResult(), tc.policyEvaluationError
				},
			}
			_, err := VerifyAttestations(ctx, resolver, &mockPE, &policy.Policy{ResolvedName: ""})
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
	// setup an image with signed attestations
	outputLayout := test.CreateTempDir(t, "", TestTempDir)

	opts := &attestation.SigningOptions{
		TransparencyLog: tlog.GetMockTL(),
	}
	attIdx, err := oci.IndexFromPath(test.UnsignedTestImage())
	assert.NoError(t, err)
	signedManifests, err := SignStatements(ctx, attIdx.Index, signer, opts)
	require.NoError(t, err)
	signedIndex := attIdx.Index
	signedIndex, err = attestation.UpdateIndexImages(signedIndex, signedManifests)
	require.NoError(t, err)

	// output signed attestations
	spec, err := oci.ParseImageSpec(oci.LocalPrefix+outputLayout, oci.WithPlatform(LinuxAMD64))
	require.NoError(t, err)
	err = oci.SaveIndex(ctx, []*oci.ImageSpec{spec}, signedIndex, attIdx.Name)
	assert.NoError(t, err)

	// mocked vsa query should pass
	policyOpts := &policy.Options{
		LocalPolicyDir:   PassPolicyDir,
		AttestationStyle: mapping.AttestationStyleAttached,
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
	// this is the digest of the policy file
	assert.Equal(t, map[string]string{"sha256": "ae71defe3b9ecebdf4f939a396b68884d0cba3c2c9d78ce5e64146d9487b0ade"}, attestationPredicate.Policy.Digest)
}

func TestVerificationFailure(t *testing.T) {
	ctx, signer := test.Setup(t)
	// setup an image with signed attestations
	outputLayout := test.CreateTempDir(t, "", TestTempDir)

	opts := &attestation.SigningOptions{
		TransparencyLog: tlog.GetMockTL(),
	}
	attIdx, err := oci.IndexFromPath(test.UnsignedTestImage())
	assert.NoError(t, err)
	signedManifests, err := SignStatements(ctx, attIdx.Index, signer, opts)
	require.NoError(t, err)
	signedIndex := attIdx.Index
	signedIndex, err = attestation.UpdateIndexImages(signedIndex, signedManifests, attestation.WithReplacedLayers(true))
	require.NoError(t, err)

	// output signed attestations
	spec, err := oci.ParseImageSpec(oci.LocalPrefix+outputLayout, oci.WithPlatform(LinuxAMD64))
	require.NoError(t, err)
	err = oci.SaveIndex(ctx, []*oci.ImageSpec{spec}, signedIndex, attIdx.Name)
	assert.NoError(t, err)

	// mocked vsa query should fail
	policyOpts := &policy.Options{
		LocalPolicyDir:   FailPolicyDir,
		AttestationStyle: mapping.AttestationStyleAttached,
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
	assert.Equal(t, map[string]string{"sha256": "4345a4f5db3ce02664bd83f8e4aad03bd9a26d4edb334338c762d9648e16bed1"}, attestationPredicate.Policy.Digest)
}

func TestSignVerify(t *testing.T) {
	ctx, signer := test.Setup(t)
	// setup an image with signed attestations
	outputLayout := test.CreateTempDir(t, "", TestTempDir)

	attIdx, err := oci.IndexFromPath(test.UnsignedTestImage())
	assert.NoError(t, err)
	validTime := time.Now().Add(time.Hour)
	expiredTime := time.Now().Add(-time.Hour)
	integratedTime := time.Now()

	testCases := []struct {
		name               string
		signTL             bool
		policyDir          string
		imageName          string
		expectedNonSuccess Outcome
		spitConfig         bool
		expires            *attestation.KeyExpiry
	}{
		// {name: "happy path", signTL: true, policyDir: PassNoTLPolicyDir},
		// {name: "sign tl, verify no tl", signTL: true, policyDir: PassPolicyDir},
		// {name: "no tl", signTL: false, policyDir: PassPolicyDir},
		// {name: "mirror", signTL: false, policyDir: PassMirrorPolicyDir, imageName: "mirror.org/library/test-image:test"},
		// {name: "mirror no match", signTL: false, policyDir: PassMirrorPolicyDir, imageName: "incorrect.org/library/test-image:test", expectedNonSuccess: OutcomeNoPolicy},
		// {name: "verify inputs", signTL: false, policyDir: InputsPolicyDir},
		{name: "mirror with verification", signTL: false, policyDir: LocalKeysPolicy, imageName: "mirror.org/library/test-image:test", spitConfig: true},
		{name: "with per repo expirey (valid)", signTL: true, policyDir: ExpiresPolicy, spitConfig: true, expires: &attestation.KeyExpiry{To: &validTime, Patterns: []string{attIdx.Name}, Platforms: []string{"linux/amd64"}}},
		{name: "with per repo expirey (expired)", signTL: true, policyDir: ExpiresPolicy, spitConfig: true, expires: &attestation.KeyExpiry{To: &expiredTime, Patterns: []string{attIdx.Name}, Platforms: []string{"linux/amd64"}}, expectedNonSuccess: OutcomeFailure},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keys, err := GenKeyMetadata(signer)
			require.NoError(t, err)
			if tc.expires != nil {
				keys.Expiries = []*attestation.KeyExpiry{tc.expires}
			}
			require.NoError(t, err)
			config := struct {
				Keys []*attestation.KeyMetadata `json:"keys"`
			}{
				Keys: []*attestation.KeyMetadata{keys},
			}
			keysYaml, err := yaml.Marshal(config)
			require.NoError(t, err)
			opts := &attestation.SigningOptions{}
			if tc.signTL {
				opts.TransparencyLog = tlog.GetMockTL()
			}
			if tc.spitConfig {
				err = os.WriteFile(filepath.Join(tc.policyDir, "config.yaml"), keysYaml, 0o600)
				require.NoError(t, err)
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
			err = oci.SaveIndex(ctx, []*oci.ImageSpec{spec}, signedIndex, imageName)
			require.NoError(t, err)

			policyOpts := &policy.Options{
				LocalPolicyDir: tc.policyDir,
				DisableTUF:     true,
				Debug:          true,
			}
			if tc.signTL {
				getTL := func(_ context.Context, _ *attestation.VerifyOptions) (tlog.TransparencyLog, error) {
					return tlog.GetMockTL(tlog.WithIntegratedTime(integratedTime)), nil
				}
				verifier, err := attestation.NewVerfier(attestation.WithLogVerifierFactory(getTL))
				require.NoError(t, err)
				policyOpts.AttestationVerifier = verifier
			}

			results, err := Verify(ctx, spec, policyOpts)
			require.NoError(t, err)
			if tc.expectedNonSuccess != "" {
				assert.Equal(t, tc.expectedNonSuccess, results.Outcome)
				return
			}
			if results.Outcome == OutcomeFailure {
				t.Logf("Violations: %v", results.Violations)
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
		attestationStyle mapping.AttestationStyle
		referrersRepo    string
		expectedError    string
		disableTuf       bool
		localPolicyDir   string
	}{
		{name: "empty"},
		{name: "tufClient provided", tufOpts: &tuf.ClientOptions{MetadataSource: "a", TargetsSource: "b"}},
		{name: "localTargetsDir provided", localTargetsDir: test.CreateTempDir(t, "", TestTempDir)},
		{name: "attestationStyle provided", attestationStyle: mapping.AttestationStyleAttached},
		{name: "referrersRepo provided", referrersRepo: "referrers"},
		{name: "referrersRepo provided with attached", referrersRepo: "referrers", attestationStyle: mapping.AttestationStyleAttached, expectedError: "referrers repo specified but attestation source not set to referrers"},
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
				assert.Equal(t, mapping.AttestationStyleReferrers, opts.AttestationStyle)
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

// LoadKeyMetadata loads the key metadata for the given signer verifier.
func GenKeyMetadata(sv dsse.SignerVerifier) (*attestation.KeyMetadata, error) {
	pub := sv.Public()
	pem, err := test.PublicKeyToPEM(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key to PEM: %w", err)
	}
	id, err := sv.KeyID()
	if err != nil {
		return nil, err
	}

	return &attestation.KeyMetadata{
		ID:            id,
		Status:        "active",
		SigningFormat: "dssev1",
		From:          time.Now().Add(-time.Hour),
		PEM:           pem,
	}, nil
}
