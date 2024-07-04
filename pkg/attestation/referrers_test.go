package attestation_test

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/pkg/attest"
	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/config"
	"github.com/docker/attest/pkg/mirror"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/policy"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	UnsignedTestImage   = filepath.Join("..", "..", "test", "testdata", "unsigned-test-image")
	NoProvenanceImage   = filepath.Join("..", "..", "test", "testdata", "no-provenance-image")
	PassPolicyDir       = filepath.Join("..", "..", "test", "testdata", "local-policy-pass")
	LocalPolicy         = filepath.Join("..", "..", "test", "testdata", "local-policy")
	LocalPolicyAttached = filepath.Join("..", "..", "test", "testdata", "local-policy-attached")
	PassNoTLPolicyDir   = filepath.Join("..", "..", "test", "testdata", "local-policy-no-tl")
	FailPolicyDir       = filepath.Join("..", "..", "test", "testdata", "local-policy-fail")
	TestTempDir         = "attest-sign-test"
)

func TestAttestationReferenceTypes(t *testing.T) {
	ctx, signer := test.Setup(t)
	ctx = policy.WithPolicyEvaluator(ctx, policy.NewRegoEvaluator(true))
	platforms := []string{"linux/amd64", "linux/arm64"}
	for _, tc := range []struct {
		server            *httptest.Server
		referrersServer   *httptest.Server
		skipSubject       bool
		useDigest         bool
		referrersRepo     string
		attestationSource config.AttestationStyle
		expectFailure     bool
		policyDir         string
	}{
		{
			server: httptest.NewServer(registry.New(registry.WithReferrersSupport(true))),
		},
		{
			server: httptest.NewServer(registry.New()),
		},
		{
			server:            httptest.NewServer(registry.New(registry.WithReferrersSupport(true))),
			skipSubject:       true,
			attestationSource: config.AttestationStyleAttached,
		},
		{
			server:    httptest.NewServer(registry.New(registry.WithReferrersSupport(true))),
			useDigest: true,
		},
		{
			server:            httptest.NewServer(registry.New(registry.WithReferrersSupport(true))),
			expectFailure:     true, //mismatched args
			attestationSource: config.AttestationStyleAttached,
			referrersRepo:     "referrers",
		},
		{
			server:            httptest.NewServer(registry.New(registry.WithReferrersSupport(true))),
			expectFailure:     true, // no policy
			attestationSource: config.AttestationStyleReferrers,
			referrersRepo:     "referrers",
		},
		{
			server:            httptest.NewServer(registry.New(registry.WithReferrersSupport(true))),
			attestationSource: config.AttestationStyleReferrers,
		},
		{
			server:            httptest.NewServer(registry.New(registry.WithReferrersSupport(false))),
			attestationSource: config.AttestationStyleReferrers,
			referrersServer:   httptest.NewServer(registry.New(registry.WithReferrersSupport(true))),
		},
	} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			s := tc.server
			defer s.Close()

			if tc.referrersServer != nil {
				defer tc.referrersServer.Close()
			}
			u, err := url.Parse(s.URL)
			require.NoError(t, err)

			opts := &attestation.SigningOptions{
				Replace:     true,
				SkipSubject: tc.skipSubject,
			}
			attIdx, err := oci.IndexFromPath(UnsignedTestImage)
			require.NoError(t, err)

			indexName := fmt.Sprintf("%s/repo:root", u.Host)
			require.NoError(t, err)

			if tc.referrersServer != nil {
				ru, err := url.Parse(s.URL)
				require.NoError(t, err)
				repo := fmt.Sprintf("%s/referrers", ru.Host)
				tc.referrersRepo = repo
				signedManifests, err := attest.SignStatements(ctx, attIdx.Index, signer, opts)
				require.NoError(t, err)
				err = mirror.PushIndexToRegistry(attIdx.Index, indexName)
				for _, img := range signedManifests {
					err = mirror.PushImageToRegistry(img.Attestation.Image, fmt.Sprintf("%s:tag-does-not-matter", repo))
					require.NoError(t, err)
				}
			} else {
				signedManifests, err := attest.SignStatements(ctx, attIdx.Index, signer, opts)
				require.NoError(t, err)
				signedIndex := attIdx.Index
				signedIndex, err = attestation.AddImagesToIndex(signedIndex, signedManifests)
				require.NoError(t, err)
				err = mirror.PushIndexToRegistry(signedIndex, indexName)
				require.NoError(t, err)
			}

			for _, platform := range platforms {
				// can eval policy in the normal way
				ref := indexName
				if tc.useDigest {
					options := oci.WithOptions(ctx, nil)
					subjectRef, err := name.ParseReference(indexName)
					require.NoError(t, err)
					desc, err := remote.Index(subjectRef, options...)
					require.NoError(t, err)
					idxDigest, err := desc.Digest()
					require.NoError(t, err)
					ref = fmt.Sprintf("%s/repo@%s", u.Host, idxDigest.String())
				}

				policyOpts := &policy.PolicyOptions{
					LocalPolicyDir: LocalPolicy,
				}
				if tc.policyDir != "" {
					policyOpts.LocalPolicyDir = tc.policyDir
				}

				if tc.referrersRepo != "" {
					policyOpts.ReferrersRepo = tc.referrersRepo
				}

				if tc.attestationSource != "" {
					policyOpts.AttestationStyle = tc.attestationSource
				}
				src, err := oci.ParseImageSpec(ref, oci.WithPlatform(platform))
				require.NoError(t, err)
				results, err := attest.Verify(ctx, src, policyOpts)
				if tc.expectFailure {
					require.Error(t, err)
					continue
				}
				require.NoError(t, err)
				assert.Equal(t, attest.OutcomeSuccess, results.Outcome)

				if !tc.skipSubject {
					// can evaluate policy using referrers
					if tc.useDigest {
						p, err := oci.ParsePlatform(platform)
						require.NoError(t, err)
						options := oci.WithOptions(ctx, p)
						subjectRef, err := name.ParseReference(indexName)
						require.NoError(t, err)
						desc, err := remote.Image(subjectRef, options...)
						require.NoError(t, err)
						subjectDigest, err := desc.Digest()
						require.NoError(t, err)
						ref = fmt.Sprintf("%s/repo@%s", u.Host, subjectDigest.String())
					}
					src, err := oci.ParseImageSpec(ref, oci.WithPlatform(platform))
					require.NoError(t, err)
					results, err = attest.Verify(ctx, src, policyOpts)
					require.NoError(t, err)
					assert.Equal(t, attest.OutcomeSuccess, results.Outcome)
				}
			}
		})
	}
}

func TestReferencesInDifferentRepo(t *testing.T) {
	ctx, signer := test.Setup(t)
	repoName := "repo"
	for _, tc := range []struct {
		server    *httptest.Server
		refServer *httptest.Server
	}{
		{
			server:    httptest.NewServer(registry.New(registry.WithReferrersSupport(true))),
			refServer: httptest.NewServer(registry.New(registry.WithReferrersSupport(true))),
		},
		{
			server:    httptest.NewServer(registry.New()),
			refServer: httptest.NewServer(registry.New(registry.WithReferrersSupport(true))),
		},
	} {
		server := tc.server
		defer server.Close()
		serverUrl, err := url.Parse(server.URL)
		require.NoError(t, err)

		refServer := tc.refServer
		defer refServer.Close()
		refServerUrl, err := url.Parse(refServer.URL)
		require.NoError(t, err)

		opts := &attestation.SigningOptions{
			Replace: true,
			SkipTL:  true,
		}
		attIdx, err := oci.IndexFromPath(UnsignedTestImage)
		require.NoError(t, err)

		indexName := fmt.Sprintf("%s/%s:latest", serverUrl.Host, repoName)
		err = mirror.PushIndexToRegistry(attIdx.Index, indexName)
		require.NoError(t, err)

		signedManifests, err := attest.SignStatements(ctx, attIdx.Index, signer, opts)
		require.NoError(t, err)

		// push signed attestation image to the ref server
		for _, img := range signedManifests {
			// push references using subject-digest.att convention
			err = mirror.PushImageToRegistry(img.Attestation.Image, fmt.Sprintf("%s/%s:tag-does-not-matter", refServerUrl.Host, repoName))
			require.NoError(t, err)
		}
		mfs2, err := attIdx.Index.IndexManifest()
		require.NoError(t, err)
		for _, mf := range mfs2.Manifests {
			//skip signed/unsigned attestations
			if mf.Annotations[attestation.DockerReferenceType] == attestation.AttestationManifestType {
				continue
			}
			// can evaluate policy using referrers in a different repo
			referencedImage := fmt.Sprintf("%s@%s", indexName, mf.Digest.String())
			policyOpts := &policy.PolicyOptions{
				LocalPolicyDir: PassPolicyDir,
			}
			src, err := oci.ParseImageSpec(referencedImage)
			require.NoError(t, err)
			results, err := attest.Verify(ctx, src, policyOpts)
			require.NoError(t, err)
			assert.Equal(t, attest.OutcomeSuccess, results.Outcome)
		}
	}
}
