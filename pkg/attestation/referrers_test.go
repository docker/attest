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
	"github.com/docker/attest/pkg/mirror"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/policy"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	UnsignedTestImage = filepath.Join("..", "..", "test", "testdata", "unsigned-test-image")
	NoProvenanceImage = filepath.Join("..", "..", "test", "testdata", "no-provenance-image")
	PassPolicyDir     = filepath.Join("..", "..", "test", "testdata", "local-policy-pass")
	PassNoTLPolicyDir = filepath.Join("..", "..", "test", "testdata", "local-policy-no-tl")
	FailPolicyDir     = filepath.Join("..", "..", "test", "testdata", "local-policy-fail")
	TestTempDir       = "attest-sign-test"
)

func TestAttestationReferenceTypes(t *testing.T) {
	ctx, signer := test.Setup(t)
	for _, tc := range []struct {
		server      *httptest.Server
		skipSubject bool
	}{
		{
			server: httptest.NewServer(registry.New(registry.WithReferrersSupport(true))),
		},
		{
			server: httptest.NewServer(registry.New()),
		},
		{
			server:      httptest.NewServer(registry.New(registry.WithReferrersSupport(true))),
			skipSubject: true,
		},
	} {
		s := tc.server
		defer s.Close()
		u, err := url.Parse(s.URL)
		require.NoError(t, err)

		opts := &attestation.SigningOptions{
			Replace:     true,
			SkipSubject: tc.skipSubject,
		}
		attIdx, err := oci.SubjectIndexFromPath(UnsignedTestImage)
		require.NoError(t, err)
		signedIndex, err := attest.Sign(ctx, attIdx.Index, signer, opts)
		require.NoError(t, err)

		indexName := fmt.Sprintf("%s/repo:root", u.Host)
		imfs, err := signedIndex.IndexManifest()
		require.NoError(t, err)
		err = mirror.PushToRegistry(signedIndex, indexName)

		for _, mf := range imfs.Manifests {
			// we are looking up via the images themselves
			if mf.Annotations[attestation.DockerReferenceType] == "attestation-manifest" {
				continue
			}

			// can eval policy in the normal way
			resolver, err := oci.NewRegistryAttestationResolver(indexName, "linux/amd64")
			require.NoError(t, err)

			policyOpts := &policy.PolicyOptions{
				LocalPolicyDir: PassPolicyDir,
			}
			results, err := attest.Verify(ctx, policyOpts, resolver)
			require.NoError(t, err)
			assert.Equal(t, attest.OutcomeSuccess, results.Outcome)

			if !tc.skipSubject {
				// can evaluate policy using referrers
				referrersResolver, err := oci.NewReferrersAttestationResolver(indexName, oci.WithPlatform("linux/amd64"))
				require.NoError(t, err)

				results, err = attest.Verify(ctx, policyOpts, referrersResolver)
				require.NoError(t, err)
				assert.Equal(t, attest.OutcomeSuccess, results.Outcome)
			}
		}
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
		attIdx, err := oci.SubjectIndexFromPath(UnsignedTestImage)
		require.NoError(t, err)

		indexName := fmt.Sprintf("%s/%s:latest", serverUrl.Host, repoName)
		err = mirror.PushToRegistry(attIdx.Index, indexName)
		require.NoError(t, err)

		signedImages, err := attest.SignedAttestationImages(ctx, attIdx.Index, signer, opts)
		require.NoError(t, err)

		// push signed attestation image to the ref server
		for _, img := range signedImages {
			// push references using subject-digest.att convention
			err = mirror.PushToRegistry(&img.Image, fmt.Sprintf("%s/%s:%s-%s.att", refServerUrl.Host, repoName, img.AttestationManifest.SubjectDescriptor.Digest.Algorithm, img.AttestationManifest.SubjectDescriptor.Digest.Hex))
			require.NoError(t, err)
		}
		mfs2, err := attIdx.Index.IndexManifest()
		require.NoError(t, err)
		for _, mf := range mfs2.Manifests {
			//skip signed/unsigned attestations
			if mf.Annotations[attestation.DockerReferenceType] == "attestation-manifest" {
				continue
			}
			// can evaluate policy using referrers in a different repo
			repo := fmt.Sprintf("%s/%s", refServerUrl.Host, repoName)
			referencedImage := fmt.Sprintf("%s@%s", indexName, mf.Digest.String())
			referrersResolver, err := oci.NewReferrersAttestationResolver(referencedImage, oci.WithReferrersRepo(repo))
			require.NoError(t, err)
			policyOpts := &policy.PolicyOptions{
				LocalPolicyDir: PassPolicyDir,
			}
			results, err := attest.Verify(ctx, policyOpts, referrersResolver)
			require.NoError(t, err)
			assert.Equal(t, attest.OutcomeSuccess, results.Outcome)
		}
	}
}
