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
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
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
	platforms := []string{"linux/amd64", "linux/arm64"}
	for _, tc := range []struct {
		server      *httptest.Server
		skipSubject bool
		useDigest   bool
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
		{
			server:    httptest.NewServer(registry.New(registry.WithReferrersSupport(true))),
			useDigest: true,
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
		require.NoError(t, err)
		err = mirror.PushToRegistry(signedIndex, indexName)

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
			resolver, err := oci.NewRegistryAttestationResolver(ref, platform)
			require.NoError(t, err)

			policyOpts := &policy.PolicyOptions{
				LocalPolicyDir: PassPolicyDir,
			}
			results, err := attest.Verify(ctx, policyOpts, resolver)
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
				referrersResolver, err := oci.NewReferrersAttestationResolver(ref, oci.WithPlatform(platform))
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
			err = mirror.PushToRegistry(img.Image, fmt.Sprintf("%s/%s:tag-does-not-matter", refServerUrl.Host, repoName))
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