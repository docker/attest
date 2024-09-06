package attestation_test

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/docker/attest"
	"github.com/docker/attest/attestation"
	"github.com/docker/attest/config"
	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/oci"
	"github.com/docker/attest/policy"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	NoProvenanceImage   = filepath.Join("..", "test", "testdata", "no-provenance-image")
	PassPolicyDir       = filepath.Join("..", "test", "testdata", "local-policy-pass")
	LocalPolicy         = filepath.Join("..", "test", "testdata", "local-policy")
	LocalPolicyAttached = filepath.Join("..", "test", "testdata", "local-policy-attached")
	PassNoTLPolicyDir   = filepath.Join("..", "test", "testdata", "local-policy-no-tl")
	FailPolicyDir       = filepath.Join("..", "test", "testdata", "local-policy-fail")
	TestTempDir         = "attest-sign-test"
)

func TestAttestationReferenceTypes(t *testing.T) {
	ctx, signer := test.Setup(t)
	platforms := []string{"linux/amd64", "linux/arm64"}
	for _, tc := range []struct {
		name              string
		server            *httptest.Server
		referrersServer   *httptest.Server
		useDigest         bool
		referrersRepo     string
		attestationSource config.AttestationStyle
		expectFailure     bool
	}{
		{
			name:   "referrers support, defaults",
			server: test.TestRegistry(ctx, t, registry.WithReferrersSupport(true)),
		},
		{
			name:      "use digest",
			server:    test.TestRegistry(ctx, t, registry.WithReferrersSupport(true)),
			useDigest: true,
		},
		{
			name:              "attached attestations, referrers repo (mismatched args)",
			server:            test.TestRegistry(ctx, t, registry.WithReferrersSupport(true)),
			expectFailure:     true, // mismatched args
			attestationSource: config.AttestationStyleAttached,
			referrersRepo:     "referrers",
		},
		{
			name:              "referrers attestations, referrers repo (no policy)",
			server:            test.TestRegistry(ctx, t, registry.WithReferrersSupport(true)),
			expectFailure:     true, // no policy
			attestationSource: config.AttestationStyleReferrers,
			referrersRepo:     "referrers",
		},
		{
			name:              "referrers attestations",
			server:            test.TestRegistry(ctx, t, registry.WithReferrersSupport(true)),
			attestationSource: config.AttestationStyleReferrers,
		},
		{
			name:   "referrers attestations, no referrers support on server",
			server: test.TestRegistry(ctx, t, registry.WithReferrersSupport(false)),

			attestationSource: config.AttestationStyleReferrers,
			referrersServer:   test.TestRegistry(ctx, t, registry.WithReferrersSupport(true)),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.server
			defer s.Close()

			if tc.referrersServer != nil {
				defer tc.referrersServer.Close()
			}
			u, err := url.Parse(s.URL)
			require.NoError(t, err)

			opts := &attestation.SigningOptions{
				SkipTL: true,
			}
			attIdx, err := oci.IndexFromPath(test.UnsignedTestImage(".."))
			require.NoError(t, err)

			indexName := fmt.Sprintf("%s/repo:root", u.Host)
			require.NoError(t, err)

			outputRepo := indexName
			if tc.referrersServer != nil {
				ru, err := url.Parse(s.URL)
				require.NoError(t, err)
				tc.referrersRepo = fmt.Sprintf("%s/referrers", ru.Host)
				outputRepo = tc.referrersRepo
			}
			// sign all the statements in the index
			signedManifests, err := attest.SignStatements(ctx, attIdx.Index, signer, opts)
			require.NoError(t, err)

			// push subject image so that it can be resolved
			require.NoError(t, err)
			err = oci.PushIndexToRegistry(ctx, attIdx.Index, indexName)
			require.NoError(t, err)

			// upload referrers
			output, err := oci.ParseImageSpec(outputRepo)
			require.NoError(t, err)
			for _, attIdx := range signedManifests {
				images, err := attIdx.BuildReferringArtifacts()
				require.NoError(t, err)
				err = oci.SaveImagesNoTag(ctx, images, []*oci.ImageSpec{output})
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

				policyOpts := &policy.Options{
					LocalPolicyDir: LocalPolicy,
					DisableTUF:     true,
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
				src, err = oci.ParseImageSpec(ref, oci.WithPlatform(platform))
				require.NoError(t, err)
				results, err = attest.Verify(ctx, src, policyOpts)
				require.NoError(t, err)
				assert.Equal(t, attest.OutcomeSuccess, results.Outcome)
			}
		})
	}
}

func TestReferencesInDifferentRepo(t *testing.T) {
	ctx, signer := test.Setup(t)
	repoName := "repo"
	for _, tc := range []struct {
		name      string
		server    *httptest.Server
		refServer *httptest.Server
	}{
		{
			name:      "referrers support",
			server:    test.TestRegistry(ctx, t, registry.WithReferrersSupport(true)),
			refServer: test.TestRegistry(ctx, t, registry.WithReferrersSupport(true)),
		},
		{
			name:      "no referrers support",
			server:    test.TestRegistry(ctx, t, registry.WithReferrersSupport(false)),
			refServer: test.TestRegistry(ctx, t, registry.WithReferrersSupport(true)),
		},
	} {
		server := tc.server
		defer server.Close()
		serverURL, err := url.Parse(server.URL)
		require.NoError(t, err)

		refServer := tc.refServer
		defer refServer.Close()
		refServerURL, err := url.Parse(refServer.URL)
		require.NoError(t, err)

		opts := &attestation.SigningOptions{
			SkipTL: true,
		}
		attIdx, err := oci.IndexFromPath(test.UnsignedTestImage(".."))
		require.NoError(t, err)

		indexName := fmt.Sprintf("%s/%s:latest", serverURL.Host, repoName)
		err = oci.PushIndexToRegistry(ctx, attIdx.Index, indexName)
		require.NoError(t, err)

		signedManifests, err := attest.SignStatements(ctx, attIdx.Index, signer, opts)
		require.NoError(t, err)

		// push signed attestation image to the ref server
		for _, signedManifest := range signedManifests {
			// push references using subject-digest.att convention
			image, err := signedManifest.BuildImage()
			require.NoError(t, err)
			err = oci.PushImageToRegistry(ctx, image, fmt.Sprintf("%s/%s:tag-does-not-matter", refServerURL.Host, repoName))
			require.NoError(t, err)

			refServer := tc.refServer
			defer refServer.Close()
			refServerURL, err := url.Parse(refServer.URL)
			require.NoError(t, err)

			opts := &attestation.SigningOptions{
				SkipTL: true,
			}
			attIdx, err := oci.IndexFromPath(test.UnsignedTestImage(".."))
			require.NoError(t, err)

			indexName := fmt.Sprintf("%s/%s:latest", serverURL.Host, repoName)
			err = oci.PushIndexToRegistry(ctx, attIdx.Index, indexName)
			require.NoError(t, err)

			signedManifests, err := attest.SignStatements(ctx, attIdx.Index, signer, opts)
			require.NoError(t, err)

			// push signed attestation image to the ref server
			for _, mf := range signedManifests {
				// push references using subject-digest.att convention
				imgs, err := mf.BuildReferringArtifacts()
				require.NoError(t, err)
				for _, img := range imgs {
					err = oci.PushImageToRegistry(ctx, img, fmt.Sprintf("%s/%s:tag-does-not-matter", refServerURL.Host, repoName))
					require.NoError(t, err)
				}
			}
			mfs2, err := attIdx.Index.IndexManifest()
			require.NoError(t, err)
			for _, mf := range mfs2.Manifests {
				// skip signed/unsigned attestations
				if mf.Annotations[attestation.DockerReferenceType] == attestation.AttestationManifestType {
					continue
				}
				// can evaluate policy using referrers in a different repo
				referencedImage := fmt.Sprintf("%s@%s", indexName, mf.Digest.String())
				policyOpts := &policy.Options{
					LocalPolicyDir: PassPolicyDir,
					DisableTUF:     true,
				}
				src, err := oci.ParseImageSpec(referencedImage)
				require.NoError(t, err)
				results, err := attest.Verify(ctx, src, policyOpts)
				require.NoError(t, err)
				assert.Equal(t, attest.OutcomeSuccess, results.Outcome)
			}
		}
	}
}

func TestCorrectArtifactTypeInTagFallback(t *testing.T) {
	ctx, signer := test.Setup(t)
	regServer := test.TestRegistry(ctx, t, registry.WithReferrersSupport(false))
	defer regServer.Close()
	serverURL, err := url.Parse(regServer.URL)
	require.NoError(t, err)

	repoName := "repo"

	opts := &attestation.SigningOptions{
		SkipTL: true,
	}
	attIdx, err := oci.IndexFromPath(test.UnsignedTestImage(".."))
	require.NoError(t, err)

	indexName := fmt.Sprintf("%s/%s:latest", serverURL.Host, repoName)
	err = oci.PushIndexToRegistry(ctx, attIdx.Index, indexName)
	require.NoError(t, err)

	signedManifests, err := attest.SignStatements(ctx, attIdx.Index, signer, opts)
	require.NoError(t, err)

	// this should create and maintain an index of referrers
	for _, mf := range signedManifests {
		imgs, err := mf.BuildReferringArtifacts()
		require.NoError(t, err)
		for _, img := range imgs {
			err = oci.PushImageToRegistry(ctx, img, fmt.Sprintf("%s/%s:tag-does-not-matter", serverURL.Host, repoName))
			require.NoError(t, err)
			mf, err := img.Manifest()
			require.NoError(t, err)
			subject := mf.Subject
			subjectRef, err := name.ParseReference(fmt.Sprintf("%s/%s:sha256-%s", serverURL.Host, repoName, subject.Digest.Hex))
			require.NoError(t, err)
			idx, err := remote.Index(subjectRef, oci.WithOptions(ctx, nil)...)
			require.NoError(t, err)
			imf, err := idx.IndexManifest()
			require.NoError(t, err)
			for _, m := range imf.Manifests {
				assert.Contains(t, m.ArtifactType, "application/vnd.in-toto")
				assert.Contains(t, m.ArtifactType, "+dsse")
			}
		}
	}
}
