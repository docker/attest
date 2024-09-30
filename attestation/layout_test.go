package attestation_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/docker/attest"
	"github.com/docker/attest/attestation"
	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/oci"
	"github.com/docker/attest/policy"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttestationFromOCILayout(t *testing.T) {
	ctx, signer := test.Setup(t)
	outputLayout := test.CreateTempDir(t, "", "attest-oci-layout")

	invalidPlatform := &v1.Platform{
		Architecture: "invalid",
		OS:           "invalid",
	}

	opts := &attestation.SigningOptions{}
	attIdx, err := oci.IndexFromPath(test.UnsignedTestIndex(".."))
	require.NoError(t, err)
	signedManifests, err := attest.SignStatements(ctx, attIdx.Index, signer, opts)
	require.NoError(t, err)
	signedIndex := attIdx.Index
	signedIndex, err = attestation.UpdateIndexImages(signedIndex, signedManifests)
	require.NoError(t, err)
	spec, err := oci.ParseImageSpec(oci.LocalPrefix + outputLayout)
	require.NoError(t, err)
	err = oci.SaveIndex(ctx, []*oci.ImageSpec{spec}, signedIndex, "docker.io/library/test-image:test")
	require.NoError(t, err)

	testCases := []struct {
		name     string
		platform *v1.Platform
		errorStr string
	}{
		{name: "nominal", platform: spec.Platform},
		{name: "invalid platform", platform: invalidPlatform, errorStr: "platform not found in index"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			spec := &oci.ImageSpec{
				Type:       oci.OCI,
				Identifier: outputLayout,
				Platform:   tc.platform,
			}
			resolver, err := policy.CreateImageDetailsResolver(spec)
			if tc.errorStr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorStr)
				return
			}
			require.NoError(t, err)
			desc, err := resolver.ImageDescriptor(ctx)
			require.NoError(t, err)
			digest := desc.Digest.String()
			assert.True(t, strings.Contains(digest, "sha256:"))
		})
	}
}

func TestSubjectNameAnnotations(t *testing.T) {
	testCases := []struct {
		name          string
		ociLayoutPath string
		errorStr      string
	}{
		{name: "oci annotation", ociLayoutPath: test.UnsignedTestIndex("..")},
		{name: "containerd annotation", ociLayoutPath: filepath.Join("..", "test", "testdata", "containerd-subject-layout")},
		{name: "missing subject name", ociLayoutPath: filepath.Join("..", "test", "testdata", "missing-subject-layout"), errorStr: "failed to find subject name in annotations"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := oci.ParseImageSpec(oci.LocalPrefix+tc.ociLayoutPath, oci.WithPlatform("linux/arm64"))
			require.NoError(t, err)
			_, err = policy.CreateImageDetailsResolver(spec)
			if tc.errorStr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorStr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestImageDetailsFromImageLayout(t *testing.T) {
	spec, err := oci.ParseImageSpec(oci.LocalPrefix+test.UnsignedTestImage(".."), oci.WithPlatform("linux/arm64"))
	require.NoError(t, err)
	resolver, err := policy.CreateImageDetailsResolver(spec)
	require.NoError(t, err)
	desc, err := resolver.ImageDescriptor(context.Background())
	require.NoError(t, err)
	digest := desc.Digest.String()
	assert.Equal(t, "sha256:7ae6b41655929ad8e1848064874a98ac3f68884996c79907f6525e3045f75390", digest)
}
