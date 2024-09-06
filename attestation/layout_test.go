package attestation_test

import (
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
	attIdx, err := oci.IndexFromPath(test.UnsignedTestImage(".."))
	require.NoError(t, err)
	signedManifests, err := attest.SignStatements(ctx, attIdx.Index, signer, opts)
	require.NoError(t, err)
	signedIndex := attIdx.Index
	signedIndex, err = attestation.UpdateIndexImages(signedIndex, signedManifests)
	require.NoError(t, err)
	spec, err := oci.ParseImageSpec(oci.LocalPrefix + outputLayout)
	require.NoError(t, err)
	err = oci.SaveIndex(ctx, []*oci.ImageSpec{spec}, signedIndex, outputLayout)
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
