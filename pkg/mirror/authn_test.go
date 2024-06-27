//go:build e2e

package mirror_test

import (
	"path/filepath"
	"testing"

	"github.com/docker/attest/pkg/mirror"
	"github.com/docker/attest/pkg/oci"
	"github.com/stretchr/testify/require"
)

func TestRegistryAuth(t *testing.T) {
	UnsignedTestImage := filepath.Join("..", "..", "test", "testdata", "unsigned-test-image")

	attIdx, err := oci.SubjectIndexFromPath(UnsignedTestImage)
	require.NoError(t, err)
	// test cases for ecr, gcr and dockerhub
	testCases := []struct {
		Image string
	}{
		{Image: "175142243308.dkr.ecr.us-east-1.amazonaws.com/e2e-test-image:latest"},
		{Image: "docker/image-signer-verifier-test:latest"},
	}
	for _, tc := range testCases {
		t.Run(tc.Image, func(t *testing.T) {
			err := mirror.PushIndexToRegistry(attIdx.Index, tc.Image)
			require.NoError(t, err)
			_, err = oci.SubjectIndexFromRemote(tc.Image)
			require.NoError(t, err)
		})
	}
}
