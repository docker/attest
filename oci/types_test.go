package oci

import (
	"testing"

	"github.com/docker/attest/internal/util"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmptyConfigImageDigest(t *testing.T) {
	empty := empty.Image
	img := EmptyConfigImage{Image: empty}
	mf, err := img.RawManifest()
	require.NoError(t, err)
	hash := util.SHA256Hex(mf)
	digest, err := img.Digest()
	require.NoError(t, err)
	assert.Equal(t, digest.Hex, hash)
}
