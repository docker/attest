package oci

import (
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefToPurl(t *testing.T) {
	arm, err := parsePlatform("arm64/linux")
	require.NoError(t, err)
	purl, canonical, err := RefToPURL("alpine", arm)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/alpine@latest?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)

	purl, canonical, err = RefToPURL("alpine:123", arm)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/alpine@123?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)

	purl, canonical, err = RefToPURL("google/alpine:123", arm)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/google/alpine@123?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)

	purl, canonical, err = RefToPURL("library/alpine:123", arm)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/alpine@123?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)

	purl, canonical, err = RefToPURL("docker.io/library/alpine:123", arm)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/alpine@123?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)

	purl, canonical, err = RefToPURL("localhost:5001/library/alpine:123", arm)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/localhost%3A5001/library/alpine@123?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)

	purl, canonical, err = RefToPURL("localhost:5001/alpine:123", arm)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/localhost%3A5001/alpine@123?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)

	purl, canonical, err = RefToPURL("localhost:5001/alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b", arm)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/localhost%3A5001/alpine?digest=sha256%3Ac5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b&platform=arm64%2Flinux", purl)
	assert.True(t, canonical)
}

var (
	UnsignedTestImage = filepath.Join("..", "..", "test", "testdata", "unsigned-test-image")
)

// Test fix for https://github.com/docker/secure-artifacts-team-issues/issues/202
func TestImageDigestForPlatform(t *testing.T) {
	idx, err := layout.ImageIndexFromPath(UnsignedTestImage)
	assert.NoError(t, err)

	idxm, err := idx.IndexManifest()
	assert.NoError(t, err)

	idxDescriptor := idxm.Manifests[0]
	idxDigest := idxDescriptor.Digest

	mfs, err := idx.ImageIndex(idxDigest)
	assert.NoError(t, err)
	mfs2, err := mfs.IndexManifest()
	assert.NoError(t, err)

	p, err := parsePlatform("linux/amd64")
	assert.NoError(t, err)
	digest, err := imageDigestForPlatform(mfs2, p)
	assert.NoError(t, err)
	assert.Equal(t, "sha256:da8b190665956ea07890a0273e2a9c96bfe291662f08e2860e868eef69c34620", digest)

	p, err = parsePlatform("linux/arm64")
	assert.NoError(t, err)
	digest, err = imageDigestForPlatform(mfs2, p)
	assert.NoError(t, err)
	assert.Equal(t, "sha256:7a76cec943853f9f7105b1976afa1bf7cd5bb6afc4e9d5852dd8da7cf81ae86e", digest)
}
