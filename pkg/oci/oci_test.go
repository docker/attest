package oci

import (
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefToPurl(t *testing.T) {
	arm, err := ParsePlatform("arm64/linux")
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

var UnsignedTestImage = filepath.Join("..", "..", "test", "testdata", "unsigned-test-image")

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

	p, err := ParsePlatform("linux/amd64")
	assert.NoError(t, err)
	desc, err := imageDescriptor(mfs2, p)
	assert.NoError(t, err)
	digest := desc.Digest.String()
	assert.Equal(t, "sha256:da8b190665956ea07890a0273e2a9c96bfe291662f08e2860e868eef69c34620", digest)

	p, err = ParsePlatform("linux/arm64")
	assert.NoError(t, err)
	desc, err = imageDescriptor(mfs2, p)
	assert.NoError(t, err)
	digest = desc.Digest.String()
	assert.Equal(t, "sha256:7a76cec943853f9f7105b1976afa1bf7cd5bb6afc4e9d5852dd8da7cf81ae86e", digest)
}

func TestWithoutTag(t *testing.T) {
	tc := []struct {
		name     string
		expected string
	}{
		{name: "image:tag", expected: "index.docker.io/library/image"},
		{name: "image", expected: "index.docker.io/library/image"},
		{name: "image:sha256-digest.att", expected: "index.docker.io/library/image"},
		{name: RegistryPrefix + "image:tag", expected: RegistryPrefix + "index.docker.io/library/image"},
		{name: "image@sha256:166710df254975d4a6c4c407c315951c22753dcaa829e020a3fd5d18fff70dd2", expected: "index.docker.io/library/image"},
		{name: RegistryPrefix + "image@sha256:166710df254975d4a6c4c407c315951c22753dcaa829e020a3fd5d18fff70dd2", expected: RegistryPrefix + "index.docker.io/library/image"},
		{name: RegistryPrefix + "127.0.0.1:36555/repo:latest", expected: RegistryPrefix + "127.0.0.1:36555/repo"},
	}
	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			notag, _ := WithoutTag(c.name)
			assert.Equal(t, c.expected, notag)
		})
	}
}

func TestReplaceTag(t *testing.T) {
	tc := []struct {
		name     string
		expected string
	}{
		{name: "image:tag", expected: "index.docker.io/library/image:sha256-digest.att"},
		{name: "image", expected: "index.docker.io/library/image:sha256-digest.att"},
		{name: "image:sha256-digest.att", expected: "index.docker.io/library/image:sha256-digest.att"},
		{name: RegistryPrefix + "image:tag", expected: RegistryPrefix + "index.docker.io/library/image:sha256-digest.att"},
		{name: "image@sha256:166710df254975d4a6c4c407c315951c22753dcaa829e020a3fd5d18fff70dd2", expected: "index.docker.io/library/image:sha256-digest.att"},
		{name: LocalPrefix + "foobar", expected: LocalPrefix + "foobar"},
		{name: RegistryPrefix + "image@sha256:166710df254975d4a6c4c407c315951c22753dcaa829e020a3fd5d18fff70dd2", expected: RegistryPrefix + "index.docker.io/library/image:sha256-digest.att"},
		{name: RegistryPrefix + "127.0.0.1:36555/repo:latest", expected: RegistryPrefix + "127.0.0.1:36555/repo:sha256-digest.att"},
	}

	digest := v1.Hash{
		Algorithm: "sha256",
		Hex:       "digest",
	}
	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			replaced, err := replaceTag(c.name, digest)
			require.NoError(t, err)
			assert.Equal(t, c.expected, replaced)
		})
	}
}
