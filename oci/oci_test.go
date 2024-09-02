package oci_test

import (
	"testing"

	"github.com/distribution/reference"
	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/oci"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefToPurl(t *testing.T) {
	arm, err := oci.ParsePlatform("arm64/linux")
	require.NoError(t, err)
	ref, err := reference.ParseNormalizedNamed("alpine")
	require.NoError(t, err)
	purl, canonical, err := oci.RefToPURL(ref, arm)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/alpine@latest?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)
	ref, err = reference.ParseNormalizedNamed("alpine:123")
	require.NoError(t, err)
	purl, canonical, err = oci.RefToPURL(ref, arm)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/alpine@123?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)
	ref, err = reference.ParseNormalizedNamed("google/alpine:123")
	require.NoError(t, err)
	purl, canonical, err = oci.RefToPURL(ref, arm)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/google/alpine@123?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)
	ref, err = reference.ParseNormalizedNamed("library/alpine:123")
	require.NoError(t, err)
	purl, canonical, err = oci.RefToPURL(ref, arm)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/alpine@123?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)
	ref, err = reference.ParseNormalizedNamed("docker.io/library/alpine:123")
	require.NoError(t, err)
	purl, canonical, err = oci.RefToPURL(ref, arm)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/alpine@123?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)
	ref, err = reference.ParseNormalizedNamed("localhost:5001/library/alpine:123")
	require.NoError(t, err)
	purl, canonical, err = oci.RefToPURL(ref, arm)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/localhost%3A5001/library/alpine@123?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)
	ref, err = reference.ParseNormalizedNamed("localhost:5001/alpine:123")
	require.NoError(t, err)
	purl, canonical, err = oci.RefToPURL(ref, arm)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/localhost%3A5001/alpine@123?platform=arm64%2Flinux", purl)
	assert.False(t, canonical)
	ref, err = reference.ParseNormalizedNamed("localhost:5001/alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b")
	require.NoError(t, err)
	purl, canonical, err = oci.RefToPURL(ref, arm)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:docker/localhost%3A5001/alpine?digest=sha256%3Ac5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b&platform=arm64%2Flinux", purl)
	assert.True(t, canonical)
}

// Test fix for https://github.com/docker/secure-artifacts-team-issues/issues/202
func TestImageDigestForPlatform(t *testing.T) {
	idx, err := layout.ImageIndexFromPath(test.UnsignedTestImage(".."))
	assert.NoError(t, err)

	idxm, err := idx.IndexManifest()
	assert.NoError(t, err)

	idxDescriptor := idxm.Manifests[0]
	idxDigest := idxDescriptor.Digest

	mfs, err := idx.ImageIndex(idxDigest)
	assert.NoError(t, err)
	mfs2, err := mfs.IndexManifest()
	assert.NoError(t, err)

	p, err := oci.ParsePlatform("linux/amd64")
	assert.NoError(t, err)
	desc, err := oci.ImageDescriptor(mfs2, p)
	assert.NoError(t, err)
	digest := desc.Digest.String()
	assert.Equal(t, "sha256:da8b190665956ea07890a0273e2a9c96bfe291662f08e2860e868eef69c34620", digest)

	p, err = oci.ParsePlatform("linux/arm64")
	assert.NoError(t, err)
	desc, err = oci.ImageDescriptor(mfs2, p)
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
		{name: oci.RegistryPrefix + "image:tag", expected: oci.RegistryPrefix + "index.docker.io/library/image"},
		{name: "image@sha256:166710df254975d4a6c4c407c315951c22753dcaa829e020a3fd5d18fff70dd2", expected: "index.docker.io/library/image"},
		{name: oci.RegistryPrefix + "image@sha256:166710df254975d4a6c4c407c315951c22753dcaa829e020a3fd5d18fff70dd2", expected: oci.RegistryPrefix + "index.docker.io/library/image"},
		{name: oci.RegistryPrefix + "127.0.0.1:36555/repo:latest", expected: oci.RegistryPrefix + "127.0.0.1:36555/repo"},
	}
	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			notag, _ := oci.WithoutTag(c.name)
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
		{name: oci.RegistryPrefix + "image:tag", expected: oci.RegistryPrefix + "index.docker.io/library/image:sha256-digest.att"},
		{name: "image@sha256:166710df254975d4a6c4c407c315951c22753dcaa829e020a3fd5d18fff70dd2", expected: "index.docker.io/library/image:sha256-digest.att"},
		{name: oci.LocalPrefix + "foobar", expected: oci.LocalPrefix + "foobar"},
		{name: oci.RegistryPrefix + "image@sha256:166710df254975d4a6c4c407c315951c22753dcaa829e020a3fd5d18fff70dd2", expected: oci.RegistryPrefix + "index.docker.io/library/image:sha256-digest.att"},
		{name: oci.RegistryPrefix + "127.0.0.1:36555/repo:latest", expected: oci.RegistryPrefix + "127.0.0.1:36555/repo:sha256-digest.att"},
	}

	digest := v1.Hash{
		Algorithm: "sha256",
		Hex:       "digest",
	}
	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			replaced, err := oci.ReplaceTag(c.name, digest)
			require.NoError(t, err)
			assert.Equal(t, c.expected, replaced)
		})
	}
}
