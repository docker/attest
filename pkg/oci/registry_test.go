package oci_test

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestRegistry(t *testing.T) {
	ctx, signer := test.Setup(t)
	server := httptest.NewServer(registry.New(registry.WithReferrersSupport(false)))
	defer server.Close()
	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	opts := &attestation.SigningOptions{}
	attIdx, err := oci.IndexFromPath(oci.UnsignedTestImage)
	require.NoError(t, err)
	signedManifests, err := attest.SignStatements(ctx, attIdx.Index, signer, opts)
	require.NoError(t, err)
	signedIndex := attIdx.Index
	signedIndex, err = attestation.UpdateIndexImages(signedIndex, signedManifests)
	require.NoError(t, err)

	indexName := fmt.Sprintf("%s/repo:root", u.Host)
	require.NoError(t, err)
	err = mirror.PushIndexToRegistry(signedIndex, indexName)
	require.NoError(t, err)

	spec, err := oci.ParseImageSpec(indexName)
	require.NoError(t, err)

	resolver, err := policy.CreateImageDetailsResolver(spec)
	require.NoError(t, err)
	desc, err := resolver.ImageDescriptor(ctx)
	require.NoError(t, err)
	digest := desc.Digest.String()
	assert.True(t, strings.Contains(digest, "sha256:"))
}
