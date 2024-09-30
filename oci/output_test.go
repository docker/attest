package oci_test

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/docker/attest/attestation"
	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/oci"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/stretchr/testify/require"
)

func TestSavingIndex(t *testing.T) {
	outputLayout := test.CreateTempDir(t, "", "mirror-test")
	attIdx, err := oci.IndexFromPath(test.UnsignedTestIndex(".."))
	require.NoError(t, err)

	ctx := context.Background()
	regServer := test.NewLocalRegistry(ctx)
	defer regServer.Close()

	u, err := url.Parse(regServer.URL)
	require.NoError(t, err)

	indexName := fmt.Sprintf("%s/repo:root", u.Host)
	output, err := oci.ParseImageSpecs(indexName)
	require.NoError(t, err)
	err = oci.SaveIndex(ctx, output, attIdx.Index, indexName)
	require.NoError(t, err)

	ociOutput, err := oci.ParseImageSpecs(oci.LocalPrefix + outputLayout)
	require.NoError(t, err)
	err = oci.SaveIndex(ctx, ociOutput, attIdx.Index, indexName)
	require.NoError(t, err)
}

func TestSavingImage(t *testing.T) {
	outputLayout := test.CreateTempDir(t, "", "mirror-test")

	img := empty.Image

	ctx := context.Background()
	regServer := test.NewLocalRegistry(ctx)
	defer regServer.Close()

	u, err := url.Parse(regServer.URL)
	require.NoError(t, err)

	indexName := fmt.Sprintf("%s/repo:root", u.Host)
	output, err := oci.ParseImageSpec(indexName)
	require.NoError(t, err)
	err = oci.SaveImage(ctx, output, img, indexName)
	require.NoError(t, err)

	ociOutput, err := oci.ParseImageSpec(oci.LocalPrefix + outputLayout)
	require.NoError(t, err)
	err = oci.SaveImage(ctx, ociOutput, img, indexName)
	require.NoError(t, err)
}

func TestSavingReferrers(t *testing.T) {
	ctx, signer := test.Setup(t)
	opts := &attestation.SigningOptions{}
	statement := &intoto.Statement{
		StatementHeader: intoto.StatementHeader{
			PredicateType: attestation.VSAPredicateType,
		},
	}

	digest, err := v1.NewHash(test.UnsignedLinuxAMD64ImageDigest)
	require.NoError(t, err)
	subject := &v1.Descriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    digest,
	}
	manifest, err := attestation.NewManifest(subject)
	require.NoError(t, err)
	err = manifest.Add(ctx, signer, statement, opts)
	require.NoError(t, err)
	regServer := test.NewLocalRegistry(ctx, registry.WithReferrersSupport(true))
	defer regServer.Close()

	u, err := url.Parse(regServer.URL)
	require.NoError(t, err)

	indexName := fmt.Sprintf("%s/repo:root", u.Host)
	output, err := oci.ParseImageSpecs(indexName)
	require.NoError(t, err)
	artifacts, err := manifest.BuildReferringArtifacts()
	require.NoError(t, err)
	err = oci.SaveImagesNoTag(ctx, artifacts, output)
	require.NoError(t, err)

	reg := &attestation.MockRegistryResolver{
		Subject:      subject,
		MockResolver: &attestation.MockResolver{},
		ImageNameStr: indexName,
	}
	require.NoError(t, err)
	refResolver, err := attestation.NewReferrersResolver(reg)
	require.NoError(t, err)
	attestations, err := refResolver.Attestations(ctx, attestation.VSAPredicateType)
	require.NoError(t, err)
	require.Len(t, attestations, 1)
}
