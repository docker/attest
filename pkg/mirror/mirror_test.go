package mirror

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/pkg/attest"
	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/oci"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/stretchr/testify/require"
)

func TestSavingIndex(t *testing.T) {
	UnsignedTestImage := filepath.Join("..", "..", "test", "testdata", "unsigned-test-image")
	outputLayout := test.CreateTempDir(t, "", "mirror-test")
	attIdx, err := oci.IndexFromPath(UnsignedTestImage)
	require.NoError(t, err)

	server := httptest.NewServer(registry.New())
	defer server.Close()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	indexName := fmt.Sprintf("%s/repo:root", u.Host)
	output, err := oci.ParseImageSpecs(indexName)
	require.NoError(t, err)
	err = SaveIndex(output, attIdx.Index, indexName)
	require.NoError(t, err)

	ociOutput, err := oci.ParseImageSpecs("oci://" + outputLayout)
	require.NoError(t, err)
	err = SaveIndex(ociOutput, attIdx.Index, indexName)
	require.NoError(t, err)
}

func TestSavingImage(t *testing.T) {
	outputLayout := test.CreateTempDir(t, "", "mirror-test")

	img := empty.Image

	server := httptest.NewServer(registry.New())
	defer server.Close()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	indexName := fmt.Sprintf("%s/repo:root", u.Host)
	output, err := oci.ParseImageSpec(indexName)
	require.NoError(t, err)
	err = SaveImage(output, img, indexName)
	require.NoError(t, err)

	ociOutput, err := oci.ParseImageSpec("oci://" + outputLayout)
	require.NoError(t, err)
	err = SaveImage(ociOutput, img, indexName)
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

	digest, err := v1.NewHash("sha256:da8b190665956ea07890a0273e2a9c96bfe291662f08e2860e868eef69c34620")
	require.NoError(t, err)
	subject := &v1.Descriptor{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Digest:    digest,
	}
	manifest, err := attest.NewAttestationManifest(subject)
	require.NoError(t, err)
	err = manifest.AddAttestation(ctx, signer, statement, opts)
	require.NoError(t, err)
	server := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	defer server.Close()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	indexName := fmt.Sprintf("%s/repo:root", u.Host)
	output, err := oci.ParseImageSpecs(indexName)
	require.NoError(t, err)
	err = SaveReferrers(manifest, output)
	require.NoError(t, err)

	reg := &test.MockRegistryResolver{
		Subject:      subject,
		MockResolver: &test.MockResolver{},
		ImageNameStr: indexName,
	}
	require.NoError(t, err)
	refResolver, err := oci.NewReferrersAttestationResolver(reg)
	require.NoError(t, err)
	attestations, err := refResolver.Attestations(ctx, attestation.VSAPredicateType)
	require.NoError(t, err)
	require.Len(t, attestations, 1)
}
