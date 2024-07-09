package mirror

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/pkg/oci"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/stretchr/testify/require"
)

func TestSavingIndex(t *testing.T) {
	UnsignedTestImage := filepath.Join("..", "..", "test", "testdata", "unsigned-test-image")
	outputLayout := test.CreateTempDir(t, "", "mirror-test")
	attIdx, err := oci.IndexFromPath(UnsignedTestImage)
	require.NoError(t, err)

	server := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	defer server.Close()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	indexName := fmt.Sprintf("%s/repo:root", u.Host)
	output, err := oci.ParseImageSpecs(indexName)
	require.NoError(t, err)
	err = SaveIndex(output, attIdx.Index, indexName)
	require.NoError(t, err)

	ociOutput, err := oci.ParseImageSpecs("oci://" + outputLayout)
	err = SaveIndex(ociOutput, attIdx.Index, indexName)
	require.NoError(t, err)
}

func TestSavingImage(t *testing.T) {

	outputLayout := test.CreateTempDir(t, "", "mirror-test")

	img := empty.Image

	server := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	defer server.Close()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	indexName := fmt.Sprintf("%s/repo:root", u.Host)
	output, err := oci.ParseImageSpec(indexName)
	require.NoError(t, err)
	err = SaveImage(output, img, indexName)
	require.NoError(t, err)

	ociOutput, err := oci.ParseImageSpec("oci://" + outputLayout)
	err = SaveImage(ociOutput, img, indexName)
	require.NoError(t, err)
}
