package tuf

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/attest/internal/embed"
	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

var (
	HttpTufTestDataPath = filepath.Join("..", "..", "test", "testdata", "tuf", "test-repo")
	OciTufTestDataPath  = filepath.Join("..", "..", "test", "testdata", "tuf", "test-repo-oci")
)

func CreateTempDir(t *testing.T, dir, pattern string) string {
	// Create a temporary directory for output oci layout
	tempDir, err := os.MkdirTemp(dir, pattern)
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Register a cleanup function to delete the temp directory when the test exits
	t.Cleanup(func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Errorf("Failed to remove temp directory: %v", err)
		}
	})
	return tempDir
}

// NewTufClient creates a new TUF client
func TestRootInit(t *testing.T) {
	tufPath := CreateTempDir(t, "", "tuf_temp")

	// Start a test HTTP server to serve data from /test/testdata/tuf/test-repo/ paths
	server := httptest.NewServer(http.FileServer(http.Dir(HttpTufTestDataPath)))
	defer server.Close()

	// run local registry
	registry, regAddr := RunTestRegistry(t)
	defer func() {
		if err := registry.Terminate(context.Background()); err != nil {
			t.Fatalf("failed to terminate container: %s", err) // nolint:gocritic
		}
	}()
	LoadRegistryTestData(t, regAddr, OciTufTestDataPath)

	testCases := []struct {
		name           string
		metadataSource string
		targetsSource  string
	}{
		{"http", server.URL + "/metadata", server.URL + "/targets"},
		{"oci", regAddr.Host + "/tuf-metadata:latest", regAddr.Host + "/tuf-targets"},
	}

	for _, tc := range testCases {
		_, err := NewTufClient(embed.DevRoot, tufPath, tc.metadataSource, tc.targetsSource)
		assert.NoErrorf(t, err, "Failed to create TUF client: %v", err)

		// recreation should work with same root
		_, err = NewTufClient(embed.DevRoot, tufPath, tc.metadataSource, tc.targetsSource)
		assert.NoErrorf(t, err, "Failed to recreate TUF client: %v", err)

		_, err = NewTufClient([]byte("broken"), tufPath, tc.metadataSource, tc.targetsSource)
		assert.Errorf(t, err, "Expected error recreating TUF client with broken root: %v", err)
	}
}

func TestDownloadTarget(t *testing.T) {
	tufPath := CreateTempDir(t, "", "tuf_temp")
	targetFile := "test.txt"
	delegatedRole := "test-role"
	delegatedTargetFile := fmt.Sprintf("%s/%s", delegatedRole, targetFile)

	// Start a test HTTP server to serve data from /test/testdata/tuf/test-repo/ paths
	server := httptest.NewServer(http.FileServer(http.Dir(HttpTufTestDataPath)))
	defer server.Close()

	// run local registry
	registry, regAddr := RunTestRegistry(t)
	defer func() {
		if err := registry.Terminate(context.Background()); err != nil {
			t.Fatalf("failed to terminate container: %s", err) // nolint:gocritic
		}
	}()
	LoadRegistryTestData(t, regAddr, OciTufTestDataPath)

	testCases := []struct {
		name           string
		metadataSource string
		targetsSource  string
	}{
		{"http", server.URL + "/metadata", server.URL + "/targets"},
		{"oci", regAddr.Host + "/tuf-metadata:latest", regAddr.Host + "/tuf-targets"},
	}

	for _, tc := range testCases {
		tufClient, err := NewTufClient(embed.DevRoot, tufPath, tc.metadataSource, tc.targetsSource)
		assert.NoErrorf(t, err, "Failed to create TUF client: %v", err)

		// get trusted tuf metadata
		trustedMetadata := tufClient.updater.GetTrustedMetadataSet()
		assert.NotNil(t, trustedMetadata, "Failed to get trusted metadata")

		// download top-level target files
		targets := trustedMetadata.Targets[metadata.TARGETS].Signed.Targets
		for _, target := range targets {
			// download target files
			_, _, err := tufClient.DownloadTarget(target.Path, filepath.Join(tufPath, "download"))
			assert.NoErrorf(t, err, "Failed to download target: %v", err)
		}

		// download delegated target
		targetInfo, err := tufClient.updater.GetTargetInfo(delegatedTargetFile)
		assert.NoError(t, err)
		_, _, err = tufClient.DownloadTarget(targetInfo.Path, filepath.Join(tufPath, targetInfo.Path))
		assert.NoError(t, err)
	}
}
