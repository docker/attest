package tuf

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

var (
	HTTPTUFTestDataPath = filepath.Join("..", "..", "test", "testdata", "tuf", "test-repo")
	OCITUFTestDataPath  = filepath.Join("..", "..", "test", "testdata", "tuf", "test-repo-oci")
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

// NewTufClient creates a new TUF client.
func TestRootInit(t *testing.T) {
	tufPath := CreateTempDir(t, "", "tuf_temp")

	// Start a test HTTP server to serve data from /test/testdata/tuf/test-repo/ paths
	server := httptest.NewServer(http.FileServer(http.Dir(HTTPTUFTestDataPath)))
	defer server.Close()

	// run local registry
	registry, regAddr := RunTestRegistry(t)
	defer func() {
		if err := registry.Terminate(context.Background()); err != nil {
			t.Fatalf("failed to terminate container: %s", err) // nolint:gocritic
		}
	}()
	LoadRegistryTestData(t, regAddr, OCITUFTestDataPath)

	alwaysGoodVersionChecker := &MockVersionChecker{err: nil}
	alwaysBadVersionChecker := &MockVersionChecker{err: assert.AnError}

	testCases := []struct {
		name           string
		metadataSource string
		targetsSource  string
	}{
		{"http", server.URL + "/metadata", server.URL + "/targets"},
		{"oci", regAddr.Host + "/tuf-metadata:latest", regAddr.Host + "/tuf-targets"},
	}

	for _, tc := range testCases {
		_, err := NewClient(&ClientOptions{DockerTUFRootDev.Data, tufPath, tc.metadataSource, tc.targetsSource, alwaysGoodVersionChecker})
		assert.NoErrorf(t, err, "Failed to create TUF client: %v", err)

		// recreation should work with same root
		_, err = NewClient(&ClientOptions{DockerTUFRootDev.Data, tufPath, tc.metadataSource, tc.targetsSource, alwaysGoodVersionChecker})
		assert.NoErrorf(t, err, "Failed to recreate TUF client: %v", err)

		_, err = NewClient(&ClientOptions{[]byte("broken"), tufPath, tc.metadataSource, tc.targetsSource, alwaysGoodVersionChecker})
		assert.Errorf(t, err, "Expected error recreating TUF client with broken root: %v", err)

		_, err = NewClient(&ClientOptions{DockerTUFRootDev.Data, tufPath, tc.metadataSource, tc.targetsSource, alwaysBadVersionChecker})
		assert.Errorf(t, err, "Expected error recreating TUF client with bad version checker")
	}
}

func TestDownloadTarget(t *testing.T) {
	tufPath := CreateTempDir(t, "", "tuf_temp")
	targetFile := "test.txt"
	delegatedRole := testRole
	delegatedTargetFile := fmt.Sprintf("%s/%s", delegatedRole, targetFile)

	// Start a test HTTP server to serve data from /test/testdata/tuf/test-repo/ paths
	server := httptest.NewServer(http.FileServer(http.Dir(HTTPTUFTestDataPath)))
	defer server.Close()

	// run local registry
	registry, regAddr := RunTestRegistry(t)
	defer func() {
		if err := registry.Terminate(context.Background()); err != nil {
			t.Fatalf("failed to terminate container: %s", err) // nolint:gocritic
		}
	}()
	LoadRegistryTestData(t, regAddr, OCITUFTestDataPath)

	alwaysGoodVersionChecker := &MockVersionChecker{err: nil}

	testCases := []struct {
		name           string
		metadataSource string
		targetsSource  string
	}{
		{"http", server.URL + "/metadata", server.URL + "/targets"},
		{"oci", regAddr.Host + "/tuf-metadata:latest", regAddr.Host + "/tuf-targets"},
		{"http, download before init", server.URL + "/metadata", server.URL + "/targets"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tufClient, err := NewClient(&ClientOptions{DockerTUFRootDev.Data, tufPath, tc.metadataSource, tc.targetsSource, alwaysGoodVersionChecker})
			require.NoErrorf(t, err, "Failed to create TUF client: %v", err)
			require.NotNil(t, tufClient.updater, "Failed to create updater")

			// get trusted tuf metadata
			trustedMetadata := tufClient.updater.GetTrustedMetadataSet()
			assert.NotNil(t, trustedMetadata, "Failed to get trusted metadata")

			// download top-level target files
			targets := trustedMetadata.Targets[metadata.TARGETS].Signed.Targets
			for _, target := range targets {
				// download target files
				_, err := tufClient.DownloadTarget(target.Path, filepath.Join(tufPath, "download"))
				assert.NoErrorf(t, err, "Failed to download target: %v", err)
			}

			// download delegated target
			targetInfo, err := tufClient.updater.GetTargetInfo(delegatedTargetFile)
			require.NoError(t, err)
			_, err = tufClient.DownloadTarget(targetInfo.Path, filepath.Join(tufPath, targetInfo.Path))
			assert.NoError(t, err)
		})
	}
}

func TestGetEmbeddedTufRootBytes(t *testing.T) {
	dev, err := GetEmbeddedRoot("dev")
	assert.NoError(t, err)

	staging, err := GetEmbeddedRoot("staging")
	assert.NoError(t, err)
	assert.NotEqual(t, dev.Data, staging.Data)

	prod, err := GetEmbeddedRoot("prod")
	assert.NoError(t, err)
	assert.NotEqual(t, dev.Data, prod.Data)
	assert.NotEqual(t, staging.Data, prod.Data)

	def, err := GetEmbeddedRoot("")
	assert.NoError(t, err)
	assert.Equal(t, def.Data, prod.Data)

	_, err = GetEmbeddedRoot("invalid")
	assert.Error(t, err)
}
