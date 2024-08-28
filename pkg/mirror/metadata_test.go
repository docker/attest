package mirror

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/pkg/tuf"
	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const (
	metadataPath = "/metadata"
	targetsPath  = "/targets"
)

func TestGetTufMetadataMirror(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir(filepath.Join("..", "..", "test", "testdata", "tuf", "test-repo"))))
	defer server.Close()

	path := test.CreateTempDir(t, "", "tuf_temp")
	m, err := NewTUFMirror(tuf.DockerTUFRootDev.Data, path, server.URL+metadataPath, server.URL+targetsPath, tuf.NewMockVersionChecker())
	assert.NoError(t, err)

	tufMetadata, err := m.getMetadataMirror(server.URL + metadataPath)
	assert.NoError(t, err)

	// check that all roles are not empty
	assert.Greater(t, len(tufMetadata.Root), 0)
	assert.Greater(t, len(tufMetadata.Snapshot), 0)
	assert.Greater(t, len(tufMetadata.Targets), 0)
	assert.Greater(t, len(tufMetadata.Timestamp), 0)
}

func TestGetMetadataManifest(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir(filepath.Join("..", "..", "test", "testdata", "tuf", "test-repo"))))
	defer server.Close()

	path := test.CreateTempDir(t, "", "tuf_temp")
	m, err := NewTUFMirror(tuf.DockerTUFRootDev.Data, path, server.URL+metadataPath, server.URL+targetsPath, tuf.NewMockVersionChecker())
	assert.NoError(t, err)

	img, err := m.GetMetadataManifest(server.URL + metadataPath)
	assert.NoError(t, err)
	assert.NotNil(t, img)

	mf, err := img.RawManifest()
	assert.NoError(t, err)

	type Annotations struct {
		Annotations map[string]string `json:"annotations"`
	}
	type Layers struct {
		Layers []Annotations `json:"layers"`
	}
	l := &Layers{}
	err = json.Unmarshal(mf, l)
	assert.NoError(t, err)

	// check that layers are annotated and use consistent snapshot naming
	for _, layer := range l.Layers {
		ann, ok := layer.Annotations[tuf.TUFFileNameAnnotation]
		assert.True(t, ok)
		// check for consistent snapshot version
		parts := strings.Split(ann, ".")
		if parts[0] == metadata.TIMESTAMP {
			continue
		}
		_, err := strconv.Atoi(parts[0])
		assert.NoError(t, err)
	}
}

func TestGetDelegatedMetadataMirrors(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir(filepath.Join("..", "..", "test", "testdata", "tuf", "test-repo"))))
	defer server.Close()

	path := test.CreateTempDir(t, "", "tuf_temp")
	m, err := NewTUFMirror(tuf.DockerTUFRootDev.Data, path, server.URL+metadataPath, server.URL+targetsPath, tuf.NewMockVersionChecker())
	assert.NoError(t, err)

	delegations, err := m.GetDelegatedMetadataMirrors()
	assert.NoError(t, err)

	assert.NotNil(t, delegations)
	assert.Greater(t, len(delegations), 0)
}
