package mirror

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/pkg/tuf"
	"github.com/stretchr/testify/assert"
)

type Layer struct {
	Annotations map[string]string `json:"annotations"`
	Digest      string            `json:"digest"`
}
type Layers struct {
	Layers []Layer `json:"layers"`
}

func TestGetTufTargetsMirror(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir(filepath.Join("..", "..", "test", "testdata", "tuf", "test-repo"))))
	defer server.Close()

	path := test.CreateTempDir(t, "", "tuf_temp")
	m, err := NewTUFMirror(tuf.DockerTUFRootDev.Data, path, server.URL+metadataPath, server.URL+targetsPath, tuf.NewMockVersionChecker())
	assert.NoError(t, err)

	targets, err := m.GetTUFTargetMirrors()
	assert.NoError(t, err)
	assert.Greater(t, len(targets), 0)

	// check for image layer annotations
	for _, target := range targets {
		img := target.Image
		mf, err := img.RawManifest()
		assert.NoError(t, err)

		// unmarshal manifest with annotations
		l := &Layers{}
		err = json.Unmarshal(mf, l)
		assert.NoError(t, err)

		// check that layers are annotated
		for _, layer := range l.Layers {
			ann, ok := layer.Annotations[tuf.TUFFileNameAnnotation]
			assert.True(t, ok)
			parts := strings.Split(ann, ".")
			// <digest>.filename.<ext|optional>
			assert.GreaterOrEqual(t, len(parts), 2)
		}
	}
}

func TestTargetDelegationMetadata(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir(filepath.Join("..", "..", "test", "testdata", "tuf", "test-repo"))))
	defer server.Close()

	path := test.CreateTempDir(t, "", "tuf_temp")
	tm, err := NewTUFMirror(tuf.DockerTUFRootDev.Data, path, server.URL+metadataPath, server.URL+targetsPath, tuf.NewMockVersionChecker())
	assert.NoError(t, err)

	targets, err := tm.TUFClient.LoadDelegatedTargets("test-role", "targets")
	assert.NoError(t, err)
	assert.Greater(t, len(targets.Signed.Targets), 0)
}

func TestGetDelegatedTargetMirrors(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir(filepath.Join("..", "..", "test", "testdata", "tuf", "test-repo"))))
	defer server.Close()

	path := test.CreateTempDir(t, "", "tuf_temp")
	m, err := NewTUFMirror(tuf.DockerTUFRootDev.Data, path, server.URL+metadataPath, server.URL+targetsPath, tuf.NewMockVersionChecker())
	assert.NoError(t, err)

	mirrors, err := m.GetDelegatedTargetMirrors()
	assert.NoError(t, err)
	assert.Greater(t, len(mirrors), 0)

	// check for index image annotations
	for _, mirror := range mirrors {
		idx := mirror.Index
		mf, err := idx.RawManifest()
		assert.NoError(t, err)

		// unmarshal manifest with annotations
		l := &Layers{}
		err = json.Unmarshal(mf, l)
		assert.NoError(t, err)

		// check that layers are annotated
		for _, layer := range l.Layers {
			ann, ok := layer.Annotations[tuf.TUFFileNameAnnotation]
			assert.True(t, ok)
			parts := strings.Split(ann, ".")
			// <subdir>/<digest>.filename.<ext|optional>
			assert.GreaterOrEqual(t, len(parts), 2)
		}
	}
}
