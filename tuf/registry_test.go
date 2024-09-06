package tuf

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/internal/util"
	"github.com/docker/attest/oci"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

const (
	tufTargetMediaType = "application/vnd.tuf.target"
	testRole           = "test-role"
	tufMetadataRepo    = "tuf-metadata"
	targetsPath        = "/tuf-targets"
	metadataPath       = "/tuf-metadata"
	targetsRepo        = "test" + targetsPath
)

func TestRegistryFetcher(t *testing.T) {

	ctx := context.Background()
	regServer := test.TestRegistry(ctx, t)
	defer regServer.Close()

	regAddr, err := url.Parse(regServer.URL)
	require.NoError(t, err)

	LoadRegistryTestData(ctx, t, regAddr, OCITUFTestDataPath)

	metadataRepo := regAddr.Host + metadataPath
	targetsRepo := regAddr.Host + targetsPath
	targetFile := "test.txt"
	delegatedRole := testRole
	dir := CreateTempDir(t, "", "tuf_temp")
	delegatedDir := CreateTempDir(t, dir, delegatedRole)
	delegatedTargetFile := fmt.Sprintf("%s/%s", delegatedRole, targetFile)

	// note - url is ignored here - needed to make http url parsing happy even when using oci
	cfg, err := config.New("", DockerTUFRootDev.Data)
	require.NoError(t, err)
	cfg.LocalMetadataDir = dir
	cfg.LocalTargetsDir = dir
	cfg.RemoteTargetsURL = targetsRepo
	cfg.RemoteMetadataURL = metadataRepo
	cfg.Fetcher, err = NewRegistryFetcher(context.Background(), cfg)
	require.NoError(t, err)

	// create a new Updater instance
	up, err := updater.New(cfg)
	require.NoError(t, err)

	// refresh the metadata
	err = up.Refresh()
	require.NoError(t, err)

	// download top-level target
	targetInfo, err := up.GetTargetInfo(targetFile)
	require.NoError(t, err)
	_, _, err = up.DownloadTarget(targetInfo, filepath.Join(dir, targetInfo.Path), "")
	require.NoError(t, err)

	// download delegated target
	targetInfo, err = up.GetTargetInfo(delegatedTargetFile)
	require.NoError(t, err)
	_, _, err = up.DownloadTarget(targetInfo, filepath.Join(delegatedDir, targetFile), "")
	require.NoError(t, err)
}

func TestRoleFromConsistentName(t *testing.T) {
	testCases := []struct {
		name     string
		expected string
	}{
		{"root.json", metadata.ROOT},
		{"1.root.json", metadata.ROOT},
		{"targets.json", metadata.TARGETS},
		{"63.targets.json", metadata.TARGETS},
		{"timestamp", metadata.TIMESTAMP},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, roleFromConsistentName(tc.name))
		})
	}
}

func TestIsDelegatedRole(t *testing.T) {
	testCases := []struct {
		name     string
		expected bool
	}{
		{metadata.ROOT, false},
		{metadata.TARGETS, false},
		{metadata.TIMESTAMP, false},
		{"doi", true},
		{"test", true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, isDelegatedRole(tc.name))
		})
	}
}

func TestFindFileInManifest(t *testing.T) {
	// make test image manifest
	file := "test.json"
	data := []byte("test")
	hash := v1.Hash{Hex: util.SHA256Hex(data)}
	img := empty.Image
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.OCIConfigJSON)
	// add test layer
	name := strings.Join([]string{hash.Hex, file}, ".")
	ann := map[string]string{TUFFileNameAnnotation: name}
	layer := mutate.Addendum{Layer: static.NewLayer(data, tufTargetMediaType), Annotations: ann}
	img, err := mutate.Append(img, layer)
	assert.NoError(t, err)
	imageManifest, err := img.RawManifest()
	assert.NoError(t, err)

	// make test index manifest
	idx := v1.ImageIndex(empty.Index)
	assert.NoError(t, err)
	// append image to index with annotation
	idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
		Add: img,
		Descriptor: v1.Descriptor{
			Annotations: map[string]string{
				TUFFileNameAnnotation: name,
			},
		},
	})
	indexManifest, err := idx.RawManifest()
	assert.NoError(t, err)
	// cache image layer
	d := &RegistryFetcher{
		cache:       NewImageCache(),
		targetsRepo: targetsRepo,
	}
	imgHash, err := img.Digest()
	assert.NoError(t, err)
	d.cache.Put(fmt.Sprintf("%s@%s", targetsRepo, imgHash.String()), imageManifest)

	testCases := []struct {
		name     string
		manifest []byte
		file     string
		expected string
	}{
		{"consistent filename image", imageManifest, fmt.Sprintf("%s.%s", hash.Hex, file), hash.Hex},
		{"filename image", imageManifest, file, ""},
		{"consistent filename index", indexManifest, fmt.Sprintf("%s.%s", hash.Hex, file), hash.Hex},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := d.findFileInManifest(tc.manifest, tc.file)
			if tc.expected == "" {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, digest.Hex)
		})
	}
}

func TestParseImgRef(t *testing.T) {
	metadataRepo := "test" + metadataPath
	metadataTag := LatestTag
	delegatedRole := testRole
	validRef := fmt.Sprintf("%s/2.root.json", metadataRepo)
	expectedRef := fmt.Sprintf("docker.io/%s:%s", metadataRepo, metadataTag)
	testCases := []struct {
		name                     string
		ref                      string
		expectedRef              string
		expectedFile             string
		metadataRepo             string
		metadataTag              string
		expectedRefError         string
		expectedConstructorError string
		targetsRepo              string
	}{
		{name: "top-level metadata", ref: validRef, expectedRef: expectedRef, expectedFile: "2.root.json"},
		{name: "short metdata repo", ref: validRef, metadataRepo: "test" + metadataPath, expectedRef: expectedRef, expectedFile: "2.root.json"},
		{name: "library path", ref: fmt.Sprintf("test%s/2.root.json", metadataPath), metadataRepo: "test" + metadataPath, expectedRef: "docker.io/test/tuf-metadata:latest", expectedFile: "2.root.json"},
		{name: "short targets repo", ref: validRef, targetsRepo: "test" + targetsPath, expectedRef: expectedRef, expectedFile: "2.root.json"},
		{name: "delegated metadata", ref: fmt.Sprintf("%s/%s/5.test-role.json", metadataRepo, delegatedRole), expectedRef: fmt.Sprintf("docker.io/%s:%s", metadataRepo, delegatedRole), expectedFile: "5.test-role.json"},
		{name: "top-level target", ref: fmt.Sprintf("%s/policy.yaml", targetsRepo), expectedRef: fmt.Sprintf("docker.io/%s:policy.yaml", targetsRepo), expectedFile: "policy.yaml"},
		{name: "delegated target", ref: fmt.Sprintf("%s/%s/policy.yaml", targetsRepo, delegatedRole), expectedRef: fmt.Sprintf("docker.io/%s:%s", targetsRepo, delegatedRole), expectedFile: fmt.Sprintf("%s/policy.yaml", delegatedRole)},
		{name: "docker/targets", ref: fmt.Sprintf("%s/2.root.json", "docker.io/docker/targets"), expectedRef: "docker.io/docker/targets:latest", expectedFile: "2.root.json", metadataRepo: "docker.io/docker/targets"},
		{name: "malformed ref", ref: fmt.Sprintf("%s/2.root.json", "@broken"), expectedRefError: "urlPath: @broken/2.root.json must be in metadata or targets repo"},
		{name: "malformed metadataRepo", ref: validRef, metadataRepo: "@broken", expectedConstructorError: "failed to parse metadata repo: invalid reference format"},
		{name: "malformed targetsRepo", ref: validRef, targetsRepo: "@broken", expectedConstructorError: "failed to parse targets repo: invalid reference format"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			repo := metadataRepo
			if tc.metadataRepo != "" {
				repo = tc.metadataRepo
			}
			targets := targetsRepo
			if tc.targetsRepo != "" {
				targets = tc.targetsRepo
			}
			cfg := &config.UpdaterConfig{
				RemoteMetadataURL: repo,
				RemoteTargetsURL:  targets,
			}
			d, err := NewRegistryFetcher(context.Background(), cfg)
			if tc.expectedConstructorError != "" {
				assert.ErrorContains(t, err, tc.expectedConstructorError)
			} else {
				require.NoError(t, err)
				imgRef, file, err := d.parseImgRef(tc.ref)
				if tc.expectedRefError != "" {
					assert.ErrorContains(t, err, tc.expectedRefError)
				} else {
					require.NoError(t, err)
					assert.Equal(t, tc.expectedRef, imgRef, "ref mismatch")
					assert.Equal(t, tc.expectedFile, file, "file mismatch")
				}
			}
		})
	}
}

func TestGetDataFromLayer(t *testing.T) {
	data := []byte("test")
	layer := static.NewLayer(data, tufTargetMediaType)
	testCases := []struct {
		name     string
		layer    v1.Layer
		max      int64
		expected []byte
	}{
		{"valid length", layer, int64(len(data)), data},
		{"invalid length", layer, int64(len(data) - 1), nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := getDataFromLayer(tc.layer, tc.max)
			if tc.expected == nil {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, data)
		})
	}
}

func TestPullFileLayer(t *testing.T) {
	ctx := context.Background()
	regServer := test.TestRegistry(ctx, t)
	defer regServer.Close()

	url, err := url.Parse(regServer.URL)
	require.NoError(t, err)

	// make test layer
	repo := tufMetadataRepo
	data := []byte("test")
	testLayer := static.NewLayer(data, tufTargetMediaType)
	hash, err := testLayer.Digest()
	assert.NoError(t, err)
	layerRef := fmt.Sprintf("%s/%s@%s", url.Host, repo, hash.String())

	// cache test manifest
	d, err := NewRegistryFetcher(context.Background(), &config.UpdaterConfig{
		RemoteMetadataURL: tufMetadataRepo,
		RemoteTargetsURL:  tufMetadataRepo,
	})
	require.NoError(t, err)

	d.cache.Put(layerRef, data)

	// push uncached image layer to local registry
	uncachedData := []byte("uncached")
	uncachedTestLayer := static.NewLayer(uncachedData, tufTargetMediaType)
	uncachedHash, err := uncachedTestLayer.Digest()
	assert.NoError(t, err)
	uncachedLayerRef := fmt.Sprintf("%s/%s@%s", url.Host, repo, uncachedHash.String())
	img := empty.Image
	img, err = mutate.Append(img, mutate.Addendum{Layer: uncachedTestLayer})
	assert.NoError(t, err)
	err = crane.Push(img, fmt.Sprintf("%s/%s", url.Host, fmt.Sprintf("%s:latest", repo)), crane.WithUserAgent(util.GetUserAgent(ctx)))
	assert.NoError(t, err)

	testCases := []struct {
		name      string
		ref       string
		maxLength int
		expected  []byte
	}{
		{"cached layer", layerRef, len(data), data},
		{"uncached layer", uncachedLayerRef, len(uncachedData), uncachedData},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			layer, err := d.pullFileLayer(tc.ref, int64(tc.maxLength))
			if tc.expected == nil {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Greater(t, len(layer), 0)
		})
	}
}

func TestGetManifest(t *testing.T) {
	ctx := context.Background()
	regServer := test.TestRegistry(ctx, t)
	defer regServer.Close()

	url, err := url.Parse(regServer.URL)
	require.NoError(t, err)

	// make test manifest
	repo := tufMetadataRepo
	img := empty.Image
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.OCIConfigJSON)
	imgRef := fmt.Sprintf("%s/%s:latest", url.Host, repo)

	// cache test manifest
	d, err := NewRegistryFetcher(context.Background(), &config.UpdaterConfig{
		RemoteMetadataURL: tufMetadataRepo,
		RemoteTargetsURL:  tufMetadataRepo,
	})
	require.NoError(t, err)

	mf, err := img.RawManifest()
	assert.NoError(t, err)
	d.cache.Put(imgRef, mf)

	// push test image to local registry
	unchachedImgRef := fmt.Sprintf("%s/%s:unchached", url.Host, repo)
	err = crane.Push(img, unchachedImgRef, crane.WithUserAgent(util.GetUserAgent(ctx)))
	assert.NoError(t, err)

	testCases := []struct {
		name     string
		ref      string
		expected []byte
	}{
		{"cached image manifest", imgRef, mf},
		{"uncached image manifest", unchachedImgRef, mf},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			manifest, err := d.getManifest(tc.ref)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, manifest)
		})
	}
}

// LoadRegistryTestData pushes TUF metadata and targets to an OCI registry.
func LoadRegistryTestData(ctx context.Context, t *testing.T, registry *url.URL, path string) {
	// push tuf metadata and targets to local registry
	MetadataRepo := tufMetadataRepo
	TargetsRepo := "tuf-targets"
	DelegatedRole := testRole

	// push top-level metadata -> metadata:latest
	err := LoadMetadata(ctx, filepath.Join(path, "metadata"), registry.Host, MetadataRepo, LatestTag)
	if err != nil {
		t.Fatal(err)
	}

	// push delegated metadata -> metadata:<DELEGATED_ROLE>
	err = LoadMetadata(ctx, filepath.Join(path, "metadata", DelegatedRole), registry.Host, MetadataRepo, DelegatedRole)
	if err != nil {
		t.Fatal(err)
	}

	// push targets -> targets:<HASH>.<FILE>.ext (image) or targets:<DELEGATED ROLE> <index)
	targetDirs, err := os.ReadDir(filepath.Join(path, "targets"))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range targetDirs {
		if !dir.IsDir() {
			continue
		}
		tIdx, err := layout.ImageIndexFromPath(filepath.Join(path, "targets", dir.Name()))
		if err != nil {
			t.Fatal(err)
		}
		ref, err := name.ParseReference(fmt.Sprintf("%s/%s:%s", registry.Host, TargetsRepo, dir.Name()))
		if err != nil {
			t.Fatal(err)
		}
		mf, err := tIdx.IndexManifest()
		if err != nil {
			t.Fatal(err)
		}
		switch len(mf.Manifests) {
		case 1:
			// top-level target
			img, err := tIdx.Image(mf.Manifests[0].Digest)
			if err != nil {
				t.Fatal(err)
			}
			err = remote.Write(ref, img, oci.WithOptions(ctx, nil)...)
			if err != nil {
				t.Fatal(err)
			}
		case 2:
			// delegated target
			err = remote.WriteIndex(ref, tIdx, oci.WithOptions(ctx, nil)...)
			if err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("no manifests found")
		}
	}
}

// LoadMetadata loads TUF metadata from a local path and pushes to a registry.
func LoadMetadata(ctx context.Context, path, host, repo, tag string) error {
	mIdx, err := layout.ImageIndexFromPath(path)
	if err != nil {
		return err
	}
	ref, err := name.ParseReference(fmt.Sprintf("%s/%s:%s", host, repo, tag))
	if err != nil {
		return err
	}
	mf, err := mIdx.IndexManifest()
	if err != nil {
		return err
	}
	img, err := mIdx.Image(mf.Manifests[0].Digest)
	if err != nil {
		return err
	}
	return remote.Write(ref, img, oci.WithOptions(ctx, nil)...)
}
