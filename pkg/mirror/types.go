package mirror

import (
	"github.com/docker/attest/pkg/tuf"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const (
	DefaultMetadataURL   = "https://docker.github.io/tuf/metadata"
	DefaultTargetsURL    = "https://docker.github.io/tuf/targets"
	tufMetadataMediaType = "application/vnd.tuf.metadata+json"
	tufTargetMediaType   = "application/vnd.tuf.target"
	tufFileAnnotation    = "tuf.io/filename"
)

type TufRole string

var TufRoles = []TufRole{metadata.ROOT, metadata.SNAPSHOT, metadata.TARGETS, metadata.TIMESTAMP}

type TufMetadata struct {
	Root      map[string][]byte
	Snapshot  map[string][]byte
	Targets   map[string][]byte
	Timestamp []byte
}

type DelegatedTargetMetadata struct {
	Name    string
	Version string
	Data    []byte
}

type MirrorImage struct {
	Image v1.Image
	Tag   string
}

type MirrorIndex struct {
	Index v1.ImageIndex
	Tag   string
}

type TufMirror struct {
	TufClient   *tuf.TufClient
	tufPath     string
	metadataURL string
	targetsURL  string
}
