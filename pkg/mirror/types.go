package mirror

import (
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/tuf"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const (
	DefaultMetadataURL   = "https://docker.github.io/tuf/metadata"
	DefaultTargetsURL    = "https://docker.github.io/tuf/targets"
	tufMetadataMediaType = "application/vnd.tuf.metadata+json"
	tufTargetMediaType   = "application/vnd.tuf.target"
)

type TUFRole string

var TUFRoles = []TUFRole{metadata.ROOT, metadata.SNAPSHOT, metadata.TARGETS, metadata.TIMESTAMP}

type TUFMetadata struct {
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

type Image struct {
	Image *oci.EmptyConfigImage
	Tag   string
}

type Index struct {
	Index v1.ImageIndex
	Tag   string
}

type TUFMirror struct {
	TUFClient   *tuf.Client
	tufPath     string
	metadataURL string
	targetsURL  string
}
