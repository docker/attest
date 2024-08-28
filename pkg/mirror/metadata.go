package mirror

import (
	"fmt"
	"strconv"

	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/tuf"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// -----------------
// TUF root metadata
// -----------------

// GetMetadataManifest returns an image with TUF root metadata as layers.
func (m *TUFMirror) GetMetadataManifest(metadataURL string) (*oci.EmptyConfigImage, error) {
	metadata, err := m.getMetadataMirror(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata: %w", err)
	}
	manifest, err := m.buildMetadataManifest(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to build metadata manifest: %w", err)
	}
	return &oci.EmptyConfigImage{Image: manifest}, nil
}

// getMetadataMirror returns a TufMetadata struct with TUF metadata as map of file names to bytes.
func (m *TUFMirror) getMetadataMirror(metadataURL string) (*TUFMetadata, error) {
	trustedMetadata := m.TUFClient.GetMetadata()

	rootMetadata := map[string][]byte{}
	rootVersion := trustedMetadata.Root.Signed.Version
	// get the previous versions of root metadata if any
	if rootVersion != 1 {
		var err error
		rootMetadata, err = m.TUFClient.GetPriorRoots(metadataURL)
		if err != nil {
			return nil, fmt.Errorf("failed to get prior root metadata: %w", err)
		}
	}
	// get current root metadata
	rootBytes, err := trustedMetadata.Root.ToBytes(false)
	if err != nil {
		return nil, fmt.Errorf("failed to get root metadata: %w", err)
	}
	rootMetadata[nameFromRole(metadata.ROOT, strconv.FormatInt(rootVersion, 10))] = rootBytes

	snapshotBytes, err := trustedMetadata.Snapshot.ToBytes(false)
	if err != nil {
		return nil, fmt.Errorf("failed to get snapshot metadata: %w", err)
	}
	targetsBytes, err := trustedMetadata.Targets[metadata.TARGETS].ToBytes(false)
	if err != nil {
		return nil, fmt.Errorf("failed to get targets metadata: %w", err)
	}
	timestampBytes, err := trustedMetadata.Timestamp.ToBytes(false)
	if err != nil {
		return nil, fmt.Errorf("failed to get timestamp metadata: %w", err)
	}

	snapshotVersion := ""
	targetsVersion := ""
	if trustedMetadata.Root.Signed.ConsistentSnapshot {
		snapshotVersion = strconv.FormatInt(trustedMetadata.Snapshot.Signed.Version, 10)
		targetsVersion = strconv.FormatInt(trustedMetadata.Targets[metadata.TARGETS].Signed.Version, 10)
	}
	return &TUFMetadata{
		Root:      rootMetadata,
		Snapshot:  map[string][]byte{nameFromRole(metadata.SNAPSHOT, snapshotVersion): snapshotBytes},
		Targets:   map[string][]byte{nameFromRole(metadata.TARGETS, targetsVersion): targetsBytes},
		Timestamp: timestampBytes,
	}, nil
}

// buildMetadataManifest returns an OCI image with TUF metadata as layers with annotations.
func (m *TUFMirror) buildMetadataManifest(metadata *TUFMetadata) (v1.Image, error) {
	img := empty.Image
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.OCIConfigJSON)
	for _, role := range TUFRoles {
		layers, err := m.makeRoleLayers(role, metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to make role layer: %w", err)
		}
		img, err = mutate.Append(img, layers...)
		if err != nil {
			return nil, fmt.Errorf("failed to append role layer to image: %w", err)
		}
	}
	return img, nil
}

// makeRoleLayers returns a list of layers for a given TUF role.
func (m *TUFMirror) makeRoleLayers(role TUFRole, tufMetadata *TUFMetadata) ([]mutate.Addendum, error) {
	var layers []mutate.Addendum
	ann := map[string]string{tuf.TUFFileNameAnnotation: ""}
	switch role {
	case metadata.ROOT:
		layers = m.annotatedMetaLayers(tufMetadata.Root)
	case metadata.SNAPSHOT:
		layers = m.annotatedMetaLayers(tufMetadata.Snapshot)
	case metadata.TARGETS:
		layers = m.annotatedMetaLayers(tufMetadata.Targets)
	case metadata.TIMESTAMP:
		ann[tuf.TUFFileNameAnnotation] = fmt.Sprintf("%s.json", role)
		layers = append(layers, mutate.Addendum{Layer: static.NewLayer(tufMetadata.Timestamp, tufMetadataMediaType), Annotations: ann})
	default:
		return nil, fmt.Errorf("unsupported TUF role: %s", role)
	}
	return layers, nil
}

// annotatedMetaLayers returns a list of layers with annotations for each TUF metadata file.
func (m *TUFMirror) annotatedMetaLayers(meta map[string][]byte) []mutate.Addendum {
	var layers []mutate.Addendum
	for name, data := range meta {
		ann := map[string]string{tuf.TUFFileNameAnnotation: name}
		layers = append(layers, mutate.Addendum{Layer: static.NewLayer(data, tufMetadataMediaType), Annotations: ann})
	}
	return layers
}

// ------------------------------
// TUF delegated targets metadata
// ------------------------------

// GetDelegatedMetadataMirrors returns a list of mirrors (image/tag pairs) for each delegated targets role metadata.
func (m *TUFMirror) GetDelegatedMetadataMirrors() ([]*Image, error) {
	// get current delegated targets metadata
	delegatedTargets, err := m.getDelegatedTargetsMetadata()
	if err != nil {
		return nil, fmt.Errorf("failed to get delegated targets metadata: %w", err)
	}
	mirror, err := m.buildDelegatedMetadataManifests(delegatedTargets)
	if err != nil {
		return nil, fmt.Errorf("failed to build delegated targets manifests: %w", err)
	}
	return mirror, nil
}

// getDelegatedTargetsMetadata returns delegated targets metadata as a list of DelegatedTargetMetadata (role name and data).
func (m *TUFMirror) getDelegatedTargetsMetadata() ([]DelegatedTargetMetadata, error) {
	var delegatedTargets []DelegatedTargetMetadata
	md := m.TUFClient.GetMetadata()
	for _, role := range md.Targets[metadata.TARGETS].Signed.Delegations.Roles {
		roleMetadata, err := m.TUFClient.LoadDelegatedTargets(role.Name, metadata.TARGETS)
		if err != nil {
			return nil, fmt.Errorf("failed to get delegated role metadata: %w", err)
		}
		roleBytes, err := roleMetadata.ToBytes(false)
		if err != nil {
			return nil, fmt.Errorf("failed to get role %s metadata: %w", role.Name, err)
		}
		meta, ok := md.Snapshot.Signed.Meta[nameFromRole(role.Name, "")]
		if !ok {
			return nil, fmt.Errorf("failed to get role %s metadata: %w", role.Name, err)
		}
		// extract target metadata version in case of consistent snapshot naming
		version := ""
		if md.Root.Signed.ConsistentSnapshot {
			version = strconv.FormatInt(meta.Version, 10)
		}
		delegatedTargets = append(delegatedTargets, DelegatedTargetMetadata{Name: role.Name, Version: version, Data: roleBytes})
	}
	return delegatedTargets, nil
}

// buildDelegatedMetadataManifests returns a list of mirrors (image/tag pairs) for each delegated target role metadata.
func (m *TUFMirror) buildDelegatedMetadataManifests(delegated []DelegatedTargetMetadata) ([]*Image, error) {
	manifests := []*Image{}
	for _, role := range delegated {
		img := empty.Image
		img = mutate.MediaType(img, types.OCIManifestSchema1)
		img = mutate.ConfigMediaType(img, types.OCIConfigJSON)
		ann := map[string]string{tuf.TUFFileNameAnnotation: nameFromRole(role.Name, role.Version)}
		layer := mutate.Addendum{Layer: static.NewLayer(role.Data, tufMetadataMediaType), Annotations: ann}
		img, err := mutate.Append(img, layer)
		if err != nil {
			return nil, fmt.Errorf("failed to append delegated targets layer to image: %w", err)
		}
		manifests = append(manifests, &Image{Image: &oci.EmptyConfigImage{Image: img}, Tag: role.Name})
	}
	return manifests, nil
}

func nameFromRole(role, version string) string {
	if version != "" {
		return fmt.Sprintf("%s.%s.json", version, role)
	}
	return fmt.Sprintf("%s.json", role)
}
