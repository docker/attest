package attestation

import (
	"encoding/json"
	"fmt"
	"maps"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/types"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

// GetAttestationManifestsFromIndex extracts all attestation manifests from an index
func GetAttestationManifestsFromIndex(index v1.ImageIndex) ([]AttestationManifest, error) {
	idx, err := index.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to extract IndexManifest from ImageIndex: %w", err)
	}
	subjects := make(map[string]*v1.Descriptor)
	for _, subject := range idx.Manifests {
		subjects[subject.Digest.String()] = &subject
	}

	var attestationManifests []AttestationManifest
	for _, manifest := range idx.Manifests {

		if manifest.Annotations[DockerReferenceType] == AttestationManifestType {
			subject := subjects[manifest.Annotations[DockerReferenceDigest]]
			if subject == nil {
				return nil, fmt.Errorf("failed to find subject for attestation manifest: %w", err)
			}
			attestationImage, err := index.Image(manifest.Digest)
			if err != nil {
				return nil, fmt.Errorf("failed to extract attestation image with digest %s: %w", manifest.Digest.String(), err)
			}
			attestationLayers, err := GetAttestationsFromImage(attestationImage)
			if err != nil {
				return nil, fmt.Errorf("failed to get attestations from image: %w", err)
			}
			attestationManifests = append(attestationManifests,
				AttestationManifest{
					Manifest:          manifest,
					SubjectDescriptor: subject,
					Attestation: AttestationImage{
						Layers: attestationLayers,
						Image:  attestationImage},
					MediaType:   manifest.MediaType,
					Annotations: manifest.Annotations,
					Digest:      manifest.Digest})
		}
	}
	return attestationManifests, nil
}

// GetAttestationsFromImage extracts all attestation layers from an image
func GetAttestationsFromImage(image v1.Image) ([]AttestationLayer, error) {
	layers, err := image.Layers()
	if err != nil {
		return nil, fmt.Errorf("failed to extract layers from image: %w", err)
	}
	var attestationLayers []AttestationLayer
	for _, layer := range layers {
		// parse layer blob as json
		r, err := layer.Uncompressed()
		if err != nil {
			return nil, fmt.Errorf("failed to get layer contents: %w", err)
		}
		defer r.Close()
		mt, err := layer.MediaType()
		if err != nil {
			return nil, fmt.Errorf("failed to get layer media type: %w", err)
		}
		layerDesc, err := partial.Descriptor(layer)
		if err != nil {
			return nil, fmt.Errorf("failed to get descriptor for layer: %w", err)
		}
		// copy original annotations
		ann := maps.Clone(layerDesc.Annotations)
		// only decode intoto statements
		var stmt = new(intoto.Statement)
		if mt == types.MediaType(intoto.PayloadType) {
			err = json.NewDecoder(r).Decode(&stmt)
			if err != nil {
				return nil, fmt.Errorf("failed to decode statement layer contents: %w", err)
			}
		}
		attestationLayers = append(attestationLayers, AttestationLayer{Layer: layer, MediaType: mt, Statement: stmt, Annotations: ann})
	}
	return attestationLayers, nil
}
