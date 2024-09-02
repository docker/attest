package attestation

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/docker/attest/oci"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
)

// implementation of Resolver that closes over attestations from an oci layout.
type LayoutResolver struct {
	*Manifest
	*oci.ImageSpec
}

func NewOCILayoutResolver(src *oci.ImageSpec) (*LayoutResolver, error) {
	r := &LayoutResolver{
		ImageSpec: src,
	}
	_, err := r.fetchManifest()
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *LayoutResolver) fetchManifest() (*Manifest, error) {
	if r.Manifest == nil {
		m, err := manifestFromOCILayout(r.Identifier, r.ImageSpec.Platform)
		if err != nil {
			return nil, err
		}
		r.Manifest = m
	}

	return r.Manifest, nil
}

func (r *LayoutResolver) Attestations(_ context.Context, predicateType string) ([]*Envelope, error) {
	var envs []*Envelope
	dsseMediaType, err := DSSEMediaType(predicateType)
	if err != nil {
		return nil, fmt.Errorf("failed to get DSSE media type for predicate '%s': %w", predicateType, err)
	}
	for _, attestationLayer := range r.Manifest.OriginalLayers {
		mt, err := attestationLayer.Layer.MediaType()
		if err != nil {
			return nil, fmt.Errorf("failed to get layer media type: %w", err)
		}
		mts := string(mt)
		if mts != dsseMediaType {
			continue
		}
		env := new(Envelope)
		// parse layer blob as json
		r, err := attestationLayer.Layer.Uncompressed()
		if err != nil {
			return nil, fmt.Errorf("failed to get layer contents: %w", err)
		}
		defer r.Close()
		err = json.NewDecoder(r).Decode(env)
		if err != nil {
			return nil, fmt.Errorf("failed to decode envelope: %w", err)
		}
		envs = append(envs, env)
	}
	return envs, nil
}

func (r *LayoutResolver) ImageName(_ context.Context) (string, error) {
	return r.SubjectName, nil
}

func (r *LayoutResolver) ImageDescriptor(_ context.Context) (*v1.Descriptor, error) {
	return r.SubjectDescriptor, nil
}

func (r *LayoutResolver) ImagePlatform(_ context.Context) (*v1.Platform, error) {
	return r.ImageSpec.Platform, nil
}

func manifestFromOCILayout(path string, platform *v1.Platform) (*Manifest, error) {
	idx, err := layout.ImageIndexFromPath(path)
	if err != nil {
		return nil, err
	}

	idxm, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get digest: %w", err)
	}

	idxDescriptor := idxm.Manifests[0]
	idxDigest := idxDescriptor.Digest

	mfs, err := idx.ImageIndex(idxDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ImageIndex for digest %s: %w", idxDigest.String(), err)
	}
	mfs2, err := mfs.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to extract IndexManifest from ImageIndex: %w", err)
	}
	var subjectDescriptor *v1.Descriptor
	for i := range mfs2.Manifests {
		manifest := &mfs2.Manifests[i]
		if manifest.Platform != nil {
			if manifest.Platform.Equals(*platform) {
				subjectDescriptor = manifest
				break
			}
		}
	}
	if subjectDescriptor == nil {
		return nil, fmt.Errorf("platform not found in index")
	}
	for i := range mfs2.Manifests {
		mf := &mfs2.Manifests[i]
		if mf.Annotations[DockerReferenceType] != AttestationManifestType {
			continue
		}

		if mf.Annotations[DockerReferenceDigest] != subjectDescriptor.Digest.String() {
			continue
		}

		attestationImage, err := mfs.Image(mf.Digest)
		if err != nil {
			return nil, fmt.Errorf("failed to extract attestation image with digest %s: %w", mf.Digest.String(), err)
		}
		layers, err := layersFromImage(attestationImage)
		if err != nil {
			return nil, fmt.Errorf("failed to get attestations from image: %w", err)
		}
		attest := &Manifest{
			OriginalLayers:     layers,
			OriginalDescriptor: mf,
			SubjectName:        idxDescriptor.Annotations["org.opencontainers.image.ref.name"],
			SubjectDescriptor:  subjectDescriptor,
		}
		return attest, nil
	}
	return nil, fmt.Errorf("attestation manifest not found")
}
