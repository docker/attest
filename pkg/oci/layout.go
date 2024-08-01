package oci

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/docker/attest/pkg/attestation"
	att "github.com/docker/attest/pkg/attestation"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
)

// implementation of AttestationResolver that closes over attestations from an oci layout.
type LayoutResolver struct {
	*attestation.Manifest
	*ImageSpec
}

func NewOCILayoutAttestationResolver(src *ImageSpec) (*LayoutResolver, error) {
	r := &LayoutResolver{
		ImageSpec: src,
	}
	_, err := r.fetchAttestationManifest()
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *LayoutResolver) fetchAttestationManifest() (*attestation.Manifest, error) {
	if r.Manifest == nil {
		m, err := attestationManifestFromOCILayout(r.Identifier, r.ImageSpec.Platform)
		if err != nil {
			return nil, err
		}
		r.Manifest = m
	}

	return r.Manifest, nil
}

func (r *LayoutResolver) Attestations(_ context.Context, predicateType string) ([]*att.Envelope, error) {
	var envs []*att.Envelope
	dsseMediaType, err := attestation.DSSEMediaType(predicateType)
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
		env := new(att.Envelope)
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

func attestationManifestFromOCILayout(path string, platform *v1.Platform) (*attestation.Manifest, error) {
	idx, err := layout.ImageIndexFromPath(path)
	if err != nil {
		return nil, err
	}

	idxm, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get digest: %w", err)
	}

	idxDescriptor := idxm.Manifests[0]
	name := idxDescriptor.Annotations["org.opencontainers.image.ref.name"]
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
		if manifest.Platform.Equals(*platform) {
			subjectDescriptor = manifest
			break
		}
	}
	for i := range mfs2.Manifests {
		mf := &mfs2.Manifests[i]
		if mf.Annotations[att.DockerReferenceType] != attestation.AttestationManifestType {
			continue
		}

		if mf.Annotations[att.DockerReferenceDigest] != subjectDescriptor.Digest.String() {
			continue
		}

		attestationImage, err := mfs.Image(mf.Digest)
		if err != nil {
			return nil, fmt.Errorf("failed to extract attestation image with digest %s: %w", mf.Digest.String(), err)
		}
		layers, err := attestation.GetAttestationsFromImage(attestationImage)
		if err != nil {
			return nil, fmt.Errorf("failed to get attestations from image: %w", err)
		}
		attest := &attestation.Manifest{
			OriginalLayers:     layers,
			OriginalDescriptor: mf,
			SubjectName:        name,
			SubjectDescriptor:  subjectDescriptor,
		}
		return attest, nil
	}
	return nil, fmt.Errorf("attestation manifest not found")
}
