package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	att "github.com/docker/attest/pkg/attestation"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/pkg/errors"
)

// implementation of AttestationResolver that closes over attestations from an oci layout
type OCILayoutResolver struct {
	*AttestationManifest
	*ImageSpec
}

func NewOCILayoutAttestationResolver(src *ImageSpec) (*OCILayoutResolver, error) {
	return &OCILayoutResolver{
		ImageSpec: src,
	}, nil
}

func (r *OCILayoutResolver) fetchAttestationManifest() (*AttestationManifest, error) {
	if r.AttestationManifest == nil {
		m, err := attestationManifestFromOCILayout(r.WithoutPrefix, r.ImageSpec.Platform)
		if err != nil {
			return nil, err
		}
		r.AttestationManifest = m
	}
	return r.AttestationManifest, nil
}

func (r *OCILayoutResolver) Attestations(ctx context.Context, predicateType string) ([]*att.Envelope, error) {
	if r.AttestationManifest == nil {
		_, err := r.fetchAttestationManifest()
		if err != nil {
			return nil, err
		}
	}
	attestationImage := r.AttestationManifest.Image
	layers, err := attestationImage.Layers()
	if err != nil {
		return nil, fmt.Errorf("failed to extract layers from attestation image: %w", err)
	}
	var envs []*att.Envelope
	manifest := r.AttestationManifest.Manifest
	for i, l := range manifest.Layers {
		if l.Annotations[InTotoPredicateType] != predicateType {
			continue
		}
		layer := layers[i]
		mt, err := layer.MediaType()
		if err != nil {
			return nil, fmt.Errorf("failed to get layer media type: %w", err)
		}
		mts := string(mt)
		if !strings.HasSuffix(mts, "+dsse") {
			continue
		}
		var env = new(att.Envelope)
		// parse layer blob as json
		r, err := layer.Uncompressed()

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

func (r *OCILayoutResolver) ImageName(ctx context.Context) (string, error) {
	if r.AttestationManifest == nil {
		_, err := r.fetchAttestationManifest()
		if err != nil {
			return "", err
		}
	}

	return r.Name, nil
}

func (r *OCILayoutResolver) ImageDigest(ctx context.Context) (string, error) {
	if r.AttestationManifest == nil {
		_, err := r.fetchAttestationManifest()
		if err != nil {
			return "", err
		}
	}
	return r.Digest, nil
}

func (r *OCILayoutResolver) ImagePlatform(ctx context.Context) (*v1.Platform, error) {
	return r.ImageSpec.Platform, nil
}

func attestationManifestFromOCILayout(path string, platform *v1.Platform) (*AttestationManifest, error) {
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
	var imageDigest string
	for _, mf := range mfs2.Manifests {
		if mf.Platform.Equals(*platform) {
			imageDigest = mf.Digest.String()
		}
	}
	for _, mf := range mfs2.Manifests {
		if mf.Annotations[att.DockerReferenceType] != AttestationManifestType {
			continue
		}

		if mf.Annotations[att.DockerReferenceDigest] != imageDigest {
			continue
		}

		attestationImage, err := mfs.Image(mf.Digest)
		if err != nil {
			return nil, fmt.Errorf("failed to extract attestation image with digest %s: %w", mf.Digest.String(), err)
		}
		manifest, err := attestationImage.Manifest()
		if err != nil {
			return nil, fmt.Errorf("failed to get manifest: %w", err)
		}
		attest := &AttestationManifest{
			Name:       name,
			Image:      attestationImage,
			Manifest:   manifest,
			Descriptor: &mf,
			Digest:     imageDigest,
			Platform:   platform,
		}
		return attest, nil
	}
	return nil, errors.New("attestation manifest not found")
}
