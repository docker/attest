package attestation

import (
	"context"
	"fmt"

	"github.com/docker/attest/oci"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ensure RegistryResolver implements Resolver.
var _ Resolver = &RegistryResolver{}

type RegistryResolver struct {
	*oci.RegistryImageDetailsResolver
	*Manifest
}

func NewRegistryResolver(src *oci.RegistryImageDetailsResolver) (*RegistryResolver, error) {
	return &RegistryResolver{
		RegistryImageDetailsResolver: src,
	}, nil
}

func (r *RegistryResolver) Attestations(ctx context.Context, predicateType string) ([]*Envelope, error) {
	if r.Manifest == nil {
		attest, err := FetchManifest(ctx, r.Identifier, r.ImageSpec.Platform)
		if err != nil {
			return nil, err
		}
		r.Manifest = attest
	}
	return ExtractEnvelopes(r.Manifest, predicateType)
}

func attestationDigestForImage(ix *v1.IndexManifest, imageDigest string, attestType string) (string, error) {
	for i := range ix.Manifests {
		m := &ix.Manifests[i]
		if v, ok := m.Annotations[DockerReferenceType]; ok && v == attestType {
			if d, ok := m.Annotations[DockerReferenceDigest]; ok && d == imageDigest {
				return m.Digest.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no attestation found for image %s", imageDigest)
}

func FetchManifest(ctx context.Context, image string, platform *v1.Platform) (*Manifest, error) {
	// we want to get to the image index, so ignoring platform for now
	options := oci.WithOptions(ctx, nil)
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference: %w", err)
	}
	index, err := remote.Index(ref, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to get index: %w", err)
	}
	indexManifest, err := index.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get index manifest: %w", err)
	}
	subjectDescriptor, err := oci.ImageDescriptor(indexManifest, platform)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain image for platform: %w", err)
	}

	digest := subjectDescriptor.Digest.String()
	ref, err = name.ParseReference(fmt.Sprintf("%s@%s", ref.Context().Name(), digest))
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation reference: %w", err)
	}

	attestationDigest, err := attestationDigestForImage(indexManifest, digest, "attestation-manifest")
	if err != nil {
		return nil, fmt.Errorf("failed to obtain attestation for image: %w", err)
	}
	ref, err = name.ParseReference(fmt.Sprintf("%s@%s", ref.Context().Name(), attestationDigest))
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation reference: %w", err)
	}
	remoteDescriptor, err := remote.Get(ref, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation: %w", err)
	}
	attestationImage, err := remoteDescriptor.Image()
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation image: %w", err)
	}

	layers, err := layersFromImage(attestationImage)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestations from image: %w", err)
	}
	attest := &Manifest{
		OriginalLayers:     layers,
		OriginalDescriptor: &remoteDescriptor.Descriptor,
		SubjectName:        image,
		SubjectDescriptor:  subjectDescriptor,
	}
	return attest, nil
}
