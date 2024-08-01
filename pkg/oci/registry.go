package oci

import (
	"context"
	"fmt"

	"github.com/docker/attest/pkg/attestation"
	att "github.com/docker/attest/pkg/attestation"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type RegistryResolver struct {
	*RegistryImageDetailsResolver
	*attestation.Manifest
}

type RegistryImageDetailsResolver struct {
	*ImageSpec
	descriptor *v1.Descriptor
}

func NewRegistryImageDetailsResolver(src *ImageSpec) (*RegistryImageDetailsResolver, error) {
	return &RegistryImageDetailsResolver{
		ImageSpec: src,
	}, nil
}

func NewRegistryAttestationResolver(src *RegistryImageDetailsResolver) (*RegistryResolver, error) {
	return &RegistryResolver{
		RegistryImageDetailsResolver: src,
	}, nil
}

func (r *RegistryImageDetailsResolver) ImageName(_ context.Context) (string, error) {
	return r.Identifier, nil
}

func (r *RegistryImageDetailsResolver) ImagePlatform(_ context.Context) (*v1.Platform, error) {
	return r.Platform, nil
}

func (r *RegistryImageDetailsResolver) ImageDescriptor(ctx context.Context) (*v1.Descriptor, error) {
	if r.descriptor == nil {
		subjectRef, err := name.ParseReference(r.Identifier)
		if err != nil {
			return nil, fmt.Errorf("failed to parse reference: %w", err)
		}
		options := WithOptions(ctx, r.Platform)
		image, err := remote.Image(subjectRef, options...)
		if err != nil {
			return nil, fmt.Errorf("failed to get image manifest: %w", err)
		}
		digest, err := image.Digest()
		if err != nil {
			return nil, fmt.Errorf("failed to get image digest: %w", err)
		}
		size, err := image.Size()
		if err != nil {
			return nil, fmt.Errorf("failed to get image size: %w", err)
		}
		mediaType, err := image.MediaType()
		if err != nil {
			return nil, fmt.Errorf("failed to get image media type: %w", err)
		}
		r.descriptor = &v1.Descriptor{
			Digest:    digest,
			Size:      size,
			MediaType: mediaType,
		}
	}
	return r.descriptor, nil
}

func (r *RegistryResolver) Attestations(ctx context.Context, predicateType string) ([]*att.Envelope, error) {
	if r.Manifest == nil {
		attest, err := FetchAttestationManifest(ctx, r.Identifier, r.ImageSpec.Platform)
		if err != nil {
			return nil, err
		}
		r.Manifest = attest
	}
	return ExtractEnvelopes(r.Manifest, predicateType)
}

func FetchAttestationManifest(ctx context.Context, image string, platform *v1.Platform) (*attestation.Manifest, error) {
	// we want to get to the image index, so ignoring platform for now
	options := WithOptions(ctx, nil)
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
	subjectDescriptor, err := imageDescriptor(indexManifest, platform)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain image for platform: %w", err)
	}

	digest := subjectDescriptor.Digest.String()
	ref, err = name.ParseReference(fmt.Sprintf("%s@%s", ref.Context().Name(), digest))
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation reference: %w", err)
	}

	attestationDigest, err := attestationDigestForDigest(indexManifest, digest, "attestation-manifest")
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

	layers, err := attestation.GetAttestationsFromImage(attestationImage)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestations from image: %w", err)
	}
	attest := &attestation.Manifest{
		OriginalLayers:     layers,
		OriginalDescriptor: &remoteDescriptor.Descriptor,
		SubjectName:        image,
		SubjectDescriptor:  subjectDescriptor,
	}
	return attest, nil
}
