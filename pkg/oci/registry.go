package oci

import (
	"context"
	"encoding/json"
	"fmt"

	att "github.com/docker/attest/pkg/attestation"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type RegistryResolver struct {
	*RegistryImageDetailsResolver
	*AttestationManifest
}

type RegistryImageDetailsResolver struct {
	*ImageSpec
	digest string
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

func (r *RegistryImageDetailsResolver) ImageName(ctx context.Context) (string, error) {
	return r.Identifier, nil
}

func (r *RegistryImageDetailsResolver) ImagePlatform(ctx context.Context) (*v1.Platform, error) {
	return r.Platform, nil
}

func (r *RegistryImageDetailsResolver) ImageDigest(ctx context.Context) (string, error) {
	if r.digest == "" {
		subjectRef, err := name.ParseReference(r.Identifier)
		if err != nil {
			return "", fmt.Errorf("failed to parse reference: %w", err)
		}
		switch t := subjectRef.(type) {
		case name.Digest:
			// TODO should check if this is an index or an image
			r.digest = t.DigestStr()
		case name.Tag:
			options := WithOptions(ctx, r.Platform)
			desc, err := remote.Image(t, options...)
			if err != nil {
				return "", fmt.Errorf("failed to get image manifest: %w", err)
			}
			subjectDigest, err := desc.Digest()
			if err != nil {
				return "", fmt.Errorf("failed to get image digest: %w", err)
			}
			r.digest = subjectDigest.String()
		default:
			return "", fmt.Errorf("unsupported reference type: %T", t)
		}
	}
	return r.digest, nil
}

func (r *RegistryResolver) Attestations(ctx context.Context, predicateType string) ([]*att.Envelope, error) {
	if r.AttestationManifest == nil {
		attest, err := FetchAttestationManifest(ctx, r.Identifier, r.ImageSpec.Platform)
		if err != nil {
			return nil, err
		}
		r.AttestationManifest = attest
	}
	return ExtractEnvelopes(r.AttestationManifest, predicateType)
}

func FetchAttestationManifest(ctx context.Context, image string, platform *v1.Platform) (*AttestationManifest, error) {
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
	digest, err := imageDigestForPlatform(indexManifest, platform)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain image for platform: %w", err)
	}
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
	manifest := new(v1.Manifest)
	err = json.Unmarshal(remoteDescriptor.Manifest, manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestation: %w", err)
	}
	attestationImage, err := remoteDescriptor.Image()
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation image: %w", err)
	}
	attest := &AttestationManifest{
		Name:       image,
		Image:      attestationImage,
		Manifest:   manifest,
		Descriptor: &remoteDescriptor.Descriptor,
		Digest:     digest,
		Platform:   platform,
	}
	return attest, nil
}
