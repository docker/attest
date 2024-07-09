package oci

import (
	"context"

	att "github.com/docker/attest/pkg/attestation"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type AttestationResolver interface {
	ImageDetailsResolver
	Attestations(ctx context.Context, mediaType string) ([]*att.Envelope, error)
}

type ImageDetailsResolver interface {
	ImageName(ctx context.Context) (string, error)
	ImagePlatform(ctx context.Context) (*v1.Platform, error)
	ImageDescriptor(ctx context.Context) (*v1.Descriptor, error)
}
