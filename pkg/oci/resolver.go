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

type MockResolver struct {
	Envs []*att.Envelope
}

func (r MockResolver) Attestations(ctx context.Context, mediaType string) ([]*att.Envelope, error) {
	return r.Envs, nil
}

func (r MockResolver) ImageName(ctx context.Context) (string, error) {
	return "library/alpine:latest", nil
}

func (r MockResolver) ImageDescriptor(ctx context.Context) (*v1.Descriptor, error) {
	digest, err := v1.NewHash("sha256:da8b190665956ea07890a0273e2a9c96bfe291662f08e2860e868eef69c34620")
	if err != nil {
		return nil, err
	}
	return &v1.Descriptor{
		Digest:    digest,
		Size:      1234,
		MediaType: "application/vnd.oci.image.manifest.v1+json",
	}, nil

}

func (r MockResolver) ImagePlatform(ctx context.Context) (*v1.Platform, error) {
	return ParsePlatform("linux/amd64")
}
