package oci

import (
	"context"

	att "github.com/docker/attest/pkg/attestation"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type AttestationManifest struct {
	// attestation image details
	Image      v1.Image
	Manifest   *v1.Manifest
	Descriptor *v1.Descriptor
	// details of subect image
	Name     string
	Digest   string
	Platform *v1.Platform
}

type AttestationResolver interface {
	ImageName(ctx context.Context) (string, error)
	ImagePlatform() (*v1.Platform, error)
	ImageDigest(ctx context.Context) (string, error)
	Attestations(ctx context.Context, mediaType string) ([]*att.Envelope, error)
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

func (r MockResolver) ImageDigest(ctx context.Context) (string, error) {
	return "sha256:test-digest", nil
}

func (r MockResolver) ImagePlatform() (*v1.Platform, error) {
	return ParsePlatform("linux/amd64")
}
