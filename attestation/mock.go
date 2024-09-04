package attestation

import (
	"context"

	"github.com/docker/attest/oci"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// ensure MockResolver implements Resolver
var _ oci.ImageDetailsResolver = MockResolver{}

type MockResolver struct {
	Envs         []*Envelope
	Image        string
	PlatformFn   func() (*v1.Platform, error)
	DescriptorFn func() (*v1.Descriptor, error)
	ImangeNameFn func() (string, error)
}

func (r MockResolver) Attestations(_ context.Context, _ string) ([]*Envelope, error) {
	return r.Envs, nil
}

func (r MockResolver) ImageName(_ context.Context) (string, error) {
	if r.Image != "" {
		return r.Image, nil
	}
	if r.ImangeNameFn != nil {
		return r.ImangeNameFn()
	}
	return "library/alpine:latest", nil
}

func (r MockResolver) ImageDescriptor(_ context.Context) (*v1.Descriptor, error) {
	if r.DescriptorFn != nil {
		return r.DescriptorFn()
	}
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

func (r MockResolver) ImagePlatform(_ context.Context) (*v1.Platform, error) {
	if r.PlatformFn != nil {
		return r.PlatformFn()
	}
	return oci.ParsePlatform("linux/amd64")
}

type MockRegistryResolver struct {
	Subject      *v1.Descriptor
	ImageNameStr string
	*MockResolver
}

func (r *MockRegistryResolver) ImageDescriptor(_ context.Context) (*v1.Descriptor, error) {
	return r.Subject, nil
}

func (r *MockRegistryResolver) ImageName(_ context.Context) (string, error) {
	return r.ImageNameStr, nil
}
