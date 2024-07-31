package test

import (
	"context"
	"os"
	"path/filepath"

	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/signerverifier"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type MockResolver struct {
	Envs []*attestation.Envelope
}

func (r MockResolver) Attestations(ctx context.Context, mediaType string) ([]*attestation.Envelope, error) {
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
	return oci.ParsePlatform("linux/amd64")
}

type MockRegistryResolver struct {
	Subject      *v1.Descriptor
	ImageNameStr string
	*MockResolver
}

func (r *MockRegistryResolver) ImageDescriptor(ctx context.Context) (*v1.Descriptor, error) {
	return r.Subject, nil
}

func (r *MockRegistryResolver) ImageName(ctx context.Context) (string, error) {
	return r.ImageNameStr, nil
}

func GetMockSigner(ctx context.Context) (dsse.SignerVerifier, error) {
	priv, err := os.ReadFile(filepath.Join("..", "..", "test", "testdata", "test-signing-key.pem"))
	if err != nil {
		return nil, err
	}
	return signerverifier.LoadKeyPair(priv)
}
