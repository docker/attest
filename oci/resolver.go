package oci

import (
	"context"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type ImageDetailsResolver interface {
	ImageName(ctx context.Context) (string, error)
	ImagePlatform(ctx context.Context) (*v1.Platform, error)
	ImageDescriptor(ctx context.Context) (*v1.Descriptor, error)
}
