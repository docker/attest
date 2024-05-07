package mirror

import (
	"fmt"
	"log"
	"os"

	"github.com/docker/attest/internal/embed"
	"github.com/docker/attest/pkg/tuf"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func NewTufMirror(root []byte, tufPath, metadataURL, targetsURL string, versionChecker tuf.VersionChecker) (*TufMirror, error) {
	if root == nil {
		root = embed.DefaultRoot
	}
	tufClient, err := tuf.NewTufClient(root, tufPath, metadataURL, targetsURL, versionChecker)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF client: %w", err)
	}
	return &TufMirror{TufClient: tufClient, tufPath: tufPath, metadataURL: metadataURL, targetsURL: targetsURL}, nil
}

func PushToRegistry(image any, imageName string) error {
	// Parse the image name
	ref, err := name.ParseReference(imageName)
	if err != nil {
		log.Fatalf("Failed to parse image name: %v", err)
	}
	// Get the authenticator from the default Docker keychain
	auth, err := authn.DefaultKeychain.Resolve(ref.Context())
	if err != nil {
		log.Fatalf("Failed to get authenticator: %v", err)
	}
	// Push the image to the registry
	switch image := image.(type) {
	case *v1.Image:
		if err := remote.Write(ref, *image, remote.WithAuth(auth)); err != nil {
			return fmt.Errorf("failed to push image %s: %w", imageName, err)
		}
	case *v1.ImageIndex:
		if err := remote.WriteIndex(ref, *image, remote.WithAuth(auth)); err != nil {
			return fmt.Errorf("failed to push image index %s: %w", imageName, err)
		}
	default:
		if err := remote.WriteIndex(ref, image.(v1.ImageIndex), remote.WithAuth(auth)); err != nil {
			return fmt.Errorf("failed to push image index %s: %w", imageName, err)
		}
	}
	return nil
}

func SaveAsOCILayout(image any, path string) error {
	// Save the image to the local filesystem
	err := os.MkdirAll(path, os.FileMode(0744))
	if err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	switch image := image.(type) {
	case *v1.Image:
		index := empty.Index
		l, err := layout.Write(path, index)
		if err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
		err = l.AppendImage(*image)
		if err != nil {
			return fmt.Errorf("failed to append image to index: %w", err)
		}
	case *v1.ImageIndex:
		_, err := layout.Write(path, *image)
		if err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	default:
		_, err := layout.Write(path, image.(v1.ImageIndex))
		if err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}
	return nil
}
