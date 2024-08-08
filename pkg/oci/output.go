package oci

import (
	"fmt"
	"os"

	"github.com/docker/attest/pkg/attestation"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func PushImageToRegistry(image v1.Image, imageName string) error {
	ref, err := name.ParseReference(imageName)
	if err != nil {
		return fmt.Errorf("Failed to parse image name '%s': %w", imageName, err)
	}

	// Push the image to the registry
	return remote.Write(ref, image, MultiKeychainOption())
}

func PushIndexToRegistry(index v1.ImageIndex, imageName string) error {
	// Parse the index name
	ref, err := name.ParseReference(imageName)
	if err != nil {
		return fmt.Errorf("Failed to parse image name: %w", err)
	}

	// Push the index to the registry
	return remote.WriteIndex(ref, index, MultiKeychainOption())
}

func SaveImageAsOCILayout(image v1.Image, path string) error {
	// Save the image to the local filesystem
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	index := empty.Index
	l, err := layout.Write(path, index)
	if err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}
	return l.AppendImage(image)
}

func SaveIndexAsOCILayout(image v1.ImageIndex, path string) error {
	// Save the index to the local filesystem
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	_, err = layout.Write(path, image)
	if err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}
	return nil
}

func SaveIndex(outputs []*ImageSpec, index v1.ImageIndex, indexName string) error {
	// split output by comma and write or push each one
	for _, output := range outputs {
		if output.Type == OCI {
			idx := v1.ImageIndex(empty.Index)
			idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
				Add: index,
				Descriptor: v1.Descriptor{
					Annotations: map[string]string{
						OCIReferenceTarget: indexName,
					},
				},
			})
			err := SaveIndexAsOCILayout(idx, output.Identifier)
			if err != nil {
				return fmt.Errorf("failed to write signed image: %w", err)
			}
		} else {
			err := PushIndexToRegistry(index, output.Identifier)
			if err != nil {
				return fmt.Errorf("failed to push signed image: %w", err)
			}
		}
	}
	return nil
}

func SaveImage(output *ImageSpec, image v1.Image, imageName string) error {
	if output.Type == OCI {
		idx := v1.ImageIndex(empty.Index)
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add: image,
			Descriptor: v1.Descriptor{
				Annotations: map[string]string{
					OCIReferenceTarget: imageName,
				},
			},
		})
		err := SaveIndexAsOCILayout(idx, output.Identifier)
		if err != nil {
			return fmt.Errorf("failed to write signed image: %w", err)
		}
	} else {
		err := PushImageToRegistry(image, output.Identifier)
		if err != nil {
			return fmt.Errorf("failed to push signed image: %w", err)
		}
	}
	return nil
}

func SaveReferrers(manifest *attestation.Manifest, outputs []*ImageSpec) error {
	for _, output := range outputs {
		// OCI layout output for referrers not supported
		if output.Type == OCI {
			continue
		}
		images, err := manifest.BuildReferringArtifacts()
		if err != nil {
			return fmt.Errorf("failed to build image: %w", err)
		}
		for _, image := range images {
			digest, err := image.Digest()
			if err != nil {
				return fmt.Errorf("failed to get attestation image digest: %w", err)
			}
			attOut, err := ReplaceDigestInSpec(output, digest)
			if err != nil {
				return fmt.Errorf("failed to create attestation image spec: %w", err)
			}
			err = PushImageToRegistry(image, attOut.Identifier)
			if err != nil {
				return fmt.Errorf("failed to push image: %w", err)
			}
		}
	}
	return nil
}