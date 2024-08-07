package mirror

import (
	"fmt"
	"os"

	"github.com/docker/attest/internal/embed"
	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/tuf"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func NewTUFMirror(root []byte, tufPath, metadataURL, targetsURL string, versionChecker tuf.VersionChecker) (*TUFMirror, error) {
	if root == nil {
		root = embed.RootDefault.Data
	}
	tufClient, err := tuf.NewClient(root, tufPath, metadataURL, targetsURL, versionChecker)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF client: %w", err)
	}
	return &TUFMirror{TUFClient: tufClient, tufPath: tufPath, metadataURL: metadataURL, targetsURL: targetsURL}, nil
}

func PushImageToRegistry(image v1.Image, imageName string) error {
	ref, err := name.ParseReference(imageName)
	if err != nil {
		return fmt.Errorf("Failed to parse image name '%s': %w", imageName, err)
	}

	// Push the image to the registry
	return remote.Write(ref, image, oci.MultiKeychainOption())
}

func PushIndexToRegistry(index v1.ImageIndex, imageName string) error {
	// Parse the index name
	ref, err := name.ParseReference(imageName)
	if err != nil {
		return fmt.Errorf("Failed to parse image name: %w", err)
	}

	// Push the index to the registry
	return remote.WriteIndex(ref, index, oci.MultiKeychainOption())
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

func SaveIndex(outputs []*oci.ImageSpec, index v1.ImageIndex, indexName string) error {
	// split output by comma and write or push each one
	for _, output := range outputs {
		if output.Type == oci.OCI {
			idx := v1.ImageIndex(empty.Index)
			idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
				Add: index,
				Descriptor: v1.Descriptor{
					Annotations: map[string]string{
						oci.OCIReferenceTarget: indexName,
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

func SaveImage(output *oci.ImageSpec, image v1.Image, imageName string) error {
	if output.Type == oci.OCI {
		idx := v1.ImageIndex(empty.Index)
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add: image,
			Descriptor: v1.Descriptor{
				Annotations: map[string]string{
					oci.OCIReferenceTarget: imageName,
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

func SaveReferrers(manifest *attestation.Manifest, outputs []*oci.ImageSpec) error {
	for _, output := range outputs {
		// OCI layout output for referrers not supported
		if output.Type == oci.OCI {
			continue
		}
		// so that we use the same tag each time to reduce number of tags (tags aren't needed for referrers but we must push one)
		// attOut, err := oci.ReplaceTagInSpec(output, manifest.SubjectDescriptor.Digest)
		// if err != nil {
		// 	return err
		// }
		images, err := manifest.BuildReferringArtifacts()
		if err != nil {
			return fmt.Errorf("failed to build image: %w", err)
		}
		for _, image := range images {
			layers, err := image.Layers()
			if err != nil {
				return fmt.Errorf("failed to get attestation image layers: %w", err)
			}
			digest, err := layers[0].Digest()
			if err != nil {
				return fmt.Errorf("failed to get attestation image digest: %w", err)
			}
			digest2, _ := image.Digest()
			fmt.Printf("digest: %s, digest2: %s\n", digest, digest2)
			attOut, err := oci.ReplaceDigestInSpec(output, digest2)
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
