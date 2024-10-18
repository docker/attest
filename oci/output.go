/*
   Copyright Docker attest authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package oci

import (
	"context"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// PushImageToRegistry pushes an image to the registry with the specified name.
func PushImageToRegistry(ctx context.Context, image v1.Image, imageName string) error {
	ref, err := name.ParseReference(imageName)
	if err != nil {
		return fmt.Errorf("Failed to parse image name '%s': %w", imageName, err)
	}

	// Push the image to the registry
	return remote.Write(ref, image, WithOptions(ctx, nil)...)
}

// PushIndexToRegistry pushes an index to the registry with the specified name.
func PushIndexToRegistry(ctx context.Context, index v1.ImageIndex, imageName string) error {
	// Parse the index name
	ref, err := name.ParseReference(imageName)
	if err != nil {
		return fmt.Errorf("Failed to parse image name: %w", err)
	}

	// Push the index to the registry
	return remote.WriteIndex(ref, index, WithOptions(ctx, nil)...)
}

// SaveIndexAsOCILayout saves an image as an OCI layout to the specified path.
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

// SaveIndexAsOCILayout saves an index as an OCI layout to the specified path.
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

// SaveIndex saves an index to the specified outputs.
func SaveIndex(ctx context.Context, outputs []*ImageSpec, index v1.ImageIndex, indexName string) error {
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
			err := PushIndexToRegistry(ctx, index, output.Identifier)
			if err != nil {
				return fmt.Errorf("failed to push signed image: %w", err)
			}
		}
	}
	return nil
}

// SaveImage saves an image to the specified output.
func SaveImage(ctx context.Context, output *ImageSpec, image v1.Image, imageName string) error {
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
		err := PushImageToRegistry(ctx, image, output.Identifier)
		if err != nil {
			return fmt.Errorf("failed to push signed image: %w", err)
		}
	}
	return nil
}

// SaveImagesNoTag saves a list of images by digest to the specified outputs.
func SaveImagesNoTag(ctx context.Context, images []v1.Image, outputs []*ImageSpec) error {
	for _, output := range outputs {
		// OCI layout output not supported
		if output.Type == OCI {
			continue
		}
		for _, image := range images {
			digest, err := image.Digest()
			if err != nil {
				return fmt.Errorf("failed to get image digest: %w", err)
			}
			spec, err := ReplaceDigestInSpec(output, digest)
			if err != nil {
				return fmt.Errorf("failed to create image spec: %w", err)
			}
			err = PushImageToRegistry(ctx, image, spec.Identifier)
			if err != nil {
				return fmt.Errorf("failed to push image: %w", err)
			}
		}
	}
	return nil
}
