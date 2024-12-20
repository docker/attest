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

package mirror_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/attest/mirror"
	"github.com/docker/attest/oci"
	"github.com/docker/attest/tuf"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type TufMirrorOutput struct {
	metadata          v1.Image
	delegatedMetadata []*mirror.Image
	targets           []*mirror.Image
	delegatedTargets  []*mirror.Index
}

func ExampleNewTUFMirror() {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	tufOutputPath := filepath.Join(home, ".docker", "tuf")

	// configure TUF mirror
	metadataURI := "https://docker.github.io/tuf-staging/metadata"
	targetsURI := "https://docker.github.io/tuf-staging/targets"
	ctx := context.Background()
	m, err := mirror.NewTUFMirror(ctx, tuf.DockerTUFRootStaging.Data, tufOutputPath, metadataURI, targetsURI, tuf.NewMockVersionChecker())
	if err != nil {
		panic(err)
	}

	// create metadata manifest
	metadataManifest, err := m.GetMetadataManifest(metadataURI)
	if err != nil {
		panic(err)
	}
	// create delegated targets metadata manifests
	delegatedMetadata, err := m.GetDelegatedMetadataMirrors()
	if err != nil {
		panic(err)
	}

	// create targets manifest
	targets, err := m.GetTUFTargetMirrors()
	if err != nil {
		panic(err)
	}
	// create delegated targets manifests
	delegatedTargets, err := m.GetDelegatedTargetMirrors()
	if err != nil {
		panic(err)
	}

	mirrorOutput := &TufMirrorOutput{
		metadata:          metadataManifest,
		delegatedMetadata: delegatedMetadata,
		targets:           targets,
		delegatedTargets:  delegatedTargets,
	}

	// push metadata and targets to registry (optional)
	err = mirrorToRegistry(ctx, mirrorOutput)
	if err != nil {
		panic(err)
	}

	// save metadata and targets to local directory (optional)
	mirrorOutputPath := filepath.Join(home, ".docker", "tuf", "mirror")
	err = mirrorToLocal(mirrorOutput, mirrorOutputPath)
	if err != nil {
		panic(err)
	}
}

func mirrorToRegistry(ctx context.Context, o *TufMirrorOutput) error {
	// push metadata to registry
	metadataRepo := "registry-1.docker.io/docker/tuf-metadata:latest"
	err := oci.PushImageToRegistry(ctx, o.metadata, metadataRepo)
	if err != nil {
		return err
	}
	// push delegated metadata to registry
	for _, metadata := range o.delegatedMetadata {
		repo, _, ok := strings.Cut(metadataRepo, ":")
		if !ok {
			return fmt.Errorf("failed to get repo without tag: %s", metadataRepo)
		}
		imageName := fmt.Sprintf("%s:%s", repo, metadata.Tag)
		err = oci.PushImageToRegistry(ctx, metadata.Image, imageName)
		if err != nil {
			return err
		}
	}

	// push top-level targets to registry
	targetsRepo := "registry-1.docker.io/docker/tuf-targets"
	for _, target := range o.targets {
		imageName := fmt.Sprintf("%s:%s", targetsRepo, target.Tag)
		err = oci.PushImageToRegistry(ctx, target.Image, imageName)
		if err != nil {
			return err
		}
	}
	// push delegated targets to registry
	for _, target := range o.delegatedTargets {
		imageName := fmt.Sprintf("%s:%s", targetsRepo, target.Tag)
		err = oci.PushIndexToRegistry(ctx, target.Index, imageName)
		if err != nil {
			return err
		}
	}
	return nil
}

func mirrorToLocal(o *TufMirrorOutput, outputPath string) error {
	// output metadata to local directory
	err := oci.SaveImageAsOCILayout(o.metadata, outputPath)
	if err != nil {
		return err
	}
	// output delegated metadata to local directory
	for _, metadata := range o.delegatedMetadata {
		path := filepath.Join(outputPath, metadata.Tag)
		err = oci.SaveImageAsOCILayout(metadata.Image, path)
		if err != nil {
			return err
		}
	}

	// output top-level targets to local directory
	for _, target := range o.targets {
		path := filepath.Join(outputPath, target.Tag)
		err = oci.SaveImageAsOCILayout(target.Image, path)
		if err != nil {
			return err
		}
	}
	// output delegated targets to local directory
	for _, target := range o.delegatedTargets {
		path := filepath.Join(outputPath, target.Tag)
		err = oci.SaveIndexAsOCILayout(target.Index, path)
		if err != nil {
			return err
		}
	}
	return nil
}
