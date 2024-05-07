package mirror_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/attest/internal/embed"
	"github.com/docker/attest/pkg/mirror"
	"github.com/docker/attest/pkg/tuf"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type TufMirrorOutput struct {
	metadata          *v1.Image
	delegatedMetadata []*mirror.MirrorImage
	targets           []*mirror.MirrorImage
	delegatedTargets  []*mirror.MirrorIndex
}

func ExampleNewTufMirror() {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	tufOutputPath := filepath.Join(home, ".docker", "tuf")

	// configure TUF mirror
	metadataURI := "https://docker.github.io/tuf-staging/metadata"
	targetsURI := "https://docker.github.io/tuf-staging/targets"
	m, err := mirror.NewTufMirror(embed.StagingRoot, tufOutputPath, metadataURI, targetsURI, tuf.NewMockVersionChecker())
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
	targets, err := m.GetTufTargetMirrors()
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
	err = mirrorToRegistry(mirrorOutput)
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

func mirrorToRegistry(o *TufMirrorOutput) error {
	// push metadata to registry
	metadataRepo := "registry-1.docker.io/docker/tuf-metadata:latest"
	err := mirror.PushToRegistry(o.metadata, metadataRepo)
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
		err = mirror.PushToRegistry(metadata.Image, imageName)
		if err != nil {
			return err
		}
	}

	// push top-level targets to registry
	targetsRepo := "registry-1.docker.io/docker/tuf-targets"
	for _, target := range o.targets {
		imageName := fmt.Sprintf("%s:%s", targetsRepo, target.Tag)
		err = mirror.PushToRegistry(target.Image, imageName)
		if err != nil {
			return err
		}
	}
	// push delegated targets to registry
	for _, target := range o.delegatedTargets {
		imageName := fmt.Sprintf("%s:%s", targetsRepo, target.Tag)
		err = mirror.PushToRegistry(target.Index, imageName)
		if err != nil {
			return err
		}
	}
	return nil
}

func mirrorToLocal(o *TufMirrorOutput, outputPath string) error {
	// output metadata to local directory
	err := mirror.SaveAsOCILayout(o.metadata, outputPath)
	if err != nil {
		return err
	}
	// output delegated metadata to local directory
	for _, metadata := range o.delegatedMetadata {
		path := filepath.Join(outputPath, metadata.Tag)
		err = mirror.SaveAsOCILayout(metadata.Image, path)
		if err != nil {
			return err
		}
	}

	// output top-level targets to local directory
	for _, target := range o.targets {
		path := filepath.Join(outputPath, target.Tag)
		err = mirror.SaveAsOCILayout(target.Image, path)
		if err != nil {
			return err
		}
	}
	// output delegated targets to local directory
	for _, target := range o.delegatedTargets {
		path := filepath.Join(outputPath, target.Tag)
		err = mirror.SaveAsOCILayout(target.Index, path)
		if err != nil {
			return err
		}
	}
	return nil
}
