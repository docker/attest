package tuf_test

import (
	"os"
	"path/filepath"

	"github.com/docker/attest/pkg/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func ExampleNewClient_registry() {
	// create a tuf client
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	tufOutputPath := filepath.Join(home, ".docker", "tuf")

	// using oci tuf metadata and targets
	metadataURI := "registry-1.docker.io/docker/tuf-metadata:latest"
	targetsURI := "registry-1.docker.io/docker/tuf-targets"

	registryClient, err := tuf.NewClient(tuf.DockerTUFRootStaging.Data, tufOutputPath, metadataURI, targetsURI, tuf.NewMockVersionChecker())
	if err != nil {
		panic(err)
	}

	// get trusted tuf metadata
	trustedMetadata := registryClient.GetMetadata()

	// top-level target files
	targets := trustedMetadata.Targets[metadata.TARGETS].Signed.Targets

	for _, t := range targets {
		// download target files
		_, err := registryClient.DownloadTarget(t.Path, filepath.Join(tufOutputPath, "download"))
		if err != nil {
			panic(err)
		}
	}
}
