package tuf_test

import (
	"context"
	"os"
	"path/filepath"

	"github.com/docker/attest/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func ExampleNewClient_registry() {
	// create a tuf client
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	tufOutputPath := filepath.Join(home, ".docker", "tuf")

	opts := tuf.NewDockerDefaultClientOptions(tufOutputPath)
	registryClient, err := tuf.NewClient(context.Background(), opts)
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
