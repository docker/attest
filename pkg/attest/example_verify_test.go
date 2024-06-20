package attest_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/docker/attest/internal/embed"
	"github.com/docker/attest/pkg/attest"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/policy"
	"github.com/docker/attest/pkg/tuf"
)

func createTufClient(outputPath string) (*tuf.TufClient, error) {
	// using oci tuf metadata and targets
	metadataURI := "registry-1.docker.io/docker/tuf-metadata:latest"
	targetsURI := "registry-1.docker.io/docker/tuf-targets"
	// example using http tuf metadata and targets
	// metadataURI := "https://docker.github.io/tuf-staging/metadata"
	// targetsURI := "https://docker.github.io/tuf-staging/targets"

	return tuf.NewTufClient(embed.StagingRoot, outputPath, metadataURI, targetsURI, tuf.NewMockVersionChecker())
}

func ExampleVerify_remote() {
	// create a tuf client
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	tufOutputPath := filepath.Join(home, ".docker", "tuf")
	tufClient, err := createTufClient(tufOutputPath)
	if err != nil {
		panic(err)
	}

	// create a resolver for remote attestations
	image := "registry-1.docker.io/library/notary:server"
	platform := "linux/amd64"

	// configure policy options
	opts := &policy.PolicyOptions{
		TufClient:       tufClient,
		LocalTargetsDir: filepath.Join(home, ".docker", "policy"), // location to store policy files downloaded from TUF
		LocalPolicyDir:  "",                                       // overrides TUF policy for local policy files if set
		PolicyId:        "",                                       // set to ignore policy mapping and select a policy by id
	}

	// verify attestations
	src, err := oci.ParseImageSpec(image, oci.WithPlatform(platform))
	if err != nil {
		panic(err)
	}
	result, err := attest.Verify(context.Background(), src, opts)
	if err != nil {
		panic(err)
	}
	switch result.Outcome {
	case attest.OutcomeSuccess:
		fmt.Println("policy passed")
	case attest.OutcomeNoPolicy:
		fmt.Println("no policy for image")
	case attest.OutcomeFailure:
		fmt.Println("policy failed")
	}
}
