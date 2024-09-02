package attest_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/docker/attest"
	"github.com/docker/attest/oci"
	"github.com/docker/attest/policy"
	"github.com/docker/attest/tuf"
)

func ExampleVerify_remote() {
	// create a tuf client
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	tufOutputPath := filepath.Join(home, ".docker", "tuf")
	tufClientOpts := tuf.NewDockerDefaultClientOptions(tufOutputPath)

	// create a resolver for remote attestations
	image := "registry-1.docker.io/library/notary:server"
	platform := "linux/amd64"

	// configure policy options
	opts := &policy.Options{
		TUFClientOptions: tufClientOpts,
		LocalTargetsDir:  filepath.Join(home, ".docker", "policy"), // location to store policy files downloaded from TUF
		LocalPolicyDir:   "",                                       // overrides TUF policy for local policy files if set
		PolicyID:         "",                                       // set to ignore policy mapping and select a policy by id
		DisableTUF:       false,                                    // set to disable TUF and rely on local policy files
	}

	src, err := oci.ParseImageSpec(image, oci.WithPlatform(platform))
	if err != nil {
		panic(err)
	}
	// verify attestations
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
