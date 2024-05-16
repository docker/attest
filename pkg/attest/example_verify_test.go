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

	return tuf.NewTufClient(embed.StagingRoot, outputPath, metadataURI, targetsURI)
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
	resolver := &oci.RegistryResolver{
		Image:    image,    // path to image index in OCI registry containing image attestations
		Platform: platform, // platform of subject image (image that attestations are being verified against)
	}
	// example using a local resolver
	// path := "/myimage"
	// platform := "linux/amd64"
	// resolver := &oci.OCILayoutResolver{
	// 	Path:     path,     // file path to OCI layout containing image attestations
	// 	Platform: platform, // platform of subject image (image that attestations are being verified against)
	// }

	// configure policy options
	opts := &policy.PolicyOptions{
		TufClient:       tufClient,
		LocalTargetsDir: filepath.Join(home, ".docker", "policy"), // location to store policy files downloaded from TUF
		LocalPolicyDir:  "",                                       // overrides TUF policy for local policy files if set
	}

	// verify attestations
	policy, err := attest.Verify(context.Background(), opts, resolver)
	if err != nil {
		panic(err) // failed policy or attestation signature verification
	}
	if policy.Success {
		fmt.Println("policy passed")
		return // passed policy
	}
	// no policy found for image
	fmt.Println("no policy for image")

	// Output: policy passed
}
