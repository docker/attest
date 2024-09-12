package attest_test

import (
	"context"

	"github.com/docker/attest"
	"github.com/docker/attest/attestation"
	"github.com/docker/attest/oci"
	"github.com/docker/attest/signerverifier"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

func ExampleSignStatements_remote() {
	// configure signerverifier
	// local signer (unsafe for production)
	signer, err := signerverifier.GenKeyPair()
	if err != nil {
		panic(err)
	}
	// example using AWS KMS signer
	// aws_arn := "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
	// aws_region := "us-west-2"
	// signer, err := signerverifier.GetAWSSigner(cmd.Context(), aws_arn, aws_region)

	// configure signing options
	opts := &attestation.SigningOptions{
		TransparencyLogger: nil, // set this to log to a transparency log
	}

	// load image index with unsigned attestation-manifests
	ref := "docker/image-signer-verifier:latest"
	attIdx, err := oci.IndexFromRemote(context.Background(), ref)
	if err != nil {
		panic(err)
	}
	// example for local image index
	// path := "/myimage"
	// attIdx, err = oci.IndexFromPath(path)
	// if err != nil {
	// 	panic(err)
	// }

	// sign all attestations in an image index
	signedManifests, err := attest.SignStatements(context.Background(), attIdx.Index, signer, opts)
	if err != nil {
		panic(err)
	}
	signedIndex := attIdx.Index
	signedIndex, err = attestation.UpdateIndexImages(signedIndex, signedManifests)
	if err != nil {
		panic(err)
	}

	// push image index with signed attestation-manifests
	err = oci.PushIndexToRegistry(context.Background(), signedIndex, ref)
	if err != nil {
		panic(err)
	}
	// output image index to filesystem (optional)
	path := "/myimage"
	idx := v1.ImageIndex(empty.Index)
	idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
		Add: signedIndex,
		Descriptor: v1.Descriptor{
			Annotations: map[string]string{
				oci.OCIReferenceTarget: attIdx.Name,
			},
		},
	})
	err = oci.SaveIndexAsOCILayout(idx, path)
	if err != nil {
		panic(err)
	}
}
