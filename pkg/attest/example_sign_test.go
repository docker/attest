package attest_test

import (
	"context"

	"github.com/docker/attest/pkg/attest"
	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/mirror"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/signerverifier"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

func ExampleSign_remote() {
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
		Replace: true, // replace unsigned intoto statements with signed intoto attestations, otherwise leave in place
	}

	// load image index with unsigned attestation-manifests
	ref := "docker/image-signer-verifier:latest"
	att, err := oci.SubjectIndexFromRemote(ref)
	if err != nil {
		panic(err)
	}
	// example for local image index
	// path := "/myimage"
	// att, err := oci.AttestationIndexFromLocal(path)

	// sign attestations
	signedImageIndex, err := attest.Sign(context.Background(), att.Index, signer, opts)
	if err != nil {
		panic(err)
	}

	// push image index with signed attestation-manifests
	err = mirror.PushToRegistry(signedImageIndex, ref)
	if err != nil {
		panic(err)
	}
	// output image index to filesystem (optional)
	path := "/myimage"
	idx := v1.ImageIndex(empty.Index)
	idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
		Add: signedImageIndex,
		Descriptor: v1.Descriptor{
			Annotations: map[string]string{
				oci.OciReferenceTarget: att.Name,
			},
		},
	})
	err = mirror.SaveAsOCILayout(idx, path)
	if err != nil {
		panic(err)
	}
}
