package attestation_test

import (
	"context"
	"time"

	"github.com/docker/attest/attestation"
	"github.com/docker/attest/oci"
	"github.com/docker/attest/signerverifier"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
)

func ExampleManifest() {
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
		TransparencyLog: nil, // set this to log to a transparency log
	}

	ref := "docker/image-signer-verifier:latest"

	digest, err := v1.NewHash("sha256:da8b190665956ea07890a0273e2a9c96bfe291662f08e2860e868eef69c34620")
	if err != nil {
		panic(err)
	}
	desc := &v1.Descriptor{
		Digest:    digest,
		Size:      1234,
		MediaType: "application/vnd.oci.image.manifest.v1+json",
	}

	// the in-toto statement to be signed
	statement := &intoto.Statement{
		StatementHeader: intoto.StatementHeader{
			PredicateType: attestation.VSAPredicateType,
			Subject:       []intoto.Subject{{Name: ref, Digest: common.DigestSet{digest.Algorithm: digest.Hex}}},
			Type:          intoto.StatementInTotoV01,
		},
		Predicate: attestation.VSAPredicate{
			Verifier: attestation.VSAVerifier{
				ID: "test-verifier",
			},
			TimeVerified:       time.Now().UTC().Format(time.RFC3339),
			ResourceURI:        "some-uri",
			Policy:             attestation.VSAPolicy{URI: "some-uri"},
			VerificationResult: "PASSED",
			VerifiedLevels:     []string{"SLSA_BUILD_LEVEL_1"},
		},
	}

	// create a new manifest to hold the attestation
	manifest, err := attestation.NewManifest(desc)
	if err != nil {
		panic(err)
	}

	// sign and add the attestation to the manifest
	err = manifest.Add(context.Background(), signer, statement, opts)
	if err != nil {
		panic(err)
	}

	output, err := oci.ParseImageSpecs("docker/image-signer-verifier-referrers:latest")
	if err != nil {
		panic(err)
	}

	// save the manifest to the registry as a referrers artifact
	artifacts, err := manifest.BuildReferringArtifacts()
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	err = oci.SaveImagesNoTag(ctx, artifacts, output)
	if err != nil {
		panic(err)
	}
}
