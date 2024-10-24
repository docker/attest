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

package attest_test

import (
	"context"

	"github.com/docker/attest"
	"github.com/docker/attest/attestation"
	"github.com/docker/attest/oci"
	"github.com/docker/attest/signerverifier"
	"github.com/docker/attest/tlog"
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

	// use rekor transparency log wit static rekor public key (see options to use dynamic rekor public key)
	rekor, err := tlog.NewRekorLog()
	if err != nil {
		panic(err)
	}
	opts := &attestation.SigningOptions{
		TransparencyLog: rekor, // unset this to disable signature transparency logging
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
