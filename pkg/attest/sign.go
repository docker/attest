package attest

import (
	"context"
	"fmt"

	"github.com/docker/attest/pkg/attestation"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// this is only relevant if there are (unsigned) in-toto statements
func SignStatements(ctx context.Context, idx v1.ImageIndex, signer dsse.SignerVerifier, opts *attestation.SigningOptions) ([]*attestation.AttestationManifest, error) {
	// extract attestation manifests from index
	attestationManifests, err := attestation.GetAttestationManifestsFromIndex(idx)
	if err != nil {
		return nil, fmt.Errorf("failed to load attestation manifests from index: %w", err)
	}
	// sign every attestation layer in each manifest
	for _, manifest := range attestationManifests {
		for _, layer := range manifest.Attestation.Layers {
			manifest.AddAttestation(ctx, signer, layer.Statement, opts)
		}
	}
	return attestationManifests, nil
}
