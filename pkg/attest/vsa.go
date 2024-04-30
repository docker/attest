package attest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/oci"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func generateVSA(ctx context.Context, image v1.Image, stmt []*intoto.Statement, signer dsse.SignerVerifier, opts *SigningOptions) (*mutate.Addendum, error) {
	if len(stmt) == 0 {
		return nil, fmt.Errorf("no attestations found to generate VSA from")
	}
	sub := stmt[0].Subject[0]
	stype := stmt[0].Type

	uri, err := attestation.ToVSAResourceURI(sub)
	if err != nil {
		return nil, fmt.Errorf("failed to generate VSA resource URI: %w", err)
	}

	inputs := make([]attestation.VSAInputAttestation, 0, len(stmt))
	layers, err := image.Layers()
	if err != nil {
		return nil, fmt.Errorf("failed to get layers: %w", err)
	}
	for _, layer := range layers {
		mt, err := layer.MediaType()
		if err != nil {
			return nil, fmt.Errorf("failed to get layer media type: %w", err)
		}
		mediaType := string(mt)
		if !strings.HasPrefix(mediaType, "application/vnd.in-toto.") ||
			!strings.HasSuffix(mediaType, "+dsse") {
			continue
		}

		dgst, err := layer.Digest()
		if err != nil {
			return nil, fmt.Errorf("failed to get layer digest: %w", err)
		}
		inputs = append(inputs, attestation.VSAInputAttestation{
			Digest:    map[string]string{"sha256": dgst.Hex},
			MediaType: string(mt),
		})
	}
	vsaStatement := &intoto.Statement{
		StatementHeader: intoto.StatementHeader{
			PredicateType: attestation.VSAPredicateType,
			Type:          stype,
			Subject:       stmt[0].Subject,
		},
		Predicate: attestation.VSAPredicate{
			Verifier: attestation.VSAVerifier{
				ID: opts.VSAOptions.VerifierID,
			},
			TimeVerified:       time.Now().UTC().Format(time.RFC3339),
			ResourceUri:        uri,
			Policy:             attestation.VSAPolicy{URI: opts.VSAOptions.PolicyURI},
			VerificationResult: "PASSED",
			VerifiedLevels:     []string{opts.VSAOptions.BuildLevel},
			InputAttestations:  inputs,
		},
	}
	payload, err := json.Marshal(vsaStatement)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal statement: %w", err)
	}
	env, err := attestation.SignDSSE(ctx, payload, intoto.PayloadType, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to sign statement: %w", err)
	}
	mediaType, err := attestation.DSSEMediaType(vsaStatement.PredicateType)
	if err != nil {
		return nil, fmt.Errorf("failed to get DSSE media type: %w", err)
	}

	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal envelope: %w", err)
	}
	mt := types.MediaType(mediaType)
	newLayer := static.NewLayer(data, mt)
	ann := make(map[string]string)
	ann[InTotoReferenceLifecycleStage] = LifecycleStageExperimental
	ann[oci.InTotoPredicateType] = attestation.VSAPredicateType
	withAnnotations := mutate.Addendum{
		Layer:       newLayer,
		Annotations: ann,
	}
	return &withAnnotations, nil
}
