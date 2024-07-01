package attest

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/oci"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/match"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func AddAttestationToImage(ctx context.Context, manifest *attestation.AttestationManifest, layer *attestation.AttestationLayer, opts *attestation.SigningOptions) error {
	newImg, newDesc, err := addLayerToImage(ctx, manifest, layer, opts)
	if err != nil {
		return fmt.Errorf("failed to add signed layers to image: %w", err)
	}
	manifest.Attestation.Image = newImg
	manifest.Descriptor = newDesc
	return nil
}

func addLayerToImage(
	ctx context.Context,
	manifest *attestation.AttestationManifest,
	layer *attestation.AttestationLayer,
	opts *attestation.SigningOptions) (v1.Image, *v1.Descriptor, error) {

	newImg, err := AddOrReplaceLayer(layer, manifest, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to add signed layers: %w", err)
	}
	if !opts.SkipSubject {
		newImg = mutate.Subject(newImg, *manifest.SubjectDescriptor).(v1.Image)
	}
	newDesc, err := partial.Descriptor(newImg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get descriptor: %w", err)
	}
	cf, err := manifest.Attestation.Image.ConfigFile()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get config file: %w", err)
	}
	newDesc.Platform = cf.Platform()
	if newDesc.Platform == nil {
		newDesc.Platform = &v1.Platform{
			Architecture: "unknown",
			OS:           "unknown",
		}
	}
	newDesc.MediaType = manifest.MediaType
	newDesc.Annotations = manifest.Annotations
	return newImg, newDesc, nil
}

func AddImageToIndex(
	idx v1.ImageIndex,
	manifest *attestation.AttestationManifest,
) (v1.ImageIndex, error) {
	idx = mutate.RemoveManifests(idx, match.Digests(manifest.Digest))
	idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
		Add:        manifest.Attestation.Image,
		Descriptor: *manifest.Descriptor,
	})
	return idx, nil
}

// create a signed image layer for the statement
func CreateSignedImageLayer(ctx context.Context, statement *intoto.Statement, signer dsse.SignerVerifier, opts *attestation.SigningOptions) (*attestation.AttestationLayer, error) {

	// sign the statement
	env, err := signInTotoStatement(ctx, statement, signer, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign statement: %w", err)
	}

	mediaType, err := attestation.DSSEMediaType(statement.PredicateType)
	if err != nil {
		return nil, fmt.Errorf("failed to get DSSE media type: %w", err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal envelope: %w", err)
	}
	return &attestation.AttestationLayer{
		Statement: statement,
		MediaType: types.MediaType(intoto.PayloadType),
		Annotations: map[string]string{
			oci.InTotoPredicateType:       statement.PredicateType,
			InTotoReferenceLifecycleStage: LifecycleStageExperimental,
		},
		Layer: static.NewLayer(data, types.MediaType(mediaType)),
	}, nil
}

func signInTotoStatement(ctx context.Context, statement *intoto.Statement, signer dsse.SignerVerifier, opts *attestation.SigningOptions) (*attestation.Envelope, error) {
	payload, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal statement: %w", err)
	}
	env, err := attestation.SignDSSE(ctx, payload, signer, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign statement: %w", err)
	}
	return env, nil
}

// AddOrReplaceLayer adds signed layers to a new or existing attestation image
func AddOrReplaceLayer(signedLayer *attestation.AttestationLayer, manifest *attestation.AttestationManifest, opts *attestation.SigningOptions) (v1.Image, error) {
	withAnnotations := func(img v1.Image) v1.Image {
		// this is handy when dealing with referrers
		return mutate.Annotations(img, map[string]string{
			attestation.DockerReferenceType:   attestation.AttestationManifestType,
			attestation.DockerReferenceDigest: manifest.SubjectDescriptor.Digest.String(),
		}).(v1.Image)
	}
	var err error
	// always create a new image from all the layers
	newImg := empty.Image
	newImg = mutate.MediaType(newImg, manifest.MediaType)
	newImg = mutate.ConfigMediaType(newImg, "application/vnd.oci.image.config.v1+json")
	add := mutate.Addendum{
		Layer:       signedLayer.Layer,
		Annotations: signedLayer.Annotations,
	}
	newImg, err = mutate.Append(newImg, add)
	if err != nil {
		return nil, fmt.Errorf("failed to add signed layer to image: %w", err)
	}
	layers := make([]*attestation.AttestationLayer, 0)
	for _, layer := range manifest.Attestation.Layers {
		if layer.Statement == signedLayer.Statement && opts.Replace {
			continue
		}
		add := mutate.Addendum{
			Layer:       layer.Layer,
			Annotations: layer.Annotations,
		}
		newImg, err = mutate.Append(newImg, add)
		layers = append(layers, layer)
		if err != nil {
			return nil, fmt.Errorf("failed to add layer to image: %w", err)
		}
	}
	manifest.Attestation.Layers = append(layers, signedLayer)
	manifest.Attestation.Image = newImg
	return withAnnotations(manifest.Attestation.Image), nil
}
