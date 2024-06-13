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

func Sign(ctx context.Context, idx v1.ImageIndex, signer dsse.SignerVerifier, opts *attestation.SigningOptions) (v1.ImageIndex, error) {
	images, err := SignedAttestationImages(ctx, idx, signer, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign attestation images: %w", err)
	}
	for _, image := range images {
		idx, err = addImageToIndex(ctx, idx, image.Image, image.Descriptor, image.AttestationManifest)
		if err != nil {
			return nil, fmt.Errorf("failed to add signed layers to index: %w", err)
		}
	}
	return idx, nil
}

func SignedAttestationImages(ctx context.Context, idx v1.ImageIndex, signer dsse.SignerVerifier, opts *attestation.SigningOptions) ([]*attestation.SignedAttestationImage, error) {
	// extract attestation manifests from index
	attestationManifests, err := attestation.GetAttestationManifestsFromIndex(idx)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation manifests: %w", err)
	}
	if len(attestationManifests) == 0 {
		return nil, fmt.Errorf("no attestation manifests found")
	}
	images := []*attestation.SignedAttestationImage{}
	// sign every attestation layer in each manifest
	for _, manifest := range attestationManifests {
		newImg, newDescriptor, err := ImageWithAttestations(ctx, manifest.Attestation.Layers, manifest, signer, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to add signed layers to image: %w", err)
		}
		images = append(images, &attestation.SignedAttestationImage{
			Image:               newImg,
			Descriptor:          newDescriptor,
			AttestationManifest: manifest,
		})
	}
	return images, nil
}

func AddAttestation(ctx context.Context, idx v1.ImageIndex, statement *intoto.Statement, signer dsse.SignerVerifier) (v1.ImageIndex, error) {
	if len(statement.Subject) == 0 {
		return nil, fmt.Errorf("statement has no subjects")
	}

	subjectDigests := make(map[string]bool)
	for _, subject := range statement.Subject {
		subjectDigest := fmt.Sprintf("sha256:%s", subject.Digest["sha256"])
		subjectDigests[subjectDigest] = true
	}

	attestationManifests, err := attestation.GetAttestationManifestsFromIndex(idx)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation manifests: %w", err)
	}
	updatedIndex := false
	for _, manifest := range attestationManifests {
		if subjectDigests[manifest.Annotations[attestation.DockerReferenceDigest]] {
			attestationLayers := []attestation.AttestationLayer{
				{
					Statement: statement,
					MediaType: types.MediaType(intoto.PayloadType),
					Annotations: map[string]string{
						oci.InTotoPredicateType: statement.PredicateType,
					},
				},
			}
			// hard-coding replace to false here, because if it's true we will remove any unsigned statements, even unrelated ones
			newImg, newDec, err := ImageWithAttestations(ctx, attestationLayers, manifest, signer, &attestation.SigningOptions{Replace: false})
			if err != nil {
				return nil, fmt.Errorf("failed to add signed layers to image: %w", err)
			}
			idx, err = addImageToIndex(ctx, idx, newImg, newDec, manifest)
			updatedIndex = true
		}
	}
	if !updatedIndex {
		return nil, fmt.Errorf("no attestation manifest found for statement")
	}
	return idx, nil
}

func ImageWithAttestations(
	ctx context.Context,
	attestationLayers []attestation.AttestationLayer,
	manifest attestation.AttestationManifest,
	signer dsse.SignerVerifier,
	opts *attestation.SigningOptions) (v1.Image, *v1.Descriptor, error) {

	signedLayers, err := signLayers(ctx, attestationLayers, signer, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign attestations: %w", err)
	}

	newImg, err := addSignedLayers(signedLayers, manifest, opts)
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

func addImageToIndex(
	ctx context.Context,
	idx v1.ImageIndex,
	img v1.Image,
	desc *v1.Descriptor,
	manifest attestation.AttestationManifest,
) (v1.ImageIndex, error) {

	idx = mutate.RemoveManifests(idx, match.Digests(manifest.Digest))
	idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
		Add:        img,
		Descriptor: *desc,
	})
	return idx, nil
}

// signLayers signs each intoto attestation layer with the given signer
func signLayers(ctx context.Context, layers []attestation.AttestationLayer, signer dsse.SignerVerifier, opts *attestation.SigningOptions) ([]mutate.Addendum, error) {
	var signedLayers []mutate.Addendum
	for _, layer := range layers {
		// only sign intoto layers
		if layer.MediaType != types.MediaType(intoto.PayloadType) {
			continue
		}
		// mark attestation as experimental
		layer.Annotations[InTotoReferenceLifecycleStage] = LifecycleStageExperimental

		// sign the statement
		env, err := signInTotoStatement(ctx, layer.Statement, signer, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to sign statement: %w", err)
		}

		mediaType, err := attestation.DSSEMediaType(layer.Statement.PredicateType)
		if err != nil {
			return nil, fmt.Errorf("failed to get DSSE media type: %w", err)
		}
		data, err := json.Marshal(env)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal envelope: %w", err)
		}
		newLayer := static.NewLayer(data, types.MediaType(mediaType))
		withAnnotations := mutate.Addendum{
			Layer:       newLayer,
			Annotations: layer.Annotations,
		}
		signedLayers = append(signedLayers, withAnnotations)
	}
	return signedLayers, nil
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

// addSignedLayers adds signed layers to a new or existing attestation image
func addSignedLayers(signedLayers []mutate.Addendum, manifest attestation.AttestationManifest, opts *attestation.SigningOptions) (v1.Image, error) {
	withAnnotations := func(img v1.Image) v1.Image {
		// this is handy when dealing with referrers
		return mutate.Annotations(img, map[string]string{
			attestation.DockerReferenceType:   attestation.AttestationManifestType,
			attestation.DockerReferenceDigest: manifest.SubjectDescriptor.Digest.String(),
		}).(v1.Image)
	}
	var err error
	if opts.Replace {
		// create a new attestation image with only signed layers
		newImg := empty.Image
		newImg = mutate.MediaType(newImg, manifest.MediaType)
		newImg = mutate.ConfigMediaType(newImg, "application/vnd.oci.image.config.v1+json")
		for _, layer := range signedLayers {
			newImg, err = mutate.Append(newImg, layer)
			if err != nil {
				return nil, fmt.Errorf("failed to append signed layer: %w", err)
			}
		}
		// add any existing unsigned (non-intoto) layers to the new image
		for _, layer := range manifest.Attestation.Layers {
			if layer.MediaType != types.MediaType(intoto.PayloadType) {
				newImg, err = mutate.AppendLayers(newImg, layer.Layer)
				if err != nil {
					return nil, fmt.Errorf("failed to append unsigned layer: %w", err)
				}
			}
		}
		return withAnnotations(newImg), nil
	}
	// Add signed layers to the existing image
	for _, layer := range signedLayers {
		manifest.Attestation.Image, err = mutate.Append(manifest.Attestation.Image, layer)
		if err != nil {
			return nil, fmt.Errorf("failed to append layer: %w", err)
		}
	}
	return withAnnotations(manifest.Attestation.Image), nil
}
