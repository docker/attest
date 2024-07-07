package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"

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

// GetAttestationManifestsFromIndex extracts all attestation manifests from an index
func GetAttestationManifestsFromIndex(index v1.ImageIndex) ([]*AttestationManifest, error) {
	idx, err := index.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to extract IndexManifest from ImageIndex: %w", err)
	}
	subjects := make(map[string]*v1.Descriptor)
	for _, subject := range idx.Manifests {
		subjects[subject.Digest.String()] = &subject
	}

	var attestationManifests []*AttestationManifest
	for _, desc := range idx.Manifests {
		if desc.Annotations[DockerReferenceType] == AttestationManifestType {
			subject := subjects[desc.Annotations[DockerReferenceDigest]]
			if subject == nil {
				return nil, fmt.Errorf("failed to find subject for attestation manifest: %w", err)
			}
			attestationImage, err := index.Image(desc.Digest)
			if err != nil {
				return nil, fmt.Errorf("failed to extract attestation image with digest %s: %w", desc.Digest.String(), err)
			}
			attestationLayers, err := GetAttestationsFromImage(attestationImage)
			if err != nil {
				return nil, fmt.Errorf("failed to get attestations from image: %w", err)
			}
			attestationManifests = append(attestationManifests,
				&AttestationManifest{
					OriginalDescriptor: &desc,
					SubjectDescriptor:  subject,
					AttestationImage: &AttestationImage{
						Layers:     attestationLayers,
						Descriptor: &desc}})
		}
	}
	return attestationManifests, nil
}

// GetAttestationsFromImage extracts all attestation layers from an image
func GetAttestationsFromImage(image v1.Image) ([]*AttestationLayer, error) {
	layers, err := image.Layers()
	if err != nil {
		return nil, fmt.Errorf("failed to extract layers from image: %w", err)
	}
	var attestationLayers []*AttestationLayer
	for _, layer := range layers {
		// parse layer blob as json
		r, err := layer.Uncompressed()
		if err != nil {
			return nil, fmt.Errorf("failed to get layer contents: %w", err)
		}
		defer r.Close()
		mt, err := layer.MediaType()
		if err != nil {
			return nil, fmt.Errorf("failed to get layer media type: %w", err)
		}
		layerDesc, err := partial.Descriptor(layer)
		if err != nil {
			return nil, fmt.Errorf("failed to get descriptor for layer: %w", err)
		}
		// copy original annotations
		ann := maps.Clone(layerDesc.Annotations)
		// only decode intoto statements
		var stmt = new(intoto.Statement)
		if mt == types.MediaType(intoto.PayloadType) {
			err = json.NewDecoder(r).Decode(&stmt)
			if err != nil {
				return nil, fmt.Errorf("failed to decode statement layer contents: %w", err)
			}
		}
		attestationLayers = append(attestationLayers, &AttestationLayer{Layer: layer, Statement: stmt, Annotations: ann})
	}
	return attestationLayers, nil
}

func (manifest *AttestationManifest) AddAttestation(ctx context.Context, signer dsse.SignerVerifier, statement *intoto.Statement, opts *SigningOptions) error {
	layer, err := createSignedImageLayer(ctx, statement, signer, opts)
	if err != nil {
		return fmt.Errorf("failed to create signed layer: %w", err)
	}
	return addLayerToImage(manifest, layer, opts)
}

func createSignedImageLayer(ctx context.Context, statement *intoto.Statement, signer dsse.SignerVerifier, opts *SigningOptions) (*AttestationLayer, error) {

	// sign the statement
	env, err := SignInTotoStatement(ctx, statement, signer, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign statement: %w", err)
	}

	mediaType, err := DSSEMediaType(statement.PredicateType)
	if err != nil {
		return nil, fmt.Errorf("failed to get DSSE media type: %w", err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal envelope: %w", err)
	}
	return &AttestationLayer{
		Statement: statement,
		Annotations: map[string]string{
			InTotoPredicateType:           statement.PredicateType,
			InTotoReferenceLifecycleStage: LifecycleStageExperimental,
		},
		Layer: static.NewLayer(data, types.MediaType(mediaType)),
	}, nil
}

func SignInTotoStatement(ctx context.Context, statement *intoto.Statement, signer dsse.SignerVerifier, opts *SigningOptions) (*Envelope, error) {
	payload, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal statement: %w", err)
	}
	env, err := SignDSSE(ctx, payload, signer, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign statement: %w", err)
	}
	return env, nil
}

func addLayerToImage(
	manifest *AttestationManifest,
	layer *AttestationLayer,
	opts *SigningOptions) error {

	err := manifest.AddOrReplaceLayer(layer, opts)
	if err != nil {
		return fmt.Errorf("failed to add signed layers: %w", err)
	}
	if !opts.SkipSubject {
		manifest.AttestationImage.Image = mutate.Subject(manifest.AttestationImage.Image, *manifest.SubjectDescriptor).(v1.Image)
	}
	newDesc, err := partial.Descriptor(manifest.AttestationImage.Image)
	if err != nil {
		return fmt.Errorf("failed to get descriptor: %w", err)
	}
	newDesc.Platform = &v1.Platform{
		Architecture: "unknown",
		OS:           "unknown",
	}
	newDesc.MediaType = manifest.OriginalDescriptor.MediaType
	newDesc.Annotations = manifest.OriginalDescriptor.Annotations
	manifest.AttestationImage.Descriptor = newDesc
	return nil
}

// AddOrReplaceLayer adds signed layers to a new or existing attestation image
// NOTE: the pointers attestation.AttestationLayer.Statement are compared when replacing,
// so make sure you are signing a layer extracted from the original attestation-manifest image!
func (manifest *AttestationManifest) AddOrReplaceLayer(signedLayer *AttestationLayer, opts *SigningOptions) error {
	var err error
	// always create a new image from all the layers
	newImg := empty.Image
	//TODO: maybe we don't need these anymore
	newImg = mutate.Annotations(newImg, map[string]string{
		DockerReferenceType:   AttestationManifestType,
		DockerReferenceDigest: manifest.SubjectDescriptor.Digest.String(),
	}).(v1.Image)

	newImg = mutate.MediaType(newImg, manifest.OriginalDescriptor.MediaType)
	newImg = mutate.ConfigMediaType(newImg, "application/vnd.oci.image.config.v1+json")
	add := mutate.Addendum{
		Layer:       signedLayer.Layer,
		Annotations: signedLayer.Annotations,
	}
	newImg, err = mutate.Append(newImg, add)
	if err != nil {
		return fmt.Errorf("failed to add signed layer to image: %w", err)
	}
	newLayers := make([]*AttestationLayer, 0)
	for _, existingLayer := range manifest.AttestationImage.Layers {
		// if we're replacing, then we don't add it back in
		if existingLayer.Statement == signedLayer.Statement && opts.Replace {
			continue
		}
		// add original layer back in
		add := mutate.Addendum{
			Layer:       existingLayer.Layer,
			Annotations: existingLayer.Annotations,
		}
		newImg, err = mutate.Append(newImg, add)
		newLayers = append(newLayers, existingLayer)
		if err != nil {
			return fmt.Errorf("failed to add layer to image: %w", err)
		}
	}
	manifest.AttestationImage.Layers = append(newLayers, signedLayer)
	manifest.AttestationImage.Image = newImg
	return nil
}

func AddImageToIndex(
	idx v1.ImageIndex,
	manifest *AttestationManifest,
) (v1.ImageIndex, error) {
	idx = mutate.RemoveManifests(idx, match.Digests(manifest.OriginalDescriptor.Digest))
	idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
		Add:        manifest.AttestationImage.Image,
		Descriptor: *manifest.AttestationImage.Descriptor,
	})
	return idx, nil
}

func AddImagesToIndex(
	idx v1.ImageIndex,
	manifests []*AttestationManifest,
) (v1.ImageIndex, error) {
	for _, manifest := range manifests {
		var err error
		idx, err = AddImageToIndex(idx, manifest)
		if err != nil {
			return nil, fmt.Errorf("failed to add image to index: %w", err)
		}
	}
	return idx, nil
}
