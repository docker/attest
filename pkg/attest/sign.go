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
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func SignIndexAttestations(ctx context.Context, idx v1.ImageIndex, signer dsse.SignerVerifier, opts *SigningOptions) (v1.ImageIndex, error) {
	indexManifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to extract IndexManifest from ImageIndex: %w", err)
	}

	var originalManifestDigests []v1.Hash
	var muts []mutate.IndexAddendum
	for _, manifest := range indexManifest.Manifests {
		if manifest.Annotations[oci.DockerReferenceType] != oci.AttestationManifestType {
			continue
		}

		originalManifestDigests = append(originalManifestDigests, manifest.Digest)

		attestationImage, err := idx.Image(manifest.Digest)
		if err != nil {
			return nil, fmt.Errorf("failed to extract attestation image with digest %s: %w", manifest.Digest.String(), err)
		}
		layers, err := attestationImage.Layers()
		if err != nil {
			return nil, fmt.Errorf("failed to extract layers from attestation image: %w", err)
		}

		var signedLayers []mutate.Addendum
		var originalLayers []v1.Layer
		var statements []*intoto.Statement

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

			if mt != types.MediaType(intoto.PayloadType) {
				originalLayers = append(originalLayers, layer)
				continue
			}
			var stmt = new(intoto.Statement)
			err = json.NewDecoder(r).Decode(&stmt)
			if err != nil {
				return nil, fmt.Errorf("failed to decode statement layer contents: %w", err)
			}

			statements = append(statements, stmt)
			layerDesc, err := partial.Descriptor(layer)
			if err != nil {
				return nil, fmt.Errorf("failed to get descriptor for layer: %w", err)
			}
			// copy original annotations and add new ones
			ann := make(map[string]string)
			for k, v := range layerDesc.Annotations {
				ann[k] = v
			}
			ann[InTotoReferenceLifecycleStage] = LifecycleStageExperimental

			var env *attestation.Envelope
			var mediaType string
			switch opts.EnvelopeStyle {
			case OCIContentDescriptor:
				// Ensure we sign just the digest, size, and media type
				payloadDesc := v1.Descriptor{
					Digest:    layerDesc.Digest,
					Size:      layerDesc.Size,
					MediaType: layerDesc.MediaType,
				}
				payload, err := json.Marshal(payloadDesc)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal descriptor: %w", err)
				}
				env, err = attestation.SignDSSE(ctx, payload, ociv1.MediaTypeDescriptor, signer)
				if err != nil {
					return nil, fmt.Errorf("failed to sign statement: %w", err)
				}
				ann[oci.DockerReferenceDigest] = layerDesc.Digest.String()
				// this is a reference type
				opts.Replace = false
				mediaType = attestation.OCIDescriptorDSSEMediaType
			case EmbeddedDSSE:
				payload, err := json.Marshal(stmt)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal statement: %w", err)
				}
				env, err = attestation.SignDSSE(ctx, payload, intoto.PayloadType, signer)
				if err != nil {
					return nil, fmt.Errorf("failed to sign statement: %w", err)
				}
				mediaType, err = attestation.DSSEMediaType(stmt.PredicateType)
				if err != nil {
					return nil, fmt.Errorf("failed to get DSSE media type: %w", err)
				}

			default:
				return nil, fmt.Errorf("unknown envelope style %q", opts.EnvelopeStyle)
			}

			data, err := json.Marshal(env)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal envelope: %w", err)
			}
			newLayer := static.NewLayer(data, types.MediaType(mediaType))

			withAnnotations := mutate.Addendum{
				Layer:       newLayer,
				Annotations: ann,
			}
			signedLayers = append(signedLayers, withAnnotations)
		}

		newImg, err := addSignedLayers(signedLayers, originalLayers, manifest.MediaType, attestationImage, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to add signed layers: %w", err)
		}

		if opts.VSAOptions != nil {
			newLayer, err := generateVSA(ctx, newImg, statements, signer, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to generate VSA: %w", err)
			}
			vsaReplace := &SigningOptions{
				Replace: false,
			}
			newImg, err = addSignedLayers([]mutate.Addendum{*newLayer}, layers, manifest.MediaType, newImg, vsaReplace)
			if err != nil {
				return nil, fmt.Errorf("failed to add VSA layer: %w", err)
			}
		}
		newDesc, err := partial.Descriptor(newImg)
		if err != nil {
			return nil, fmt.Errorf("failed to get descriptor: %w", err)
		}
		cf, err := attestationImage.ConfigFile()
		if err != nil {
			return nil, fmt.Errorf("failed to get config file: %w", err)
		}
		newDesc.Platform = cf.Platform()
		newDesc.MediaType = manifest.MediaType
		newDesc.Annotations = manifest.Annotations

		muts = append(muts, mutate.IndexAddendum{
			Add:        newImg,
			Descriptor: *newDesc,
		})
	}
	// create new index with signed images
	newIndex := mutate.RemoveManifests(idx, match.Digests(originalManifestDigests...))
	newIndex = mutate.AppendManifests(newIndex, muts...)

	return newIndex, nil
}

func addSignedLayers(signedLayers []mutate.Addendum, originalLayers []v1.Layer, mediaType types.MediaType, attestationImage v1.Image, opts *SigningOptions) (v1.Image, error) {
	var err error
	if opts.Replace {
		newImg := empty.Image
		newImg = mutate.MediaType(newImg, mediaType)
		newImg = mutate.ConfigMediaType(newImg, "application/vnd.oci.image.config.v1+json")
		for _, layer := range signedLayers {
			newImg, err = mutate.Append(newImg, layer)
			if err != nil {
				return nil, fmt.Errorf("failed to append layer: %w", err)
			}
		}
		newImg, err = mutate.AppendLayers(newImg, originalLayers...)
		if err != nil {
			return nil, fmt.Errorf("failed to append original layers: %w", err)
		}
		return newImg, nil

	}
	for _, layer := range signedLayers {
		attestationImage, err = mutate.Append(attestationImage, layer)
		if err != nil {
			return nil, fmt.Errorf("failed to append layer: %w", err)
		}
	}
	return attestationImage, nil
}
