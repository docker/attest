package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	"github.com/docker/attest/oci"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/match"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// NewManifest creates a new attestation manifest from a descriptor.
func NewManifest(subject *v1.Descriptor) (*Manifest, error) {
	return &Manifest{
		OriginalDescriptor: &v1.Descriptor{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
		},
		OriginalLayers:    []*Layer{},
		SubjectDescriptor: subject,
	}, nil
}

// ManifestsFromIndex extracts all attestation manifests from an index.
func ManifestsFromIndex(index v1.ImageIndex) ([]*Manifest, error) {
	idx, err := index.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to extract IndexManifest from ImageIndex: %w", err)
	}
	subjects := make(map[string]*v1.Descriptor)
	for i := range idx.Manifests {
		subject := &idx.Manifests[i]
		subjects[subject.Digest.String()] = subject
	}

	var attestationManifests []*Manifest
	for i := range idx.Manifests {
		desc := idx.Manifests[i]
		if desc.Annotations[DockerReferenceType] == AttestationManifestType {
			subject := subjects[desc.Annotations[DockerReferenceDigest]]
			if subject == nil {
				return nil, fmt.Errorf("failed to find subject for attestation manifest: %w", err)
			}
			attestationImage, err := index.Image(desc.Digest)
			if err != nil {
				return nil, fmt.Errorf("failed to extract attestation image with digest %s: %w", desc.Digest.String(), err)
			}
			attestationLayers, err := layersFromImage(attestationImage)
			if err != nil {
				return nil, fmt.Errorf("failed to get attestations from image: %w", err)
			}
			attestationManifests = append(attestationManifests,
				&Manifest{
					OriginalDescriptor: &desc,
					SubjectDescriptor:  subject,
					OriginalLayers:     attestationLayers,
				})
		}
	}
	return attestationManifests, nil
}

// LayersFromImage extracts all attestation layers from an image.
func layersFromImage(image v1.Image) ([]*Layer, error) {
	layers, err := image.Layers()
	if err != nil {
		return nil, fmt.Errorf("failed to extract layers from image: %w", err)
	}
	var attestationLayers []*Layer
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
		var stmt *intoto.Statement
		if mt == types.MediaType(intoto.PayloadType) {
			stmt = new(intoto.Statement)
			err = json.NewDecoder(r).Decode(&stmt)
			if err != nil {
				return nil, fmt.Errorf("failed to decode statement layer contents: %w", err)
			}
		}
		attestationLayers = append(attestationLayers, &Layer{Layer: layer, Statement: stmt, Annotations: ann})
	}
	return attestationLayers, nil
}

func (manifest *Manifest) Add(ctx context.Context, signer dsse.SignerVerifier, statement *intoto.Statement, opts *SigningOptions) error {
	layer, err := createSignedImageLayer(ctx, statement, signer, opts)
	if err != nil {
		return fmt.Errorf("failed to create signed layer: %w", err)
	}
	manifest.SignedLayers = append(manifest.SignedLayers, layer)
	return nil
}

func createSignedImageLayer(ctx context.Context, statement *intoto.Statement, signer dsse.SignerVerifier, opts *SigningOptions) (*Layer, error) {
	// sign the statement
	env, err := signInTotoStatement(ctx, statement, signer, opts)
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
	return &Layer{
		Statement: statement,
		Annotations: map[string]string{
			InTotoPredicateType:           statement.PredicateType,
			InTotoReferenceLifecycleStage: LifecycleStageExperimental,
		},
		Layer: static.NewLayer(data, types.MediaType(mediaType)),
	}, nil
}

func signInTotoStatement(ctx context.Context, statement *intoto.Statement, signer dsse.SignerVerifier, opts *SigningOptions) (*Envelope, error) {
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

func updateImageIndex(
	idx v1.ImageIndex,
	manifest *Manifest,
	options ...func(*ManifestImageOptions) error,
) (v1.ImageIndex, error) {
	image, err := manifest.BuildImage(options...)
	if err != nil {
		return nil, fmt.Errorf("failed to build image: %w", err)
	}
	newDesc, err := partial.Descriptor(image)
	if err != nil {
		return nil, fmt.Errorf("failed to get descriptor: %w", err)
	}
	newDesc.Platform = &v1.Platform{
		Architecture: "unknown",
		OS:           "unknown",
	}
	newDesc.MediaType = manifest.OriginalDescriptor.MediaType
	newDesc.Annotations = manifest.OriginalDescriptor.Annotations
	idx = mutate.RemoveManifests(idx, match.Digests(manifest.OriginalDescriptor.Digest))
	idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
		Add:        image,
		Descriptor: *newDesc,
	})
	return idx, nil
}

func UpdateIndexImages(idx v1.ImageIndex, manifest []*Manifest, options ...func(*ManifestImageOptions) error) (v1.ImageIndex, error) {
	var err error
	for _, m := range manifest {
		idx, err = updateImageIndex(idx, m, options...)
		if err != nil {
			return nil, fmt.Errorf("failed to add image to index: %w", err)
		}
	}
	return idx, nil
}

func newOptions(options ...func(*ManifestImageOptions) error) (*ManifestImageOptions, error) {
	opts := &ManifestImageOptions{}
	for _, opt := range options {
		err := opt(opts)
		if err != nil {
			return nil, err
		}
	}
	return opts, nil
}

func WithoutSubject(skipSubject bool) func(*ManifestImageOptions) error {
	return func(r *ManifestImageOptions) error {
		r.skipSubject = skipSubject
		return nil
	}
}

func WithReplacedLayers(replaceLayers bool) func(*ManifestImageOptions) error {
	return func(r *ManifestImageOptions) error {
		r.replaceLayers = replaceLayers
		return nil
	}
}

// build an image with signed attestations, optionally replacing existing layers with signed layers.
func (manifest *Manifest) BuildImage(options ...func(*ManifestImageOptions) error) (v1.Image, error) {
	opts, err := newOptions(options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create options: %w", err)
	}
	resultLayers := manifest.SignedLayers
	for _, existingLayer := range manifest.OriginalLayers {
		var found bool
		for _, signedLayer := range manifest.SignedLayers {
			if existingLayer.Statement == signedLayer.Statement {
				found = true
				// copy over original annotations
				for k, v := range existingLayer.Annotations {
					signedLayer.Annotations[k] = v
				}
				break
			}
		}
		// add existing layers if they've not been signed or we're not replacing them
		if !found || !opts.replaceLayers {
			resultLayers = append(resultLayers, existingLayer)
		}
	}
	// so that we attach all attestations to a single attestations image - as per current buildkit
	opts.laxReferrers = true
	newImg, err := buildImageFromLayers(resultLayers, manifest.OriginalDescriptor, manifest.SubjectDescriptor, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to build image: %w", err)
	}
	return newImg, nil
}

// build an image per attestation (layer) suitable for use as Referrers.
func (manifest *Manifest) BuildReferringArtifacts() ([]v1.Image, error) {
	var images []v1.Image
	for _, layer := range manifest.SignedLayers {
		opts := &ManifestImageOptions{}
		newImg, err := buildImageFromLayers([]*Layer{layer}, manifest.OriginalDescriptor, manifest.SubjectDescriptor, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to build image: %w", err)
		}
		images = append(images, newImg)
	}
	return images, nil
}

// build an image containing only layers provided.
func buildImageFromLayers(layers []*Layer, manifest *v1.Descriptor, subject *v1.Descriptor, opts *ManifestImageOptions) (v1.Image, error) {
	newImg := empty.Image
	var err error
	if len(layers) == 0 {
		return nil, fmt.Errorf("no layers supplied to build image")
	}
	// NB: if we add the subject before the layers, it does not end up being computed/serialized in the output for some reason
	// TODO - recreate this bug and push upstream
	for _, layer := range layers {
		add := mutate.Addendum{
			Layer:       layer.Layer,
			Annotations: layer.Annotations,
		}
		newImg, err = mutate.Append(newImg, add)
		if err != nil {
			return nil, fmt.Errorf("failed to add layer to image: %w", err)
		}
	}

	// this is for attaching attestations to an attestation image in the index
	if opts.laxReferrers {
		newImg = mutate.ConfigMediaType(newImg, "application/vnd.oci.image.config.v1+json")
	} else {
		dsseMediatType, err := DSSEMediaType(layers[0].Statement.PredicateType)
		if err != nil {
			return nil, fmt.Errorf("failed to get DSSE media type: %w", err)
		}
		newImg = mutate.ArtifactType(newImg, dsseMediatType)
		newImg = mutate.ConfigMediaType(newImg, "application/vnd.oci.empty.v1+json")
	}
	// we need to set this even when we set the artifact type otherwise things break (even the go-container-registry client)
	// even though it's allowed to be empty by spec when setting artifact type
	newImg = mutate.MediaType(newImg, manifest.MediaType)

	// see note above - must be added after the layers!
	if !opts.skipSubject {
		subject.Platform = nil
		ok := false
		newImg, ok = mutate.Subject(newImg, *subject).(v1.Image)
		if !ok {
			return nil, fmt.Errorf("failed to set subject: %w", err)
		}
	}
	if !opts.laxReferrers {
		// as per https://github.com/opencontainers/image-spec/blob/main/manifest.md#guidance-for-an-empty-descriptor
		newImg = &oci.EmptyConfigImage{Image: newImg}
	}
	return newImg, nil
}

func ExtractEnvelopes(manifest *Manifest, predicateType string) ([]*EnvelopeReference, error) {
	var envs []*EnvelopeReference
	dsseMediaType, err := DSSEMediaType(predicateType)
	if err != nil {
		return nil, fmt.Errorf("failed to get DSSE media type for predicate '%s': %w", predicateType, err)
	}
	for _, attestationLayer := range manifest.OriginalLayers {
		mt, err := attestationLayer.Layer.MediaType()
		if err != nil {
			return nil, fmt.Errorf("failed to get layer media type: %w", err)
		}
		if string(mt) == dsseMediaType {
			reader, err := attestationLayer.Layer.Uncompressed()
			if err != nil {
				return nil, fmt.Errorf("failed to get layer contents: %w", err)
			}
			defer reader.Close()
			env := new(EnvelopeReference)
			err = json.NewDecoder(reader).Decode(&env)
			if err != nil {
				return nil, fmt.Errorf("failed to decode envelope: %w", err)
			}
			var uri string
			if len(manifest.OriginalDescriptor.URLs) > 0 {
				uri = manifest.OriginalDescriptor.URLs[0]
			}
			env.ResourceDescriptor = &ResourceDescriptor{
				MediaType: string(mt),
				Digest:    map[string]string{manifest.OriginalDescriptor.Digest.Algorithm: manifest.OriginalDescriptor.Digest.Hex},
				URI:       uri,
			}
			envs = append(envs, env)
		}
	}

	return envs, nil
}

func ExtractStatementsFromIndex(idx v1.ImageIndex, mediaType string) ([]*AnnotatedStatement, error) {
	mfs2, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to extract IndexManifest from ImageIndex: %w", err)
	}

	var statements []*AnnotatedStatement

	for i := range mfs2.Manifests {
		mf := &mfs2.Manifests[i]
		if mf.Annotations[DockerReferenceType] != "attestation-manifest" {
			continue
		}

		attestationImage, err := idx.Image(mf.Digest)
		if err != nil {
			return nil, fmt.Errorf("failed to extract attestation image with digest %s: %w", mf.Digest.String(), err)
		}
		layers, err := attestationImage.Layers()
		if err != nil {
			return nil, fmt.Errorf("failed to extract layers from attestation image: %w", err)
		}

		for _, layer := range layers {
			// parse layer blob as json
			mt, err := layer.MediaType()
			if err != nil {
				return nil, fmt.Errorf("failed to get layer media type: %w", err)
			}

			if string(mt) != mediaType {
				continue
			}
			r, err := layer.Uncompressed()
			if err != nil {
				return nil, fmt.Errorf("failed to get layer contents: %w", err)
			}
			defer r.Close()
			inTotoStatement := new(intoto.Statement)
			var desc *v1.Descriptor
			if strings.HasSuffix(string(mt), "+dsse") {
				env := new(Envelope)
				err = json.NewDecoder(r).Decode(env)
				if err != nil {
					return nil, fmt.Errorf("failed to decode env: %w", err)
				}
				payload, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
				if err != nil {
					return nil, fmt.Errorf("failed to decode payload: %w", err)
				}
				err = json.Unmarshal([]byte(payload), inTotoStatement)
				if err != nil {
					return nil, fmt.Errorf("failed to decode %s statement: %w", mediaType, err)
				}
			} else {
				desc := new(v1.Descriptor)
				err = json.NewDecoder(r).Decode(desc)
				if err != nil {
					return nil, fmt.Errorf("failed to decode statement: %w", err)
				}
			}

			layerDesc, err := partial.Descriptor(layer)
			if err != nil {
				return nil, fmt.Errorf("failed to get descriptor for layer: %w", err)
			}
			annotations := make(map[string]string)
			for k, v := range layerDesc.Annotations {
				annotations[k] = v
			}
			statements = append(statements, &AnnotatedStatement{
				OCIDescriptor:   desc,
				InTotoStatement: inTotoStatement,
				Annotations:     annotations,
			})
		}
	}
	return statements, nil
}

func ExtractAnnotatedStatements(path string, mediaType string) ([]*AnnotatedStatement, error) {
	idx, err := layout.ImageIndexFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load image index: %w", err)
	}

	idxm, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get digest: %w", err)
	}
	idxDigest := idxm.Manifests[0].Digest

	mfs, err := idx.ImageIndex(idxDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ImageIndex for digest %s: %w", idxDigest.String(), err)
	}
	return ExtractStatementsFromIndex(mfs, mediaType)
}
