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
					OriginalLayers:     attestationLayers})
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
	manifest.SignedLayers = append(manifest.SignedLayers, layer)
	return nil
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

func UpdateIndexImage(
	idx v1.ImageIndex,
	manifest *AttestationManifest,
	options ...func(*AttestationManifestImageOptions) error) (v1.ImageIndex, error) {
	image, err := manifest.BuildAttestationImage(options...)

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

func UpdateIndexImages(idx v1.ImageIndex, manifest []*AttestationManifest, options ...func(*AttestationManifestImageOptions) error) (v1.ImageIndex, error) {
	var err error
	for _, m := range manifest {
		idx, err = UpdateIndexImage(idx, m, options...)
		if err != nil {
			return nil, fmt.Errorf("failed to add image to index: %w", err)
		}
	}
	return idx, nil
}

func newOptions(options ...func(*AttestationManifestImageOptions) error) (*AttestationManifestImageOptions, error) {
	opts := &AttestationManifestImageOptions{}
	for _, opt := range options {
		err := opt(opts)
		if err != nil {
			return nil, err
		}
	}
	return opts, nil
}

func WithoutSubject(skipSubject bool) func(*AttestationManifestImageOptions) error {
	return func(r *AttestationManifestImageOptions) error {
		r.skipSubject = skipSubject
		return nil
	}
}

func WithReplacedLayers(replaceLayers bool) func(*AttestationManifestImageOptions) error {
	return func(r *AttestationManifestImageOptions) error {
		r.replaceLayers = replaceLayers
		return nil
	}
}

// build an image with signed attestations, optionally replacing existing layers with signed layers
func (manifest *AttestationManifest) BuildAttestationImage(options ...func(*AttestationManifestImageOptions) error) (v1.Image, error) {
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
		//add existing layers if they've not been signed or we're not replacing them
		if !found || !opts.replaceLayers {
			resultLayers = append(resultLayers, existingLayer)
		}
	}
	// so taht we attach all attestations to a single attestations image - as per current buildkit
	opts.laxReferrers = true
	newImg, err := buildImage(resultLayers, manifest.OriginalDescriptor, manifest.SubjectDescriptor, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to build image: %w", err)
	}
	return newImg, nil
}

// build an image per attestation (layer) suitable for use as Referrers
func (manifest *AttestationManifest) BuildReferringArtifacts() ([]v1.Image, error) {
	var images []v1.Image
	for _, layer := range manifest.SignedLayers {
		opts := &AttestationManifestImageOptions{}
		newImg, err := buildImage([]*AttestationLayer{layer}, manifest.OriginalDescriptor, manifest.SubjectDescriptor, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to build image: %w", err)
		}
		images = append(images, newImg)
	}
	return images, nil
}

// build and image containing only layers
func buildImage(layers []*AttestationLayer, manifest *v1.Descriptor, subject *v1.Descriptor, opts *AttestationManifestImageOptions) (v1.Image, error) {
	newImg := empty.Image
	var err error
	if len(layers) == 0 {
		return nil, fmt.Errorf("no layers supplied to build image")
	}
	// NB: if we add the subject before the layers, it does not end up being computed/serialised in the output for some reason
	//TODO - recreate this bug and push upstream
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
		newImg = mutate.Subject(newImg, *subject).(v1.Image)
	}
	if !opts.laxReferrers {
		// as per https://github.com/opencontainers/image-spec/blob/main/manifest.md#guidance-for-an-empty-descriptor
		newImg = &EmptyConfigImage{newImg}
	}
	return newImg, nil
}

type EmptyConfigImage struct {
	v1.Image
}

func (i *EmptyConfigImage) RawConfigFile() ([]byte, error) {
	return []byte("{}"), nil
}

func (i *EmptyConfigImage) Manifest() (*v1.Manifest, error) {
	mf, err := i.Image.Manifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest: %w", err)
	}
	mf.Config = v1.Descriptor{
		MediaType: "application/vnd.oci.empty.v1+json",
		Size:      2,
		Digest:    v1.Hash{Algorithm: "sha256", Hex: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
		Data:      []byte("{}"),
	}
	return mf, nil
}

func (i *EmptyConfigImage) RawManifest() ([]byte, error) {
	mf, err := i.Manifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest: %w", err)
	}
	return json.Marshal(mf)
}
