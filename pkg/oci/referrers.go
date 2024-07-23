package oci

import (
	"context"
	"fmt"

	"github.com/docker/attest/pkg/attestation"
	att "github.com/docker/attest/pkg/attestation"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type ReferrersResolver struct {
	referrersRepo string
	ImageDetailsResolver
}

func NewReferrersAttestationResolver(src ImageDetailsResolver, options ...func(*ReferrersResolver) error) (*ReferrersResolver, error) {
	res := &ReferrersResolver{
		ImageDetailsResolver: src,
	}
	for _, opt := range options {
		err := opt(res)
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func WithReferrersRepo(repo string) func(*ReferrersResolver) error {
	return func(r *ReferrersResolver) error {
		r.referrersRepo = repo
		return nil
	}
}

func (r *ReferrersResolver) resolveAttestations(ctx context.Context, predicateType string) ([]*attestation.AttestationManifest,
	error) {
	dsseMediaType, err := attestation.DSSEMediaType(predicateType)
	if err != nil {
		return nil, fmt.Errorf("failed to get DSSE media type for predicate '%s': %w", predicateType, err)
	}
	imageName, err := r.ImageName(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get image name: %w", err)
	}
	subjectRef, err := name.ParseReference(imageName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference: %w", err)
	}
	desc, err := r.ImageDescriptor(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get descriptor: %w", err)
	}
	subjectDigest := desc.Digest.String()
	if err != nil {
		return nil, fmt.Errorf("failed to get digest: %w", err)
	}
	var referrersSubjectRef name.Digest
	if r.referrersRepo != "" {
		referrersSubjectRef, err = name.NewDigest(fmt.Sprintf("%s@%s", r.referrersRepo, subjectDigest))
		if err != nil {
			return nil, fmt.Errorf("failed to create referrers reference: %w", err)
		}
	} else {
		referrersSubjectRef = subjectRef.Context().Digest(subjectDigest)
	}
	options := WithOptions(ctx, nil)
	options = append(options, remote.WithFilter("artifactType", dsseMediaType))
	referrersIndex, err := remote.Referrers(referrersSubjectRef, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to get referrers: %w", err)
	}
	referrersIndexManifest, err := referrersIndex.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get index manifest: %w", err)
	}
	aManifests := make([]*attestation.AttestationManifest, 0)
	for _, m := range referrersIndexManifest.Manifests {
		remoteRef := referrersSubjectRef.Context().Digest(m.Digest.String())
		attestationImage, err := remote.Image(remoteRef)
		if err != nil {
			return nil, fmt.Errorf("failed to get referred image: %w", err)
		}
		layers, err := attestation.GetAttestationsFromImage(attestationImage)
		if err != nil {
			return nil, fmt.Errorf("failed to get attestations from image: %w", err)
		}
		if len(layers) != 1 {
			return nil, fmt.Errorf("expected exactly one layer, got %d", len(layers))
		}
		mt, err := layers[0].Layer.MediaType()
		if err != nil {
			return nil, fmt.Errorf("failed to get layer media type: %w", err)
		}
		if string(mt) != dsseMediaType {
			return nil, fmt.Errorf("expected layer media type %s, got %s", dsseMediaType, mt)
		}
		attest := &attestation.AttestationManifest{
			SubjectName:        imageName,
			OriginalLayers:     layers,
			OriginalDescriptor: &m,
			SubjectDescriptor:  desc,
		}
		aManifests = append(aManifests, attest)
	}
	return aManifests, nil
}

func (r *ReferrersResolver) Attestations(ctx context.Context, predicateType string) ([]*att.Envelope, error) {
	manifests, err := r.resolveAttestations(ctx, predicateType)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve attestations: %w", err)
	}
	var envs []*att.Envelope
	for _, attest := range manifests {
		es, err := ExtractEnvelopes(attest, predicateType)
		if err != nil {
			return nil, fmt.Errorf("failed to extract envelopes: %w", err)
		}
		envs = append(envs, es...)
	}
	return envs, nil
}
