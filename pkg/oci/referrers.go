package oci

import (
	"context"
	"fmt"

	"github.com/docker/attest/pkg/attestation"
	att "github.com/docker/attest/pkg/attestation"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
)

type ReferrersResolver struct {
	digest        string
	referrersRepo string
	manifests     []*attestation.AttestationManifest
	*RegistryImageDetailsResolver
}

func NewReferrersAttestationResolver(src *RegistryImageDetailsResolver, options ...func(*ReferrersResolver) error) (*ReferrersResolver, error) {
	res := &ReferrersResolver{
		RegistryImageDetailsResolver: src,
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

func (r *ReferrersResolver) resolveAttestations(ctx context.Context) error {
	if r.manifests == nil {
		subjectRef, err := name.ParseReference(r.Identifier)
		if err != nil {
			return fmt.Errorf("failed to parse reference: %w", err)
		}
		desc, err := r.ImageDescriptor(ctx)
		if err != nil {
			return fmt.Errorf("failed to get descriptor: %w", err)
		}
		subjectDigest := desc.Digest.String()
		if err != nil {
			return fmt.Errorf("failed to get digest: %w", err)
		}
		var referrersSubjectRef name.Digest
		if r.referrersRepo != "" {
			referrersSubjectRef, err = name.NewDigest(fmt.Sprintf("%s@%s", r.referrersRepo, subjectDigest))
			if err != nil {
				return fmt.Errorf("failed to create referrers reference: %w", err)
			}
		} else {
			referrersSubjectRef = subjectRef.Context().Digest(subjectDigest)
		}
		// TODO - search for in-toto artifact type
		referrersIndex, err := remote.Referrers(referrersSubjectRef)
		if err != nil {
			return fmt.Errorf("failed to get referrers: %w", err)
		}
		referrersIndexManifest, err := referrersIndex.IndexManifest()
		if err != nil {
			return fmt.Errorf("failed to get index manifest: %w", err)
		}
		if len(referrersIndexManifest.Manifests) == 0 {
			return errors.New("no referrers found")
		}
		aManifests := make([]*attestation.AttestationManifest, 0)
		for _, m := range referrersIndexManifest.Manifests {
			remoteRef := referrersSubjectRef.Context().Digest(m.Digest.String())
			attestationImage, err := remote.Image(remoteRef)
			if err != nil {
				return fmt.Errorf("failed to get referred image: %w", err)
			}
			layers, err := attestation.GetAttestationsFromImage(attestationImage)
			if err != nil {
				return fmt.Errorf("failed to get attestations from image: %w", err)
			}
			attest := &attestation.AttestationManifest{
				SubjectName:        r.Identifier,
				OriginalLayers:     layers,
				OriginalDescriptor: &m,
				SubjectDescriptor:  desc,
			}
			aManifests = append(aManifests, attest)
		}

		if len(aManifests) == 0 {
			return errors.New("no attestation manifests found")
		}
		r.manifests = aManifests
	}
	return nil
}

func (r *ReferrersResolver) Attestations(ctx context.Context, predicateType string) ([]*att.Envelope, error) {
	err := r.resolveAttestations(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve attestations: %w", err)
	}
	var envs []*att.Envelope
	for _, attest := range r.manifests {
		es, err := ExtractEnvelopes(attest, predicateType)
		if err != nil {
			return nil, fmt.Errorf("failed to extract envelopes: %w", err)
		}
		envs = append(envs, es...)
	}
	return envs, nil
}
