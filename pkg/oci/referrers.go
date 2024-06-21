package oci

import (
	"context"
	"fmt"

	att "github.com/docker/attest/pkg/attestation"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
)

type ReferrersResolver struct {
	digest        string
	referrersRepo string
	manifests     []*AttestationManifest
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
		subjectDigest, err := r.ImageDigest(ctx)
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
		aManifests := make([]*AttestationManifest, 0)
		for _, m := range referrersIndexManifest.Manifests {

			remoteRef := referrersSubjectRef.Context().Digest(m.Digest.String())
			attestationImage, err := remote.Image(remoteRef)
			if err != nil {
				return fmt.Errorf("failed to get referred image: %w", err)
			}
			manifest, err := attestationImage.Manifest()
			if err != nil {
				return fmt.Errorf("failed to get manifest: %w", err)
			}
			if manifest.Annotations[att.DockerReferenceType] != AttestationManifestType {
				continue
			}
			if manifest.Annotations[att.DockerReferenceDigest] != subjectDigest {
				continue
			}
			attest := &AttestationManifest{
				Name:       r.Identifier,
				Image:      attestationImage,
				Manifest:   manifest,
				Descriptor: &m,
				Digest:     subjectDigest,
				Platform:   r.Platform,
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
