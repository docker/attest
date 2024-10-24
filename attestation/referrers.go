/*
   Copyright Docker attest authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package attestation

import (
	"context"
	"fmt"
	"strings"

	"github.com/docker/attest/oci"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ensure ReferrersResolver implements Resolver.
var _ Resolver = &ReferrersResolver{}

type ReferrersResolver struct {
	referrersRepo string
	oci.ImageDetailsResolver
}

func NewReferrersResolver(src oci.ImageDetailsResolver, options ...func(*ReferrersResolver) error) (*ReferrersResolver, error) {
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

func (r *ReferrersResolver) resolveAttestations(ctx context.Context, predicateType string) ([]*Manifest, error) {
	dsseMediaType, err := DSSEMediaType(predicateType)
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
	var referrersSubjectRef name.Digest
	if r.referrersRepo != "" {
		referrersSubjectRef, err = name.NewDigest(fmt.Sprintf("%s@%s", strings.TrimPrefix(r.referrersRepo, oci.RegistryPrefix), subjectDigest))
		if err != nil {
			return nil, fmt.Errorf("failed to create referrers reference: %w", err)
		}
	} else {
		referrersSubjectRef = subjectRef.Context().Digest(subjectDigest)
	}
	options := oci.WithOptions(ctx, nil)
	options = append(options, remote.WithFilter("artifactType", dsseMediaType))
	referrersIndex, err := remote.Referrers(referrersSubjectRef, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to get referrers: %w", err)
	}
	referrersIndexManifest, err := referrersIndex.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get index manifest: %w", err)
	}
	aManifests := make([]*Manifest, 0)
	for i := range referrersIndexManifest.Manifests {
		m := referrersIndexManifest.Manifests[i]
		remoteRef := referrersSubjectRef.Context().Digest(m.Digest.String())
		options = oci.WithOptions(ctx, nil)
		attestationImage, err := remote.Image(remoteRef, options...)
		if err != nil {
			return nil, fmt.Errorf("failed to get referred image: %w", err)
		}
		layers, err := layersFromImage(attestationImage)
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
		attest := &Manifest{
			SubjectName:        imageName,
			OriginalLayers:     layers,
			OriginalDescriptor: &m,
			SubjectDescriptor:  desc,
		}
		aManifests = append(aManifests, attest)
	}
	return aManifests, nil
}

func (r *ReferrersResolver) Attestations(ctx context.Context, predicateType string) ([]*EnvelopeReference, error) {
	manifests, err := r.resolveAttestations(ctx, predicateType)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve attestations: %w", err)
	}
	var envs []*EnvelopeReference
	for _, attest := range manifests {
		es, err := ExtractEnvelopes(attest, predicateType)
		if err != nil {
			return nil, fmt.Errorf("failed to extract envelopes: %w", err)
		}
		envs = append(envs, es...)
	}
	return envs, nil
}
