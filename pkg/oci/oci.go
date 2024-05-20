package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/containerd/containerd/platforms"
	"github.com/distribution/reference"
	att "github.com/docker/attest/pkg/attestation"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
)

// parsePlatform parses the provided platform string or attempts to obtain
// the platform of the current host system
func parsePlatform(platformStr string) (*v1.Platform, error) {
	if platformStr == "" {
		cdp := platforms.Normalize(platforms.DefaultSpec())
		if cdp.OS != "windows" {
			cdp.OS = "linux"
		}
		return &v1.Platform{
			OS:           cdp.OS,
			Architecture: cdp.Architecture,
			Variant:      cdp.Variant,
		}, nil
	} else {
		return v1.ParsePlatform(platformStr)
	}
}

func attestationManifestFromOCILayout(path string, platformStr string) (*AttestationManifest, error) {
	idx, err := layout.ImageIndexFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load image index: %w", err)
	}

	idxm, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get digest: %w", err)
	}

	idxDescriptor := idxm.Manifests[0]
	name := idxDescriptor.Annotations["org.opencontainers.image.ref.name"]
	idxDigest := idxDescriptor.Digest

	mfs, err := idx.ImageIndex(idxDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ImageIndex for digest %s: %w", idxDigest.String(), err)
	}
	mfs2, err := mfs.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to extract IndexManifest from ImageIndex: %w", err)
	}
	platform, err := parsePlatform(platformStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse platform: %w", err)
	}
	var imageDigest string
	for _, mf := range mfs2.Manifests {
		if mf.Platform.Equals(*platform) {
			imageDigest = mf.Digest.String()
		}
	}
	for _, mf := range mfs2.Manifests {
		if mf.Annotations[att.DockerReferenceType] != AttestationManifestType {
			continue
		}

		if mf.Annotations[DockerReferenceDigest] != imageDigest {
			continue
		}

		attestationImage, err := mfs.Image(mf.Digest)
		if err != nil {
			return nil, fmt.Errorf("failed to extract attestation image with digest %s: %w", mf.Digest.String(), err)
		}
		manifest, err := attestationImage.Manifest()
		if err != nil {
			return nil, fmt.Errorf("failed to get manifest: %w", err)
		}
		attest := &AttestationManifest{
			Name:       name,
			Image:      attestationImage,
			Manifest:   manifest,
			Descriptor: &mf,
			Digest:     imageDigest,
			Platform:   platform,
		}
		return attest, nil
	}
	return nil, errors.New("attestation manifest not found")

}

// implementation of AttestationResolver that closes over attestations from an oci layout
type OCILayoutResolver struct {
	Path     string
	Platform string
	*AttestationManifest
}

func (r *OCILayoutResolver) ImagePlatformStr() string {
	return r.Platform
}
func (r *OCILayoutResolver) fetchAttestationManifest() (*AttestationManifest, error) {
	if r.AttestationManifest == nil {
		m, err := attestationManifestFromOCILayout(r.Path, r.Platform)
		if err != nil {
			return nil, fmt.Errorf("failed to get attestation manifest: %w", err)
		}
		r.AttestationManifest = m
	}
	return r.AttestationManifest, nil
}

func (r *OCILayoutResolver) Attestations(ctx context.Context, predicateType string) ([]*att.Envelope, error) {
	if r.AttestationManifest == nil {
		_, err := r.fetchAttestationManifest()
		if err != nil {
			return nil, fmt.Errorf("failed to get attestation manifest: %w", err)
		}
	}
	attestationImage := r.AttestationManifest.Image
	layers, err := attestationImage.Layers()
	if err != nil {
		return nil, fmt.Errorf("failed to extract layers from attestation image: %w", err)
	}
	var envs []*att.Envelope
	manifest := r.AttestationManifest.Manifest
	for i, l := range manifest.Layers {
		if l.Annotations[InTotoPredicateType] != predicateType {
			continue
		}
		layer := layers[i]
		mt, err := layer.MediaType()
		if err != nil {
			return nil, fmt.Errorf("failed to get layer media type: %w", err)
		}
		mts := string(mt)
		if !strings.HasSuffix(mts, "+dsse") {
			continue
		}
		var env = new(att.Envelope)
		// parse layer blob as json
		r, err := layer.Uncompressed()

		if err != nil {
			return nil, fmt.Errorf("failed to get layer contents: %w", err)
		}
		defer r.Close()
		err = json.NewDecoder(r).Decode(env)
		if err != nil {
			return nil, fmt.Errorf("failed to decode envelope: %w", err)
		}
		envs = append(envs, env)
	}
	return envs, nil
}

func (r *OCILayoutResolver) ImageName(ctx context.Context) (string, error) {
	if r.AttestationManifest == nil {
		_, err := r.fetchAttestationManifest()
		if err != nil {
			return "", fmt.Errorf("failed to get attestation manifest: %w", err)
		}
	}

	return r.Name, nil
}

func (r *OCILayoutResolver) ImageDigest(ctx context.Context) (string, error) {
	if r.AttestationManifest == nil {
		_, err := r.fetchAttestationManifest()
		if err != nil {
			return "", fmt.Errorf("failed to get attestation manifest: %w", err)
		}
	}
	return r.Digest, nil
}

type RegistryResolver struct {
	Image    string
	Platform string
	*AttestationManifest
}

func (r *RegistryResolver) ImageName(ctx context.Context) (string, error) {
	return r.Image, nil
}

func (r *RegistryResolver) ImagePlatformStr() string {
	return r.Platform
}

func (r *RegistryResolver) ImageDigest(ctx context.Context) (string, error) {
	if r.AttestationManifest == nil {
		attest, err := FetchAttestationManifest(ctx, r.Image, r.Platform)
		if err != nil {
			return "", fmt.Errorf("failed to get attestation manifest: %w", err)
		}
		r.AttestationManifest = attest
	}
	return r.Digest, nil
}

func (r *RegistryResolver) Attestations(ctx context.Context, predicateType string) ([]*att.Envelope, error) {
	if r.AttestationManifest == nil {
		attest, err := FetchAttestationManifest(ctx, r.Image, r.Platform)
		if err != nil {
			return nil, fmt.Errorf("failed to get attestation manifest: %w", err)
		}
		r.AttestationManifest = attest
	}
	return ExtractEnvelopes(r.AttestationManifest, predicateType)
}

func FetchAttestationManifest(ctx context.Context, image, platformStr string) (*AttestationManifest, error) {
	platform, err := parsePlatform(platformStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse platform %s: %w", platform, err)
	}

	// we want to get to the image index, so ignoring platform for now
	options := withOptions(ctx, nil)
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference: %w", err)
	}

	desc, err := remote.Index(ref, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain index manifest: %w", err)
	}
	ix, err := desc.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to obtain index manifest: %w", err)
	}
	digest, err := imageDigestForPlatform(ix, platform)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain image for platform: %w", err)
	}
	ref, err = name.ParseReference(fmt.Sprintf("%s@%s", ref.Context().Name(), digest))
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation reference: %w", err)
	}

	attestationDigest, err := attestationDigestForDigest(ix, digest, "attestation-manifest")
	if err != nil {
		return nil, fmt.Errorf("failed to obtain attestation for image: %w", err)
	}
	ref, err = name.ParseReference(fmt.Sprintf("%s@%s", ref.Context().Name(), attestationDigest))
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation reference: %w", err)
	}
	remoteDescriptor, err := remote.Get(ref, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation: %w", err)
	}
	manifest := new(v1.Manifest)
	err = json.Unmarshal(remoteDescriptor.Manifest, manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestation: %w", err)
	}
	attestationImage, err := remoteDescriptor.Image()
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation image: %w", err)
	}
	attest := &AttestationManifest{
		Name:       image,
		Image:      attestationImage,
		Manifest:   manifest,
		Descriptor: &remoteDescriptor.Descriptor,
		Digest:     digest,
		Platform:   platform,
	}
	return attest, nil
}

func withOptions(ctx context.Context, platform *v1.Platform) []remote.Option {
	// prepare options
	options := []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithTransport(HttpTransport()), remote.WithContext(ctx)}

	// add in platform into remote Get operation; this might conflict with an explicit digest, but we are trying anyway
	if platform != nil {
		options = append(options, remote.WithPlatform(*platform))
	}
	return options
}

func ExtractEnvelopes(ia *AttestationManifest, predicateType string) ([]*att.Envelope, error) {
	manifest := ia.Manifest
	im := ia.Image

	var envs []*att.Envelope

	ls, err := im.Layers()
	if err != nil {
		return nil, fmt.Errorf("failed to get layers: %w", err)
	}
	for i, l := range manifest.Layers {
		if (strings.HasPrefix(string(l.MediaType), "application/vnd.in-toto.")) &&
			strings.HasSuffix(string(l.MediaType), "+dsse") &&
			l.Annotations[InTotoPredicateType] == predicateType {
			reader, err := ls[i].Uncompressed()
			if err != nil {
				return nil, fmt.Errorf("failed to get layer contents: %w", err)
			}
			defer reader.Close()
			var env = new(att.Envelope)
			err = json.NewDecoder(reader).Decode(&env)
			if err != nil {
				return nil, fmt.Errorf("failed to decode envelope: %w", err)
			}
			envs = append(envs, env)
		}
	}

	return envs, nil
}

func imageDigestForPlatform(ix *v1.IndexManifest, platform *v1.Platform) (string, error) {
	for _, m := range ix.Manifests {
		if (m.MediaType == ocispec.MediaTypeImageManifest || m.MediaType == "application/vnd.docker.distribution.manifest.v2+json") && m.Platform.Equals(*platform) {
			return m.Digest.String(), nil
		}
	}
	return "", errors.New(fmt.Sprintf("no image found for platform %v", platform))
}

func attestationDigestForDigest(ix *v1.IndexManifest, imageDigest string, attestType string) (string, error) {
	for _, m := range ix.Manifests {
		if v, ok := m.Annotations[att.DockerReferenceType]; ok && v == attestType {
			if d, ok := m.Annotations[DockerReferenceDigest]; ok && d == imageDigest {
				return m.Digest.String(), nil
			}
		}
	}
	return "", errors.New(fmt.Sprintf("no attestation found for image %s", imageDigest))
}

func RefToPURL(ref string, platform string) (string, bool, error) {
	var isCanonical bool
	named, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return "", false, fmt.Errorf("failed to parse ref %q: %w", ref, err)
	}
	var qualifiers []packageurl.Qualifier

	if canonical, ok := named.(reference.Canonical); ok {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "digest",
			Value: canonical.Digest().String(),
		})
		isCanonical = true
	} else {
		named = reference.TagNameOnly(named)
	}

	version := ""
	if tagged, ok := named.(reference.Tagged); ok {
		version = tagged.Tag()
	}

	name := reference.FamiliarName(named)

	ns := ""
	parts := strings.Split(name, "/")
	if len(parts) > 1 {
		ns = strings.Join(parts[:len(parts)-1], "/")
	}
	name = parts[len(parts)-1]

	pf, err := parsePlatform(platform)
	if err != nil {
		return "", false, fmt.Errorf("failed to parse platform %q: %w", platform, err)
	}
	if pf != nil {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "platform",
			Value: pf.String(),
		})
	}

	p := packageurl.NewPackageURL("docker", ns, name, version, qualifiers, "")
	return p.ToString(), isCanonical, nil
}

func SplitDigest(digest string) (*common.DigestSet, error) {
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid digest %q", digest)
	}
	return &common.DigestSet{
		parts[0]: parts[1],
	}, nil
}
