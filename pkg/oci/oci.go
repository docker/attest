package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	"github.com/docker/attest/pkg/attestation"
	att "github.com/docker/attest/pkg/attestation"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
)

// ParsePlatform parses the provided platform string or attempts to obtain
// the platform of the current host system
func ParsePlatform(platformStr string) (*v1.Platform, error) {
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

func WithOptions(ctx context.Context, platform *v1.Platform) []remote.Option {
	// prepare options
	options := []remote.Option{MultiKeychainOption(), remote.WithTransport(HttpTransport()), remote.WithContext(ctx)}

	// add in platform into remote Get operation; this might conflict with an explicit digest, but we are trying anyway
	if platform != nil {
		options = append(options, remote.WithPlatform(*platform))
	}
	return options
}

func ExtractEnvelopes(manifest *attestation.AttestationManifest, predicateType string) ([]*att.Envelope, error) {
	var envs []*att.Envelope
	dsseMediaType, err := attestation.DSSEMediaType(predicateType)
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

func imageDescriptor(ix *v1.IndexManifest, platform *v1.Platform) (*v1.Descriptor, error) {
	for _, m := range ix.Manifests {
		if (m.MediaType == ocispec.MediaTypeImageManifest || m.MediaType == "application/vnd.docker.distribution.manifest.v2+json") && m.Platform.Equals(*platform) {
			return &m, nil
		}
	}
	return nil, errors.New(fmt.Sprintf("no image found for platform %v", platform))
}

func attestationDigestForDigest(ix *v1.IndexManifest, imageDigest string, attestType string) (string, error) {
	for _, m := range ix.Manifests {
		if v, ok := m.Annotations[att.DockerReferenceType]; ok && v == attestType {
			if d, ok := m.Annotations[att.DockerReferenceDigest]; ok && d == imageDigest {
				return m.Digest.String(), nil
			}
		}
	}
	return "", errors.New(fmt.Sprintf("no attestation found for image %s", imageDigest))
}

func RefToPURL(ref string, platform *v1.Platform) (string, bool, error) {
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

	if platform != nil {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "platform",
			Value: platform.String(),
		})
	}

	p := packageurl.NewPackageURL("docker", ns, name, version, qualifiers, "")
	return p.ToString(), isCanonical, nil
}

func SplitDigest(digest string) (common.DigestSet, error) {
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid digest %q", digest)
	}
	return common.DigestSet{
		parts[0]: parts[1],
	}, nil
}

func ReplaceTagInSpec(src *ImageSpec, digest v1.Hash) (*ImageSpec, error) {
	newName, err := replaceTag(src.Identifier, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repo name: %w", err)
	}
	return &ImageSpec{
		Identifier: newName,
		Type:       src.Type,
		Platform:   src.Platform,
	}, nil
}

// so that the index tag is replaced with a tag unique to the image digest and doesn't overwrite it
func replaceTag(image string, digest v1.Hash) (string, error) {
	if strings.HasPrefix(image, LocalPrefix) {
		return image, nil
	}
	notag, err := WithoutTag(image)
	if err != nil {
		return "", nil
	}
	return fmt.Sprintf("%s:%s-%s.att", notag, digest.Algorithm, digest.Hex), nil
}
