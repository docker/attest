package oci

import (
	"context"
	"fmt"
	"strings"

	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	"github.com/docker/attest/internal/util"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/package-url/packageurl-go"
)

// ParsePlatform parses the provided platform string or attempts to obtain
// the platform of the current host system.
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
	}
	return v1.ParsePlatform(platformStr)
}

func WithOptions(ctx context.Context, platform *v1.Platform) []remote.Option {
	// prepare options
	options := []remote.Option{
		MultiKeychainOption(),
		remote.WithContext(ctx),
		remote.WithUserAgent(util.GetUserAgent(ctx)),
	}

	// add in platform into remote Get operation; this might conflict with an explicit digest, but we are trying anyway
	if platform != nil {
		options = append(options, remote.WithPlatform(*platform))
	}
	return options
}

func ImageDescriptor(ix *v1.IndexManifest, platform *v1.Platform) (*v1.Descriptor, error) {
	for i := range ix.Manifests {
		m := &ix.Manifests[i]
		if (m.MediaType == ocispec.MediaTypeImageManifest || m.MediaType == "application/vnd.docker.distribution.manifest.v2+json") && m.Platform.Equals(*platform) {
			return m, nil
		}
	}
	return nil, fmt.Errorf("no image found for platform %v", platform)
}

func RefToPURL(named reference.Named, platform *v1.Platform) (string, bool, error) {
	var isCanonical bool
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

	p := packageurl.NewPackageURL(packageurl.TypeDocker, ns, name, version, qualifiers, "")
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
	newName, err := ReplaceTag(src.Identifier, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repo name: %w", err)
	}
	return &ImageSpec{
		Identifier: newName,
		Type:       src.Type,
		Platform:   src.Platform,
	}, nil
}

// so that the index tag is replaced with a tag unique to the image digest and doesn't overwrite it.
func ReplaceTag(image string, digest v1.Hash) (string, error) {
	if strings.HasPrefix(image, LocalPrefix) {
		return image, nil
	}
	notag, err := WithoutTag(image)
	if err != nil {
		return "", nil
	}
	return fmt.Sprintf("%s:%s-%s.att", notag, digest.Algorithm, digest.Hex), nil
}

func ReplaceDigestInSpec(src *ImageSpec, digest v1.Hash) (*ImageSpec, error) {
	newName, err := replaceDigest(src.Identifier, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repo name: %w", err)
	}
	return &ImageSpec{
		Identifier: newName,
		Type:       src.Type,
		Platform:   src.Platform,
	}, nil
}

func replaceDigest(image string, digest v1.Hash) (string, error) {
	if strings.HasPrefix(image, LocalPrefix) {
		return image, nil
	}
	notag, err := WithoutTag(image)
	if err != nil {
		return "", nil
	}
	return fmt.Sprintf("%s@%s:%s", notag, digest.Algorithm, digest.Hex), nil
}
