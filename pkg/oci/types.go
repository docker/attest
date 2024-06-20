package oci

import (
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const (
	AttestationManifestType = "attestation-manifest"
	InTotoPredicateType     = "in-toto.io/predicate-type"
	OciReferenceTarget      = "org.opencontainers.image.ref.name"
)

type SubjectIndex struct {
	Index v1.ImageIndex
	Name  string
}

func SubjectIndexFromPath(path string) (*SubjectIndex, error) {
	wrapperIdx, err := layout.ImageIndexFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load image index: %w", err)
	}

	idxm, err := wrapperIdx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get digest: %w", err)
	}
	imageName := idxm.Manifests[0].Annotations[OciReferenceTarget]
	idxDigest := idxm.Manifests[0].Digest

	idx, err := wrapperIdx.ImageIndex(idxDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ImageIndex for digest %s: %w", idxDigest.String(), err)
	}
	return &SubjectIndex{
		Index: idx,
		Name:  imageName,
	}, nil
}

func SubjectIndexFromRemote(image string) (*SubjectIndex, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference %s: %w", image, err)
	}
	// Get the authenticator from the default Docker keychain
	auth, err := authn.DefaultKeychain.Resolve(ref.Context())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve auth for image %s: %w", image, err)
	}
	// Pull the image from the registry
	idx, err := remote.Index(ref, remote.WithAuth(auth))
	if err != nil {
		return nil, fmt.Errorf("failed to pull image %s: %w", image, err)
	}
	return &SubjectIndex{
		Index: idx,
		Name:  image,
	}, nil
}

const (
	LocalPrefix               = "oci://"
	RegistryPrefix            = "docker://"
	OCI            SourceType = "OCI"
	Docker         SourceType = "Docker"
)

type SourceType string

type AttestationOptions struct {
	NoReferrers   bool
	Attach        bool
	ReferrersRepo string
}

func LoadSubjectIndex(input *ImageSpec) (*SubjectIndex, error) {
	if input.Type == OCI {
		return SubjectIndexFromPath(input.WithoutPrefix)
	} else {
		return SubjectIndexFromRemote(input.WithoutPrefix)
	}
}

func (i *ImageSpec) ForPlatforms(platform string) ([]*ImageSpec, error) {
	platforms := strings.Split(platform, ",")
	var specs []*ImageSpec
	for _, p := range platforms {
		spec, err := ParseImageSpec(i.OriginalStr, WithPlatform(p))
		if err != nil {
			return nil, err
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

func ParseImageSpec(img string, options ...ImageSpecOption) (*ImageSpec, error) {
	img = strings.TrimSpace(img)
	if strings.Contains(img, ",") {
		return nil, fmt.Errorf("only one image is supported")
	}
	withoutPrefix := strings.TrimPrefix(strings.TrimPrefix(img, LocalPrefix), RegistryPrefix)
	src := &ImageSpec{
		OriginalStr:   img,
		WithoutPrefix: withoutPrefix,
	}
	if strings.HasPrefix(img, LocalPrefix) {
		src.Type = OCI
	} else {
		src.Type = Docker
	}
	for _, option := range options {
		err := option(src)
		if err != nil {
			return nil, err
		}
	}
	if src.Platform == nil {
		platform, err := ParsePlatform("")
		if err != nil {
			return nil, err
		}
		src.Platform = platform
	}
	return src, nil
}

type ImageSpecOption func(*ImageSpec) error

func WithPlatform(platform string) ImageSpecOption {
	return func(i *ImageSpec) error {
		if strings.Contains(platform, ",") {
			return fmt.Errorf("only one platform is supported")
		}
		p, err := ParsePlatform(platform)
		if err != nil {
			return err
		}
		i.Platform = p
		return nil
	}
}

func ParseImageSpecs(img string) ([]*ImageSpec, error) {
	outputs := strings.Split(img, ",")
	var sources []*ImageSpec
	for _, output := range outputs {
		src, err := ParseImageSpec(output)
		if err != nil {
			return nil, err
		}
		sources = append(sources, src)
	}
	return sources, nil
}

type ImageSpec struct {
	// as passed into the constructor
	OriginalStr string
	// OCI or Docker
	Type SourceType
	// without oci:// or docker://
	WithoutPrefix string
	Platform      *v1.Platform
}

func WithoutTag(image string) (string, error) {
	notag := image
	if strings.HasPrefix(image, LocalPrefix) {
		return image, nil
	}
	prefix := ""
	if strings.HasPrefix(image, RegistryPrefix) {
		notag = strings.TrimPrefix(image, RegistryPrefix)
		prefix = RegistryPrefix
	}
	ref, err := name.ParseReference(notag)
	if err != nil {
		return "", err
	}
	repo := ref.Context().Name()
	return prefix + repo, nil
}
