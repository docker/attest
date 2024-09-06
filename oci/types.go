package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const (
	OCIReferenceTarget            = "org.opencontainers.image.ref.name"
	LocalPrefix                   = "oci://"
	RegistryPrefix                = "docker://"
	OCI                SourceType = "OCI"
	Docker             SourceType = "Docker"
)

type (
	SourceType string
	NamedIndex struct {
		Index v1.ImageIndex
		Name  string
	}
)

type ImageSpecOption func(*ImageSpec) error

type ImageSpec struct {
	// OCI or Docker
	Type SourceType
	// without oci:// or docker:// (name or path)
	Identifier string
	Platform   *v1.Platform
}

func IndexFromPath(path string) (*NamedIndex, error) {
	wrapperIdx, err := layout.ImageIndexFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load image index: %w", err)
	}

	idxm, err := wrapperIdx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get digest: %w", err)
	}
	imageName := idxm.Manifests[0].Annotations[OCIReferenceTarget]
	idxDigest := idxm.Manifests[0].Digest

	idx, err := wrapperIdx.ImageIndex(idxDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ImageIndex for digest %s: %w", idxDigest.String(), err)
	}
	return &NamedIndex{
		Index: idx,
		Name:  imageName,
	}, nil
}

func IndexFromRemote(ctx context.Context, image string) (*NamedIndex, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference %s: %w", image, err)
	}

	// Pull the image from the registry
	idx, err := remote.Index(ref, WithOptions(ctx, nil)...)
	if err != nil {
		return nil, fmt.Errorf("failed to pull image %s: %w", image, err)
	}
	return &NamedIndex{
		Index: idx,
		Name:  image,
	}, nil
}

func LoadIndex(ctx context.Context, input *ImageSpec) (*NamedIndex, error) {
	if input.Type == OCI {
		return IndexFromPath(input.Identifier)
	}
	return IndexFromRemote(ctx, input.Identifier)
}

func (i *ImageSpec) ForPlatforms(platform string) ([]*ImageSpec, error) {
	platforms := strings.Split(platform, ",")
	var specs []*ImageSpec
	for _, pStr := range platforms {
		p, err := ParsePlatform(pStr)
		if err != nil {
			return nil, err
		}
		spec := &ImageSpec{
			Type:       i.Type,
			Identifier: i.Identifier,
			Platform:   p,
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
		Identifier: withoutPrefix,
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

func WithoutTag(image string) (string, error) {
	if strings.HasPrefix(image, LocalPrefix) {
		return image, nil
	}
	prefix := ""
	if strings.HasPrefix(image, RegistryPrefix) {
		image = strings.TrimPrefix(image, RegistryPrefix)
		prefix = RegistryPrefix
	}
	ref, err := name.ParseReference(image)
	if err != nil {
		return "", err
	}
	repo := ref.Context().Name()
	return prefix + repo, nil
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

func (i *EmptyConfigImage) Digest() (v1.Hash, error) {
	mb, err := i.RawManifest()
	if err != nil {
		return v1.Hash{}, err
	}
	digest, _, err := v1.SHA256(bytes.NewReader(mb))
	return digest, err
}
