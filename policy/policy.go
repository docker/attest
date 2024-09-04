package policy

import (
	"context"
	"fmt"

	"github.com/distribution/reference"
	"github.com/docker/attest/attestation"
	"github.com/docker/attest/config"
	"github.com/docker/attest/oci"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/package-url/packageurl-go"
)

func CreateImageDetailsResolver(imageSource *oci.ImageSpec) (oci.ImageDetailsResolver, error) {
	switch imageSource.Type {
	case oci.OCI:
		return attestation.NewOCILayoutResolver(imageSource)
	case oci.Docker:
		return oci.NewRegistryImageDetailsResolver(imageSource)
	}
	return nil, fmt.Errorf("unsupported image source type: %s", imageSource.Type)
}

func CreateAttestationResolver(resolver oci.ImageDetailsResolver, mapping *config.PolicyMapping) (attestation.Resolver, error) {
	if mapping.Attestations != nil {
		if mapping.Attestations.Style == config.AttestationStyleAttached {
			switch resolver := resolver.(type) {
			case *oci.RegistryImageDetailsResolver:
				return attestation.NewRegistryResolver(resolver)
			case *attestation.LayoutResolver:
				return resolver, nil
			default:
				return nil, fmt.Errorf("unsupported image details resolver type: %T", resolver)
			}
		}
		if mapping.Attestations.Repo != "" {
			return attestation.NewReferrersResolver(resolver, attestation.WithReferrersRepo(mapping.Attestations.Repo))
		}
	}
	return attestation.NewReferrersResolver(resolver)
}

// VerifySubject verifies if any of the given subject PURLs matches the image name and platform from resolver.
// Tags are not taken into account when attempting to match because sometimes the user may not have specified a tag, and maybe there
// isn't a purl subject with that particular tag (because of post build tagging?).
func VerifySubject(ctx context.Context, subject []intoto.Subject, resolver attestation.Resolver) error {
	img, err := resolver.ImageName(ctx)
	if err != nil {
		return err
	}
	inputName, err := reference.ParseNormalizedNamed(img)
	if err != nil {
		return err
	}
	descriptor, err := resolver.ImageDescriptor(ctx)
	if err != nil {
		return err
	}
	platform, err := resolver.ImagePlatform(ctx)
	if err != nil {
		return err
	}
	for _, sub := range subject {
		if sub.Digest[descriptor.Digest.Algorithm] != descriptor.Digest.Hex {
			continue
		}
		purl, err := packageurl.FromString(sub.Name)
		if err != nil {
			continue
		}
		if purl.Type != "docker" {
			continue
		}
		if purl.Qualifiers.Map()["platform"] != platform.String() {
			continue
		}
		// ensure reference is normalized before comparing
		subjectName, err := reference.ParseNormalizedNamed(purl.Name)
		if err != nil {
			continue
		}

		// this assumes that domain is part of the package URL (some say it should be a qualifier)
		// buildkit puts the domain in the name, e.g. pkg:docker/ecr.io/foobar/alpine@latest?platform=linux%2Famd64
		if inputName.Name() == subjectName.Name() {
			// found a match
			return nil
		}
	}
	return fmt.Errorf("no matching subject found for image: %s", img)
}
