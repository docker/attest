package policy

import (
	"fmt"

	"github.com/docker/attest/attestation"
	"github.com/docker/attest/config"
	"github.com/docker/attest/oci"
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
