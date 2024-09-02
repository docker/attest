package attestation

import (
	"context"

	"github.com/docker/attest/oci"
)

type Resolver interface {
	oci.ImageDetailsResolver
	Attestations(ctx context.Context, mediaType string) ([]*Envelope, error)
}
