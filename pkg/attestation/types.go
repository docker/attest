package attestation

import (
	"encoding/base64"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	DockerReferenceType        = "vnd.docker.reference.type"
	AttestationManifestType    = "attestation-manifest"
	DockerReferenceDigest      = "vnd.docker.reference.digest"
	DockerDsseExtKind          = "application/vnd.docker.attestation-verification.v1+json"
	RekorTlExtKind             = "Rekor"
	OCIDescriptorDSSEMediaType = ociv1.MediaTypeDescriptor + "+dsse"
)

var base64Encoding = base64.StdEncoding.Strict()

type AttestationLayer struct {
	Statement   *intoto.Statement
	Layer       v1.Layer
	MediaType   types.MediaType
	Annotations map[string]string
}

type AttestationImage struct {
	Layers []AttestationLayer
	Image  v1.Image
}

type SignedAttestationImage struct {
	Image               v1.Image
	Desc                *v1.Descriptor
	AttestationManifest AttestationManifest
}

type AttestationManifest struct {
	Manifest          v1.Descriptor
	Attestation       AttestationImage
	MediaType         types.MediaType
	Annotations       map[string]string
	Digest            v1.Hash
	SubjectDescriptor *v1.Descriptor
}

// the following types are needed until https://github.com/secure-systems-lab/dsse/pull/61 is merged
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}
type Signature struct {
	KeyID     string    `json:"keyid"`
	Sig       string    `json:"sig"`
	Extension Extension `json:"extension"`
}
type Extension struct {
	Kind string              `json:"kind"`
	Ext  DockerDsseExtension `json:"ext"`
}

type DockerDsseExtension struct {
	Tl DockerTlExtension `json:"tl"`
}

type DockerTlExtension struct {
	Kind string `json:"kind"`
	Data any    `json:"data"`
}

type VerifyOptions struct {
	Keys   []KeyMetadata `json:"keys"`
	SkipTL bool          `json:"skip_tl"`
}

type SigningOptions struct {
	// replace unsigned statements with signed attestations
	Replace bool
	// don't log to the configured transparency log
	SkipTL bool
	// don't add OCI subject field to attestation image
	SkipSubject bool
}

func DSSEMediaType(predicateType string) (string, error) {
	var predicateName string
	switch predicateType {
	case v02.PredicateSLSAProvenance:
		predicateName = "provenance"
	case intoto.PredicateSPDX:
		predicateName = "spdx"
	case VSAPredicateType:
		predicateName = "verification_summary"

	default:
		return "", fmt.Errorf("unknown predicate type %q", predicateType)
	}

	return fmt.Sprintf("application/vnd.in-toto.%s+dsse", predicateName), nil
}
