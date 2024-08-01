package attestation

import (
	"encoding/base64"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	DockerReferenceType           = "vnd.docker.reference.type"
	AttestationManifestType       = "attestation-manifest"
	InTotoPredicateType           = "in-toto.io/predicate-type"
	DockerReferenceDigest         = "vnd.docker.reference.digest"
	DockerDSSEExtKind             = "application/vnd.docker.attestation-verification.v1+json"
	RekorTLExtKind                = "Rekor"
	OCIDescriptorDSSEMediaType    = ociv1.MediaTypeDescriptor + "+dsse"
	InTotoReferenceLifecycleStage = "vnd.docker.lifecycle-stage"
	LifecycleStageExperimental    = "experimental"
)

var base64Encoding = base64.StdEncoding.Strict()

type AttestationLayer struct {
	Statement   *intoto.Statement
	Layer       v1.Layer
	Annotations map[string]string
}

type AttestationManifest struct {
	OriginalDescriptor *v1.Descriptor
	OriginalLayers     []*AttestationLayer

	// accumulated during signing
	SignedLayers []*AttestationLayer
	// details of subect image
	SubjectName       string
	SubjectDescriptor *v1.Descriptor
}

type AttestationManifestImageOptions struct {
	// how to output the image
	skipSubject   bool
	replaceLayers bool
	laxReferrers  bool
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
	Extension Extension `json:"extension,omitempty"`
}
type Extension struct {
	Kind string              `json:"kind"`
	Ext  DockerDSSEExtension `json:"ext"`
}

type DockerDSSEExtension struct {
	TL DockerTLExtension `json:"tl"`
}

type DockerTLExtension struct {
	Kind string `json:"kind"`
	Data any    `json:"data"`
}

type VerifyOptions struct {
	Keys   []KeyMetadata `json:"keys"`
	SkipTL bool          `json:"skip_tl"`
}

type SigningOptions struct {
	// don't log to the configured transparency log
	SkipTL bool
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
