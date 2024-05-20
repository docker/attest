package attestation

import (
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/package-url/packageurl-go"
)

const (
	VSAPredicateType = "https://slsa.dev/verification_summary/v1"
)

type VerificationSummary struct {
	intoto.StatementHeader
	Predicate VSAPredicate `json:"predicate"`
}

type VSAPredicate struct {
	Verifier           VSAVerifier           `json:"verifier"`
	TimeVerified       string                `json:"timeVerified"`
	ResourceUri        string                `json:"resourceUri"`
	Policy             VSAPolicy             `json:"policy"`
	InputAttestations  []VSAInputAttestation `json:"inputAttestations"`
	VerificationResult string                `json:"verificationResult"`
	VerifiedLevels     []string              `json:"verifiedLevels"`
}

type VSAVerifier struct {
	ID string `json:"id"`
}

type VSAPolicy struct {
	URI string `json:"uri"`
}

type VSAInputAttestation struct {
	Digest    map[string]string `json:"digest"`
	MediaType string            `json:"mediaType"`
}

func ToVSAResourceURI(sub intoto.Subject) (string, error) {
	//parse purl
	purl, err := packageurl.FromString(sub.Name)
	if err != nil {
		return "", fmt.Errorf("failed to parse package url: %w", err)
	}
	quals := purl.Qualifiers.Map()
	if quals["digest"] == "" {
		quals["digest"] = "sha256:" + sub.Digest["sha256"]
	}
	purl.Qualifiers = packageurl.QualifiersFromMap(quals)
	return purl.String(), nil
}
