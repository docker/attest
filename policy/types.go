package policy

import (
	"github.com/docker/attest/attestation"
	"github.com/docker/attest/config"
	"github.com/docker/attest/tuf"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

type Summary struct {
	Subjects   []intoto.Subject `json:"subjects"`
	SLSALevels []string         `json:"slsa_levels"`
	Verifier   string           `json:"verifier"`
	PolicyURI  string           `json:"policy_uri"`
}

type Violation struct {
	Type        string            `json:"type"`
	Description string            `json:"description"`
	Attestation *intoto.Statement `json:"attestation"`
	Details     map[string]any    `json:"details"`
}

type Result struct {
	Success    bool        `json:"success"`
	Violations []Violation `json:"violations"`
	Summary    Summary     `json:"summary"`
}

type Options struct {
	TUFClientOptions    *tuf.ClientOptions
	DisableTUF          bool
	LocalTargetsDir     string
	LocalPolicyDir      string
	PolicyID            string
	ReferrersRepo       string
	AttestationStyle    config.AttestationStyle
	Debug               bool
	AttestationVerifier attestation.Verifier
}

type Policy struct {
	InputFiles   []*File
	Query        string
	Mapping      *config.PolicyMapping
	ResolvedName string
	URI          string
	Digest       map[string]string
}

type Input struct {
	Digest         string `json:"digest"`
	PURL           string `json:"purl"`
	Tag            string `json:"tag,omitempty"`
	Domain         string `json:"domain"`
	NormalizedName string `json:"normalized_name"`
	FamiliarName   string `json:"familiar_name"`
	Platform       string `json:"platform"`
}

type File struct {
	Path    string
	Content []byte
}
