package policy

import (
	"github.com/docker/attest/pkg/config"
	"github.com/docker/attest/pkg/tuf"
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

type PolicyOptions struct {
	TUFClient        tuf.TUFDownloader
	LocalTargetsDir  string
	LocalPolicyDir   string
	PolicyID         string
	ReferrersRepo    string
	AttestationStyle config.AttestationStyle
}

type Policy struct {
	InputFiles   []*PolicyFile
	Query        string
	Mapping      *config.PolicyMapping
	ResolvedName string
}

type PolicyInput struct {
	Digest      string `json:"digest"`
	PURL        string `json:"purl"`
	IsCanonical bool   `json:"isCanonical"`
}

type PolicyFile struct {
	Path    string
	Content []byte
}
