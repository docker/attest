package config

type PolicyMappings struct {
	Version  string          `json:"version"`
	Kind     string          `json:"kind"`
	Policies []PolicyMapping `json:"policies"`
	Mirrors  []PolicyMirror  `json:"mirrors"`
}

type AttestationStyle string

const (
	AttestationStyleAttached  AttestationStyle = "attached"
	AttestationStyleReferrers AttestationStyle = "referrers"
)

type PolicyMapping struct {
	Id           string              `json:"id"`
	Description  string              `json:"description"`
	Origin       *PolicyOrigin       `json:"origin"`
	Files        []PolicyMappingFile `json:"files"`
	Attestations *ReferrersConfig    `json:"attestations"`
}

type ReferrersConfig struct {
	Style AttestationStyle `json:"style"`
	Repo  string           `json:"repo"`
}

type PolicyMappingFile struct {
	Path string `json:"path"`
}

type PolicyMirror struct {
	PolicyId string     `yaml:"policy-id"`
	Mirror   MirrorSpec `json:"mirror"`
}

type MirrorSpec struct {
	Domains []string `json:"domains"`
	Prefix  string   `json:"prefix"`
}

type PolicyOrigin struct {
	Name   string `json:"name"`
	Prefix string `json:"prefix"`
	Domain string `json:"domain"`
}
