package config

type PolicyMappings struct {
	Version  string           `json:"version"`
	Kind     string           `json:"kind"`
	Policies []*PolicyMapping `json:"policies"`
	Rules    []*PolicyRule    `json:"rules"`
}

type AttestationStyle string

const (
	AttestationStyleAttached  AttestationStyle = "attached"
	AttestationStyleReferrers AttestationStyle = "referrers"
)

type PolicyMapping struct {
	Id           string              `json:"id"`
	Description  string              `json:"description"`
	Files        []PolicyMappingFile `json:"files"`
	Attestations *AttestationConfig  `json:"attestations"`
}

type AttestationConfig struct {
	Style AttestationStyle `json:"style"`
	Repo  string           `json:"repo"`
}

type PolicyMappingFile struct {
	Path string `json:"path"`
}

type PolicyRule struct {
	Pattern  string `json:"pattern"`
	PolicyId string `yaml:"policy-id"`
	Rewrite  string `json:"rewrite"`
}
