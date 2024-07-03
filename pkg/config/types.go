package config

import "regexp"

type policyMappingsFile struct {
	Version  string            `yaml:"version"`
	Kind     string            `yaml:"kind"`
	Policies []*PolicyMapping  `yaml:"policies"`
	Rules    []*policyRuleFile `yaml:"rules"`
}

type policyRuleFile struct {
	Pattern  string `yaml:"pattern"`
	PolicyId string `yaml:"policy-id"`
	Rewrite  string `yaml:"rewrite"`
}

type PolicyMappings struct {
	Version  string
	Kind     string
	Policies map[string]*PolicyMapping
	Rules    []*PolicyRule
}

type AttestationStyle string

const (
	AttestationStyleAttached  AttestationStyle = "attached"
	AttestationStyleReferrers AttestationStyle = "referrers"
)

type PolicyMapping struct {
	Id           string              `yaml:"id"`
	Description  string              `yaml:"description"`
	Files        []PolicyMappingFile `yaml:"files"`
	Attestations *AttestationConfig  `yaml:"attestations"`
}

type AttestationConfig struct {
	Style AttestationStyle `yaml:"style"`
	Repo  string           `yaml:"repo"`
}

type PolicyMappingFile struct {
	Path string `yaml:"path"`
}

type PolicyRule struct {
	Pattern  *regexp.Regexp
	PolicyId string
	Rewrite  string
}
