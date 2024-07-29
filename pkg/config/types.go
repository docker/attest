package config

import (
	"regexp"
)

type policyMappingsFile struct {
	Version  string            `json:"version"`
	Kind     string            `json:"kind"`
	Policies []*PolicyMapping  `json:"policies"`
	Rules    []*policyRuleFile `json:"rules"`
}

type policyRuleFile struct {
	Pattern     string `json:"pattern"`
	PolicyId    string `json:"policy-id"`
	Replacement string `json:"rewrite"`
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
	Pattern     *regexp.Regexp
	PolicyId    string
	Replacement string
}
