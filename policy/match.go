package policy

import (
	"fmt"

	"github.com/docker/attest/mapping"
)

type matchType string

const (
	matchTypePolicy        matchType = "policy"
	matchTypeMatchNoPolicy matchType = "match_no_policy"
	matchTypeNoMatch       matchType = "no_match"
)

type policyMatch struct {
	matchType   matchType
	policy      *mapping.PolicyMapping
	rule        *mapping.PolicyRule
	matchedName string
}

func findPolicyMatch(imageName string, mappings *mapping.PolicyMappings) (*policyMatch, error) {
	if mappings == nil {
		return &policyMatch{matchType: matchTypeNoMatch, matchedName: imageName}, nil
	}
	return findPolicyMatchImpl(imageName, mappings, make(map[*mapping.PolicyRule]bool))
}

func findPolicyMatchImpl(imageName string, mappings *mapping.PolicyMappings, matched map[*mapping.PolicyRule]bool) (*policyMatch, error) {
	for _, rule := range mappings.Rules {
		if rule.Pattern.MatchString(imageName) {
			switch {
			case rule.PolicyID == "" && rule.Replacement == "":
				return nil, fmt.Errorf("rule %s has neither policy-id nor rewrite", rule.Pattern)
			case rule.PolicyID != "" && rule.Replacement != "":
				return nil, fmt.Errorf("rule %s has both policy-id and rewrite", rule.Pattern)
			case rule.PolicyID != "":
				policy := mappings.Policies[rule.PolicyID]
				if policy != nil {
					return &policyMatch{
						matchType:   matchTypePolicy,
						policy:      policy,
						rule:        rule,
						matchedName: imageName,
					}, nil
				}
				return &policyMatch{
					matchType:   matchTypeMatchNoPolicy,
					rule:        rule,
					matchedName: imageName,
				}, nil
			case rule.Replacement != "":
				if matched[rule] {
					return nil, fmt.Errorf("rewrite loop detected")
				}
				matched[rule] = true
				imageName = rule.Pattern.ReplaceAllString(imageName, rule.Replacement)
				return findPolicyMatchImpl(imageName, mappings, matched)
			}
		}
	}
	return &policyMatch{matchType: matchTypeNoMatch, matchedName: imageName}, nil
}
