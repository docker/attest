package mapping

import (
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type matchType string

const (
	MatchTypePolicy        matchType = "policy"
	MatchTypeMatchNoPolicy matchType = "match_no_policy"
	MatchTypeNoMatch       matchType = "no_match"
)

type PolicyMatch struct {
	MatchType   matchType
	Policy      *PolicyMapping
	Rule        *PolicyRule
	MatchedName string
}

func (mappings *PolicyMappings) FindPolicyMatch(imageName string, platform *v1.Platform) (*PolicyMatch, error) {
	if mappings == nil {
		return &PolicyMatch{MatchType: MatchTypeNoMatch, MatchedName: imageName}, nil
	}
	return mappings.findPolicyMatchImpl(imageName, platform, make(map[*PolicyRule]bool))
}

func (mappings *PolicyMappings) findPolicyMatchImpl(imageName string, platform *v1.Platform, matched map[*PolicyRule]bool) (*PolicyMatch, error) {
	for _, rule := range mappings.Rules {
		platformMatch := false
		if len(rule.Platforms) == 0 {
			platformMatch = true
		}
		for i := range rule.Platforms {
			if rule.Platforms[i].Equals(*platform) {
				platformMatch = true
				break
			}
		}
		if !platformMatch {
			continue
		}
		if rule.Pattern.MatchString(imageName) {
			switch {
			case rule.PolicyID == "" && rule.Replacement == "":
				return nil, fmt.Errorf("rule %s has neither policy-id nor rewrite", rule.Pattern)
			case rule.PolicyID != "" && rule.Replacement != "":
				return nil, fmt.Errorf("rule %s has both policy-id and rewrite", rule.Pattern)
			case rule.PolicyID != "":
				policy := mappings.Policies[rule.PolicyID]
				if policy != nil {
					return &PolicyMatch{
						MatchType:   MatchTypePolicy,
						Policy:      policy,
						Rule:        rule,
						MatchedName: imageName,
					}, nil
				}
				return &PolicyMatch{
					MatchType:   MatchTypeMatchNoPolicy,
					Rule:        rule,
					MatchedName: imageName,
				}, nil
			case rule.Replacement != "":
				if matched[rule] {
					return nil, fmt.Errorf("rewrite loop detected")
				}
				matched[rule] = true
				imageName = rule.Pattern.ReplaceAllString(imageName, rule.Replacement)
				return mappings.findPolicyMatchImpl(imageName, platform, matched)
			}
		}
	}
	return &PolicyMatch{MatchType: MatchTypeNoMatch}, nil
}
