package attest

import rego.v1

# this file only exists in the testing delegation

violations contains {
	"type": "testing_delegation",
	"description": "This policy always fails. We'd better not promote this to production.",
}

result := {
	"success": false,
	"violations": violations,
	"summary": {
		"subjects": set(),
		"slsa_levels": ["SLSA_BUILD_LEVEL_3"],
		"verifier": "docker-official-images",
		"policy_uri": "https://docker.com/official/policy/v0.1",
	},
}
