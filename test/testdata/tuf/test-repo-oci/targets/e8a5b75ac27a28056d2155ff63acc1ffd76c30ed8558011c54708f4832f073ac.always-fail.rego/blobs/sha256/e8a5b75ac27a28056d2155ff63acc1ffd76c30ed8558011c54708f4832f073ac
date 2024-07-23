package attest

import rego.v1

violations contains {
	"type": "always_fail",
	"description": "This policy always fails",
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
