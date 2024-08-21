package attest

import rego.v1

keys := [{
	"id": "6b241993defaba26558c64f94a94303ce860e7ad9163d801495c91cf57197c75",
	"key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZmicqYSY38DprGr42jU0V3ND0ROj\nzSRH1+yjsxhh0bi52Hh/DuOhrSq2KJ5a09lW3ybnDjljowbkof0Y1i9Oow==\n-----END PUBLIC KEY-----",
	"from": "2023-12-15T14:00:00Z",
	"to": null,
	# this key is still active
	"status": "active",
	"signing-format": "dssev1",
}]

provs(pred) := p if {
	res := attest.fetch(pred)
	not res.error
	p := res.value
}

atts := union({
	provs("https://slsa.dev/provenance/v0.2"),
	provs("https://spdx.dev/Document"),
})

opts := {"keys": keys}

statements contains s if {
	some att in atts
	res := attest.verify(att, opts)
	not res.error
	s := res.value
}

subjects contains subject if {
	some statement in statements
	some subject in statement.subject
}

success if {
	# print("input:",input)
	true
}

result := {
	"success": success,
	"violations": set(),
	"summary": {
		"subjects": subjects,
		"slsa_levels": ["SLSA_BUILD_LEVEL_3"],
		"verifier": "docker-official-images",
		"policy_uri": "https://docker.com/official/policy/v0.1",
	},
}
