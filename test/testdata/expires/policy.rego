package attest

import rego.v1

import data.keys

split_digest := split(input.digest, ":")

digest_type := split_digest[0]

digest := split_digest[1]

keys[0].expires := [{
	# if the pattern and the platform match, the 'to' will be checked for expiration
	"patterns": ["^docker.io/library/test-image$"],
	"platforms": ["linux/amd64"],
	"to": "2024-10-04T15:00:00Z",
}]

param := "TEST"
key[0].param := param

provs(pred) := p if {
	res := attest.fetch(pred)
	not res.error
	p := res.value
}

atts := union({
	provs("https://spdx.dev/Document"),
})

statements contains merged if {
	some att in atts
	some key in keys
	opts := {"keys": [key], "skip_tl": false}
	res := attest.verify(att, opts)
	not res.error
	s := res.value
	# capture the key used to verify the statement for later use
	merged = object.union(s, {"key": key})
}

subjects contains subject if {
	some statement in statements
	statement.key.param == param
	some subject in statement.subject
}

unsafe_statement_from_attestation(att) := statement if {
	payload := att.payload
	statement := json.unmarshal(base64.decode(payload))
}

violations contains violation if {
	some att in atts
	statement := unsafe_statement_from_attestation(att)
	opts := {"keys": keys, "skip_tl": false}
	res := attest.verify(att, opts)
	err := res.error
	violation := {
		"type": "unsigned_statement",
		"description": sprintf("Statement is not correctly signed: %v", [err]),
		"attestation": statement,
		"details": {"error": err},
	}
}

result := {
	"success": count(statements) > 0,
	"violations": violations,
	"summary": {
		"subjects": subjects,
		"slsa_level": "SLSA_BUILD_LEVEL_3",
		"verifier": "docker-official-images",
		"policy_uri": "https://docker.com/official/policy/v0.1",
	},
}
