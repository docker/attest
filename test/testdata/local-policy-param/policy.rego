package attest

import rego.v1

import data.keys
import input.parameters

provs(pred) := p if {
	res := attest.fetch(pred)
	not res.error
	p := res.value
}

atts := union({
	provs("https://slsa.dev/provenance/v0.2"),
	provs("https://spdx.dev/Document"),
})

opts := {"keys": keys, "skip_tl": true}

statements contains s if {
	parameters.foo == "bar"
	some att in atts
	res := attest.verify(att, opts)
	not res.error
	s := res.value
}

subjects contains subject if {
	some statement in statements
	some subject in statement.subject
}

unsafe_statement_from_attestation(att) := statement if {
	payload := att.payload
	statement := json.unmarshal(base64.decode(payload))
}

violations contains violation if {
	some att in atts
	statement := unsafe_statement_from_attestation(att)
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
