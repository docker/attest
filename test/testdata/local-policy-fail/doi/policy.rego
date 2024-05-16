package attest

import rego.v1

import data.config

atts := union({
	attestations.attestation("https://slsa.dev/provenance/v0.2"),
	attestations.attestation("https://spdx.dev/Document")
})

statements contains s if {
  some att in atts
  s := attestations.verify_envelope(att, config.doi.keys)
}

subjects contains subject if {
  print("statements ")
	some statement in statements
  print("statement ")
	some subject in statement.subject
  print("subject ", subject)
}

violations contains v if {
	v := {
		"type": "missing_attestation",
		"description": "Attestation missing for subject",
		"attestation": null,
		"details": {}
	}
}

result := {
	"success": false,
	"violations": violations,
	"attestations": statements,
	"summary": {
		"subjects": subjects,
		"slsa_level": "SLSA_BUILD_LEVEL_3",
		"verifier": "docker-official-images",
    "policy_uri": "https://docker.com/official/policy/v0.1"
	},
}
