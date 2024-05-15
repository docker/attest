package attest

import rego.v1

import data.config

splitDigest := split(input.digest, ":")

digestType := splitDigest[0]

digest := splitDigest[1]

# allow if {
# 	some env in attestations.attestation("https://slsa.dev/verification_summary/v1")
# 	statement := verified_statement(config.doi.keys, env)
# 	valid_vsa(statement)
# }

default allow := false

allow if {
	count(violations) == 0
}

violations contains sbom_missing if {
	not sbom_envelope
	sbom_missing := "No SBOM found in attestation"
}

violations contains sbom_unsigned if {
	sbom_envelope
	not verified_statement(config.doi.keys, sbom_envelope)
	sbom_unsigned := "SBOM statement not correctly signed"
}

violations contains sbom_wrong_type if {
	sbom_envelope
	statement := verified_statement(config.doi.keys, sbom_envelope)
	not valid_sbom(statement)
	sbom_wrong_type := "SBOM statement not right type"
}

violations contains provenance_missing if {
	not provenance_envelope
	provenance_missing := "No provenance found in attestation"
}

violations contains provenance_unsigned if {
	provenance_envelope
	not verified_statement(config.doi.keys, provenance_envelope)
	provenance_unsigned := "provenance statement not correctly signed"
}

violations contains provenance_wrong_type if {
	provenance_envelope
	statement := verified_statement(config.doi.keys, provenance_envelope)
	not valid_provenance(statement)
	provenance_wrong_type := "provenance statement not right type"
}

atts := union({
	attestations.attestation("https://slsa.dev/provenance/v0.2"),
	attestations.attestation("https://spdx.dev/Document")
})

provenance_envelope := env if {
	some env in attestations.attestation("https://slsa.dev/provenance/v0.2")
}

sbom_envelope := env if {
	some env in attestations.attestation("https://spdx.dev/Document")
}

subjects contains subject if {
	some att in atts
	statement := verified_statement(config.doi.keys, att)
	some subject in statement.subject
}

result := {
	"success": allow,
	"violations": violations,
	"attestations": atts,
	"summary": {
		"subjects": subjects,
		"slsa_level": "SLSA_BUILD_LEVEL_3",
		"verifier": "docker-official-images"
	}
}

vsa_envelope := env if {
	some env in attestations.attestation("https://slsa.dev/verification_summary/v1")
}

verified_statement(keys, env) := statement if {
	statement := attestations.verify_envelope(env, keys)
	some subject in statement.subject
	valid_subject(subject)
}

valid_vsa(statement) if {
	statement.predicateType == "https://slsa.dev/verification_summary/v1"
}

valid_sbom(statement) if {
	statement.predicateType == "https://spdx.dev/Document"
}

valid_provenance(statement) if {
	statement.predicateType == "https://slsa.dev/provenance/v0.2"
}

valid_subject(sub) if {
	sub.digest[digestType] == digest
	valid_subject_name(sub.name)
}

valid_subject_name(name) if {
	input.canonical
}

valid_subject_name(name) if {
	not input.canonical
	name == input.purl
}
