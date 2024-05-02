package attest

import rego.v1

import data.config

splitDigest := split(input.digest, ":")

digestType := splitDigest[0]

digest := splitDigest[1]

allow if {
	some env in attestations.attestation("https://slsa.dev/verification_summary/v0.1")
	some statement in verified_statements(config.doi.keys, env)
}


verified_statements(keys, env) := statements if {
	statements := {statement |
		statement := attestations.verify_envelope(env, keys)
		some subject in statement.subject
		valid_subject(subject)
	}
}


valid_subject(sub) if {
	print("valid_subject")
	print("sub.digest[digestType]:", sub.digest[digestType])
	print("digest", digest)
	sub.digest[digestType] == digest
	print("digest matches")
	valid_subject_name(sub.name)
}

valid_subject_name(name) if {
	input.canonical
	print("is canonical, ignoring name")
}

valid_subject_name(name) if {
	not input.canonical
	print("valid_subject_name...")
	print("name:", name)
	print("input.purl:", input.purl)
	name == input.purl
	print("name match")
}
