package attest

import rego.v1

import data.config

splitDigest := split(input.digest, ":")

digestType := splitDigest[0]

digest := splitDigest[1]

allow if {
	some env in attestations.attestation("https://slsa.dev/verification_summary/v1")
}
