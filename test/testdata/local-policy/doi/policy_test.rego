package attest
import rego.v1

config := {"keys": []}
envs := [{"env": "test"}]
purl := "pkg:docker/library/alpine:1.2.3"

statement := {"subject": [{"name": purl, "digest": {"sha256": "dea014f47cd49d694d3a68564eb9e6ae38a7ee9624fd52ec05ccbef3f3fab8a0"}}]}
input_digest := "sha256:dea014f47cd49d694d3a68564eb9e6ae38a7ee9624fd52ec05ccbef3f3fab8a0"

test_with_mock_data if {
	allow with attestations.attestation as envs
        with attestations.verify_envelope as statement
        with input.digest as input_digest
        with input.purl as purl
        with input.canonical as false
}

layout_digest := "sha256:da8b190665956ea07890a0273e2a9c96bfe291662f08e2860e868eef69c34620"
outout_purl := "pkg:docker/test-image@test?platform=linux%2Famd64"
test_with_signed_oci_layout if {
    allow with input.digest as layout_digest
        with input.purl as outout_purl
        with input.canonical as false
}
