package attest

import rego.v1

keys := [{
	"id": "a0c296026645799b2a297913878e81b0aefff2a0c301e97232f717e14402f3e4",
	"key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgH23D1i2+ZIOtVjmfB7iFvX8AhVN\n9CPJ4ie9axw+WRHozGnRy99U2dRge3zueBBg2MweF0zrToXGig2v3YOrdw==\n-----END PUBLIC KEY-----",
	"from": "2023-12-15T14:00:00Z",
	"to": null,
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

success if {
	input.domain == "docker.io"
	input.familiarName == "test-image"
	input.normalizedName == "library/test-image"
	input.platform == "linux/amd64"
	input.tag == "test"
}

result := {
	"success": success,
	"violations": set(),
	"attestations": set(),
	"summary": {
		"subjects": set(),
		"slsa_level": "SLSA_BUILD_LEVEL_3",
		"verifier": "docker-official-images",
		"policy_uri": "https://docker.com/official/policy/v0.1",
	},
}
