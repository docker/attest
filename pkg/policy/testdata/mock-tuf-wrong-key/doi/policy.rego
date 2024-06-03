package attest

import rego.v1

keys := [{
	"id": "a0c296026645799b2a297913878e81b0aefff2a0c301e97232f717e14402f3e4",
	"key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHyZpSgzvqFqNv7f3x7865OS38rAb\nQMcff55zM2UH/KR3Pr84a8QsGDNgaNGzJQJWjtMSgfV8WnNoffNK+svFNg==\n-----END PUBLIC KEY-----",
	"from": "2023-12-15T14:00:00Z",
	"to": null,
}]

default success := false

opts := {"keys": keys}

success if {
	some env in attestations.attestation("foo")
	statement := attestations.verify(env, opts)
}

result := {"success": success}
