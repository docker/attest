package attest

import rego.v1

keys := [{
	"id": "a0c296026645799b2a297913878e81b0aefff2a0c301e97232f717e14402f3e4",
	"key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgH23D1i2+ZIOtVjmfB7iFvX8AhVN\n9CPJ4ie9axw+WRHozGnRy99U2dRge3zueBBg2MweF0zrToXGig2v3YOrdw==\n-----END PUBLIC KEY-----",
	"from": "2023-12-15T14:00:00Z",
	"to": null,
}]

opts := {"keys": keys}

success if {
	some env in attest.fetch("foo")
	statement := attest.verify(env, opts)
}

result := {"success": success}
