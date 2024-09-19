package attest

import rego.v1

success if {
	some env in attest.fetch("foo")
}
