package attest_test

import rego.v1

import data.attest

test_sucess if {
	attest.success
}
