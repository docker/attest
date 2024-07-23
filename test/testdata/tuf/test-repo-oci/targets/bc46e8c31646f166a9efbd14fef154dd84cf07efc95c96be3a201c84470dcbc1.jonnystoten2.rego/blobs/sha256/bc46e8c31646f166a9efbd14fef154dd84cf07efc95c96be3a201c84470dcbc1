package attest

import rego.v1

split_digest := split(input.digest, ":")

digest_type := split_digest[0]

digest := split_digest[1]

keys := [{
	"id": "a0c296026645799b2a297913878e81b0aefff2a0c301e97232f717e14402f3e4",
	"key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgH23D1i2+ZIOtVjmfB7iFvX8AhVN\n9CPJ4ie9axw+WRHozGnRy99U2dRge3zueBBg2MweF0zrToXGig2v3YOrdw==\n-----END PUBLIC KEY-----",
	"from": "2023-12-15T14:00:00Z",
	"to": null,
	"status": "active",
	"signing-format": "dssev1",
}]

verify_opts := {"keys": keys}

verify_attestation(att) := attest.verify(att, verify_opts)

attestations contains att if {
	result := attest.fetch("https://slsa.dev/verification_summary/v1")
	not result.error
	some att in result.value
}

signed_statements contains statement if {
	some att in attestations
	result := verify_attestation(att)
	not result.error
	statement := result.value
}

statements_with_subject contains statement if {
	some statement in signed_statements
	some subject in statement.subject
	subject.digest[digest_type] == digest
	valid_subject_name(input.isCanonical, subject.name, input.purl)
}

id(statement) := crypto.sha256(json.marshal(statement))

subjects contains subject if {
	some statement in statements_with_subject
	some subject in statement.subject
}

global_violations contains v if {
	count(attestations) == 0
	v := {
		"type": "missing_attestation",
		"description": "No https://slsa.dev/verification_summary/v1 attestation found",
		"attestation": null,
		"details": {},
	}
}

# we need to key this by statement_id rather than statement because we can't
# use an object as a key due to a bug(?) in OPA: https://github.com/open-policy-agent/opa/issues/6736
statement_violations[statement_id] contains v if {
	some att in attestations
	result := verify_attestation(att)
	err := result.error
	statement := unsafe_statement_from_attestation(att)
	statement_id := id(statement)
	v := {
		"type": "unsigned_statement",
		"description": sprintf("Statement is not correctly signed: %v", [err]),
		"attestation": statement,
		"details": {"error": err},
	}
}

statement_violations[statement_id] contains v if {
	some statement in signed_statements
	statement_id := id(statement)
	not statement in statements_with_subject
	v := {
		"type": "bad_subjects",
		"description": "Statement does not have this image as a subject",
		"attestation": statement,
		"details": {"input": input},
	}
}

statement_violations[statement_id] contains v if {
	some statement in statements_with_subject
	statement_id := id(statement)
	v := field_value_does_not_equal(statement, "verificationResult", "PASSED", "wrong_verification_result")
}

# TODO: add to statement_violations if there are statements that have an incorrect resource_uri
# this should match the input.purl, but we really only care about the repo name and the digest
# we need to receive the input.purl as a parsed object so we can compare only the parts we care about

statement_violations[statement_id] contains v if {
	some statement in statements_with_subject
	statement_id := id(statement)
	v := field_value_does_not_equal(statement, "verifier.id", "signing-demo-verifier", "wrong_verifier")
}

statement_violations[statement_id] contains v if {
	some statement in statements_with_subject
	statement_id := id(statement)
	v := field_value_does_not_equal(statement, "policy.uri", "https://docker.com/official/policy/v0.1", "wrong_policy_uri")
}

statement_violations[statement_id] contains v if {
	some statement in statements_with_subject
	statement_id := id(statement)
	v := array_field_does_not_contain(statement, "verifiedLevels", "SLSA_BUILD_LEVEL_3", "wrong_verified_levels")
}

bad_statements contains statement if {
	some statement in statements_with_subject
	statement_id := id(statement)
	statement_violations[statement_id]
}

good_statements := statements_with_subject - bad_statements

all_violations contains v if {
	some v in global_violations
}

all_violations contains v if {
	some violations in statement_violations
	some v in violations
}

result := {
	"success": allow,
	"violations": all_violations,
	"summary": {
		"subjects": subjects,
		"slsa_levels": ["SLSA_BUILD_LEVEL_3"],
		"verifier": "signing-demo-verifier",
		"policy_uri": "https://docker.com/official/policy/v0.1",
	},
}

default allow := false

allow if {
	count(good_statements) > 0
}

# TODO: this should take into account the repo name from the purl
valid_subject_name(true, name, purl)

valid_subject_name(false, name, purl) if {
	name == purl
}

field_value_does_not_equal(statement, field, expected, type) := v if {
	path := split(field, ".")
	actual := object.get(statement.predicate, path, null)
	expected != actual
	v := is_not_violation(statement, field, expected, actual, type)
}

array_field_does_not_contain(statement, field, expected, type) := v if {
	path := split(field, ".")
	actual := object.get(statement.predicate, path, null)
	not expected in actual
	v := not_contains_violation(statement, field, expected, actual, type)
}

is_not_violation(statement, field, expected, actual, type) := {
	"type": type,
	"description": sprintf("%v is not %v", [field, expected]),
	"attestation": statement,
	"details": {
		"field": field,
		"actual": actual,
		"expected": expected,
	},
}

not_contains_violation(statement, field, expected, actual, type) := {
	"type": type,
	"description": sprintf("%v does not contain %v", [field, expected]),
	"attestation": statement,
	"details": {
		"field": field,
		"actual": actual,
		"expected": expected,
	},
}

# This is unsafe because we're not checking the signature on the attestation,
# do not call this unless you've already verified the attestation or you need the
# statement for some other reason
unsafe_statement_from_attestation(att) := statement if {
	payload := att.payload
	statement := json.unmarshal(base64.decode(payload))
}
