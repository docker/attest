package def_parse_test

import rego.v1

test_parse_library_definition if {
	def := `Maintainers: me <me@example.com> (@me)
GitRepo: blah

Tags: 1, 2, 3
GitCommit: fa105cb3c26c8f0e87d7dbb1bf5293691ac2f688
File: Dockerfile.foo`
	result := attest.internals.parse_library_definition(def)
	definition := result.value
	definition.Entries[0].GitRepo == "blah"
	definition.Entries[0].GitCommit == "fa105cb3c26c8f0e87d7dbb1bf5293691ac2f688"
	definition.Entries[0].Tags == ["1", "2", "3"]
	definition.Entries[0].File == "Dockerfile.foo"
}
