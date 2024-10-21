package git_checksum_test

import rego.v1

test_reproducible_git_checksum if {
	# test case from https://github.com/docker-library/meta/blob/5c3af85f2c735ea2b689271cb64ff38bcca28bec/builds.json
	#  build id: e1dc43214da28419a105a665f994080e83093c6849fe2851344350b8c264afd1
	# grab with `curl https://raw.githubusercontent.com/docker-library/meta/5c3af85f2c735ea2b689271cb64ff38bcca28bec/builds.json | jq '."e1dc43214da28419a105a665f994080e83093c6849fe2851344350b8c264afd1"'`

	repo := "https://github.com/docker-library/busybox.git"
	commit := "91f9975d4bb91d7c916ef74de77911d961ac9b75"
	dir := "latest/glibc/amd64"
	expected_checksum := "48d47b7ee1617a53291a76942cd240773fbb59daaa874007c6d16cb3125d63c2"

	result := attest.internals.reproducible_git_checksum(repo, commit, dir)
	actual_checksum := result.value
	actual_checksum == expected_checksum
}
