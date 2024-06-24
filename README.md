# attest
library to create, verify, and evaluate policy for attestations on container images

[![codecov](https://codecov.io/gh/docker/attest/branch/main/graph/badge.svg?token=YOUR_TOKEN)](https://codecov.io/gh/docker/attest)

# usage
## signing and verifying attestations
See [example_sign_test.go](./pkg/attest/example_sign_test.go)

See [example_verify_test.go](./pkg/attest/example_verify_test.go)

## mirroring TUF repositories to OCI
See [example_mirror_test.go](./pkg/mirror/example_mirror_test.go)

### using `go-tuf` OCI registry client
See [example_registry_test.go](./pkg/tuf/example_registry_test.go)
