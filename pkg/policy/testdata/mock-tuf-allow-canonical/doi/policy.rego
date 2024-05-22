package attest

import rego.v1

result := {
  "success": input.isCanonical,
}
