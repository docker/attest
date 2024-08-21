package attest

import rego.v1

result := {
  "success": input.is_canonical,
}
