package attest

import rego.v1

default canonical = false

canonical if {
  not input.tag
}

result := {"success": canonical}
