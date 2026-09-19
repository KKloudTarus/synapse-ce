require "reachbench/direct"

Reachbench::Direct.run
opaque_constant = ["Reachbench", "Dynamic"].join("::")
require "reachbench/dynamic"
Object.const_get(opaque_constant).run
