Gem::Specification.new do |spec|
  spec.name = "reachbench-ruby-import"
  spec.version = "1.0.0"
  spec.summary = "Closed local import fixture"
  spec.files = ["main.rb"]
  spec.add_runtime_dependency "reachbench-direct", "= 1.0.0"
  spec.add_runtime_dependency "reachbench-dynamic", "= 1.0.0"
  spec.add_runtime_dependency "reachbench-unused", "= 1.0.0"
  spec.add_runtime_dependency "reachbench-unsupported", "= 1.0.0"
  spec.metadata["reachbench.no_coverage_capabilities"] = "reachbench-unsupported"
end
