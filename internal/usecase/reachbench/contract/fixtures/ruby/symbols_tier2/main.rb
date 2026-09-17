def entry
  control_positive
  symbol_positive
  opaque_dispatch(ENV.fetch("REACHBENCH_CONTROL", ""))
end

def control_positive; end
def control_unreachable; end

def opaque_dispatch(name)
  handler = { "opaque" => method(:control_opaque) }[name]
  handler.call if handler
end

def control_opaque; end
def control_no_coverage; end

def symbol_positive; end

entry
