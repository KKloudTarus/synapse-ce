export function entry() {
  controlPositive();
  opaqueDispatch(process.env.REACHBENCH_CONTROL);
}

function controlPositive() {}
function controlUnreachable() {}
function opaqueDispatch(name) {
  const handler = { opaque: controlOpaque }[name];
  if (handler) handler();
}
function controlOpaque() {}
// This marker tracks deterministic parser unavailability, not dead source.
function controlNoCoverage() {}

entry();
