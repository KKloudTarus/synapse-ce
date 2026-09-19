import { crossModuleTarget } from "./module.mjs";

function entry() {
  controlPositive();
  const alias = functionAliasTarget;
  alias();
  invokeSynchronously(callbackTarget);
  returnedCallable()();
  crossModuleTarget();
  opaqueDispatch(process.env.REACHBENCH_CONTROL);
}

function controlPositive() {}
function controlUnreachable() {}

function opaqueDispatch(name) {
  const handler = { opaque: controlOpaque }[name];
  if (handler) handler();
}

function controlOpaque() {}
// This marker is a deterministic unavailable parser capability, not an unused source target.
function controlNoCoverage() {}
function functionAliasTarget() {}
function callbackTarget() {}
function invokeSynchronously(callback) { callback(); }
function returnedCallable() { return returnedCallableTarget; }
function returnedCallableTarget() {}

entry();
