function vuln() {
  return 1;
}

function safe() {
  return 0;
}

function factory(selectVulnerable) {
  if (selectVulnerable) {
    return vuln;
  }
  return safe;
}

factory(process.env.REACHBENCH_TARGET)();
