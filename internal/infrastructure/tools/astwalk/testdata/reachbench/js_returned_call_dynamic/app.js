function vuln() {
  return 1;
}

function factory() {
  return vuln;
}

factory()();
