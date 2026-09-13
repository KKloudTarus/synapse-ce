function doWork() {
  return 1;
}

const table = { run: doWork };

function handler(name) {
  table[name]();
}

handler("run");
