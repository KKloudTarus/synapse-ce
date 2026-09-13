import bus from 'bus';

function vuln() {
  return 1;
}

bus.handler = vuln;
bus.start();
