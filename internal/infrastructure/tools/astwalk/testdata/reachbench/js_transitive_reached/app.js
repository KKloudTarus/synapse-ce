function handler() {
  stepOne();
}

function stepOne() {
  stepTwo();
}

function stepTwo() {
  return 1;
}

handler();
