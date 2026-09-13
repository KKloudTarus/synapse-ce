function log(x) {
  return x;
}

class Base {
  run() {
    this.step();
  }

  step() {
    return log(1);
  }
}

class Derived extends Base {
  step() {
    return log(2);
  }
}

const d = new Derived();
d.run();
