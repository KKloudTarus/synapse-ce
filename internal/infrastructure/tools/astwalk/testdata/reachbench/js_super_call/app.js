function log(x) {
  return x;
}

class Base {
  step() {
    return log(1);
  }
}

class Derived extends Base {
  step() {
    return super.step();
  }
}

const d = new Derived();
d.step();
