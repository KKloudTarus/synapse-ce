function log(x) {
  return x;
}

class A {
  get danger() {
    return log(1);
  }
}

const o = new A();
const y = o.danger;
