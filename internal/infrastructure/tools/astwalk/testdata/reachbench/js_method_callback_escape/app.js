function dispatch(fn) {
  return fn;
}

class Svc {
  run() {
    dispatch(this.onEvent);
  }

  onEvent() {
    return 1;
  }
}

const s = new Svc();
s.run();
