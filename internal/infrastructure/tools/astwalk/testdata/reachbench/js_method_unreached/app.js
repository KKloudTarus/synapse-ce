class Service {
  handle() {
    return 1;
  }

  unused() {
    return 2;
  }
}

const s = new Service();
s.handle();
