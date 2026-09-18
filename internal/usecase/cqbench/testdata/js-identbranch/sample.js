function resolve(flag) {
  let handler;
  if (flag) {
    handler = registry.lookup("default");
  } else {
    handler = registry.lookup("default");
  }
  return handler;
}
