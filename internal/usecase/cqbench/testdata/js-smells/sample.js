function render(payload) {
  // TODO: sanitize payload before evaluating it.
  return eval(payload);
}

function compare(a, b) {
  if (a == b) {
    return true;
  }
  return false;
}
