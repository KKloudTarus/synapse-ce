function secret() {
  return 1;
}

function handler(code) {
  eval(code);
}

handler("secret()");
