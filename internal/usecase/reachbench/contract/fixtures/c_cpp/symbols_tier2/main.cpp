#include <cstdlib>

namespace reachbench {
void controlPositive() {}
void controlUnreachable() {}
void controlOpaque() {}

void opaqueDispatch(const char* value) {
  if (value != nullptr && value[0] == 'o') controlOpaque();
}

// This capability marker represents unsupported inline-assembly coverage, not a dead function.
void controlNoCoverage() {}
}  // namespace reachbench

int main() {
  reachbench::controlPositive();
  reachbench::opaqueDispatch(std::getenv("REACHBENCH_CONTROL"));
}
