export { controlPositive } from "@reachbench/lexical";

import * as opaqueControls from "@reachbench/lexical-opaque";

const opaqueName = globalThis.__REACHBENCH_CONTROL__;
if (typeof opaqueName === "string" && opaqueName.length > 0) {
  opaqueControls[opaqueName]();
}
