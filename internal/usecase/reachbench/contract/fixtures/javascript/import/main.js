import { run as directRun } from "@reachbench/direct";

export async function entry() {
  directRun();
  const opaqueSpecifier = "@reachbench/dynamic";
  (await import(opaqueSpecifier)).run();
}

entry();
