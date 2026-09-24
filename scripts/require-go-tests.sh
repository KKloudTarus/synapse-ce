#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 4 ]; then
  echo "usage: require-go-tests.sh EXPECTED_TESTS JSONL_PATH MODE GO_TEST_ARGS..." >&2
  exit 2
fi

expected="$1"
report="$2"
mode="$3"
shift 3
case "$mode" in
  pass|measurement) ;;
  *) echo "unknown benchmark test mode: $mode" >&2; exit 2 ;;
esac

mkdir -p "$(dirname "$report")"
go test -count=1 -json "$@" | tee "$report"

IFS=',' read -r -a required <<< "$expected"
if [ "${#required[@]}" -eq 0 ]; then
  echo "benchmark has no required tests" >&2
  exit 1
fi
for name in "${required[@]}"; do
  if [ -z "$name" ]; then
    echo "benchmark has an empty required test name" >&2
    exit 1
  fi
  if ! jq -e --arg name "$name" 'select(.Action == "pass" and .Test == $name)' "$report" > /dev/null; then
    echo "required benchmark test did not pass: $name" >&2
    exit 1
  fi
  if [ "$mode" = measurement ] &&
    ! jq -e --arg name "$name" 'select(.Action == "output" and .Test == $name and (.Output | test("samples=[1-9][0-9]*")) and (.Output | test("dataset=")))' "$report" > /dev/null; then
    echo "required benchmark measurement is absent: $name" >&2
    exit 1
  fi
done

if ! jq -e 'select(.Action == "pass" and .Test == null and .Package != null)' "$report" > /dev/null; then
  echo "benchmark package did not report a passing result" >&2
  exit 1
fi
