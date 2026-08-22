#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
src_dir="${repo_root}/internal/infrastructure/ebpf/c"
clang_bin="${CLANG:-clang}"
strip_bin="${LLVM_STRIP:-llvm-strip}"

if ! command -v "${clang_bin}" >/dev/null 2>&1; then
  echo "clang is required to build eBPF objects" >&2
  exit 1
fi
if ! command -v "${strip_bin}" >/dev/null 2>&1; then
  echo "llvm-strip is required to build eBPF objects" >&2
  exit 1
fi

multiarch=""
if command -v gcc >/dev/null 2>&1; then
  multiarch="$(gcc -print-multiarch 2>/dev/null || true)"
elif command -v dpkg-architecture >/dev/null 2>&1; then
  multiarch="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || true)"
fi
if [[ -z "${multiarch}" ]]; then
  case "$(uname -m)" in
    x86_64) multiarch="x86_64-linux-gnu" ;;
    aarch64) multiarch="aarch64-linux-gnu" ;;
  esac
fi
include_flags=(-I "${src_dir}")
if [[ -n "${multiarch}" && -d "/usr/include/${multiarch}" ]]; then
  include_flags+=(-I "/usr/include/${multiarch}")
fi

common_flags=(-target bpfel -O2 -g -Wall -Werror "-fdebug-prefix-map=${repo_root}=." "${include_flags[@]}")
sources=(connlog exec file priv netconn)

build_arch() {
  local goarch="$1"
  local target_arch="$2"
  local suffix="$3"

  for name in "${sources[@]}"; do
    local source="${src_dir}/${name}.bpf.c"
    local output="${src_dir}/${name}${suffix}.bpf.o"
    "${clang_bin}" "${common_flags[@]}" "-D__TARGET_ARCH_${target_arch}" -c "${source}" -o "${output}"
    # Keep BTF and BTF.ext for CO-RE, but remove nonessential DWARF/debug sections and absolute source
    # paths. The checked-in artifact remains loadable without clang on production hosts.
    "${strip_bin}" -g "${output}"
    echo "built ${output#"${repo_root}/"} (${goarch})"
  done
}

# Preserve the historical unsuffixed names for amd64 so existing checkouts and diffs remain small.
build_arch amd64 x86 ""
build_arch arm64 arm64 ".arm64"
