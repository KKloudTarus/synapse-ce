#!/usr/bin/env bash
# install-tools.sh – install the external binaries Synapse shells out to,
# at PINNED versions, so operators don't hand-install them. Checksum verification is
# delegated to Anchore's official installers (they verify the download against the
# release checksums file); recon tools install via `go install` at pinned versions
# (verified through the Go module proxy + checksum database).
#
# Usage:
#   scripts/install-tools.sh                 # syft + grype into ./bin (the SCA essentials)
#   scripts/install-tools.sh --recon         # also subfinder/httpx/naabu (Linux recon; opt-in)
#   BINDIR=/usr/local/bin scripts/install-tools.sh   # install elsewhere
#
# Pins are overridable via env (SYFT_VERSION, GRYPE_VERSION, …) so an operator can
# match the sha256 pins configured in the binregistry.
set -euo pipefail

# ---- pinned versions (override via env) ----
SYFT_VERSION="${SYFT_VERSION:-v1.45.1}"   # matches deploy/Dockerfile
GRYPE_VERSION="${GRYPE_VERSION:-v0.115.0}"
SUBFINDER_VERSION="${SUBFINDER_VERSION:-v2.6.6}"
HTTPX_VERSION="${HTTPX_VERSION:-v1.6.9}"
NAABU_VERSION="${NAABU_VERSION:-v2.3.3}"

BINDIR="${BINDIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin}"
WITH_RECON=0
[ "${1:-}" = "--recon" ] && WITH_RECON=1

uname_s="$(uname -s)"
say()  { printf '\033[36m▸ %s\033[0m\n' "$*"; }
warn() { printf '\033[33m! %s\033[0m\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

mkdir -p "$BINDIR"
say "Installing Synapse tools into: $BINDIR"

# ---- syft + grype via Anchore's official, checksum-verifying installers ----
# Fetch install.sh pinned to the release tag (not a moving branch), then install the
# pinned tool version. The installer verifies the binary against the release checksums.
install_anchore() {
  local tool="$1" version="$2"
  if have curl; then
    curl -sSfL "https://raw.githubusercontent.com/anchore/${tool}/${version}/install.sh" \
      | sh -s -- -b "$BINDIR" "$version"
  elif have wget; then
    wget -qO- "https://raw.githubusercontent.com/anchore/${tool}/${version}/install.sh" \
      | sh -s -- -b "$BINDIR" "$version"
  else
    warn "need curl or wget to install ${tool}; skipping"
    return 1
  fi
}

say "syft ${SYFT_VERSION}"
install_anchore syft "$SYFT_VERSION"
say "grype ${GRYPE_VERSION}"
install_anchore grype "$GRYPE_VERSION"

# ---- bubblewrap (Linux sandbox). macOS has no bwrap → sandbox off. ----
if [ "$uname_s" = "Linux" ]; then
  if have bwrap; then
    say "bubblewrap already present: $(command -v bwrap)"
  elif have apt-get; then say "installing bubblewrap (apt)";  sudo apt-get update -qq && sudo apt-get install -y bubblewrap
  elif have dnf;     then say "installing bubblewrap (dnf)";  sudo dnf install -y bubblewrap
  elif have pacman;  then say "installing bubblewrap (pacman)"; sudo pacman -S --noconfirm bubblewrap
  elif have apk;     then say "installing bubblewrap (apk)";   sudo apk add bubblewrap
  else warn "could not detect a package manager for bubblewrap – install it manually"
  fi
else
  warn "bubblewrap is Linux-only; on ${uname_s} the sandbox + live recon stay disabled (fail-closed, by design)"
fi

# ---- recon tools (opt-in, Linux): ProjectDiscovery via pinned `go install` ----
if [ "$WITH_RECON" = 1 ]; then
  if [ "$uname_s" != "Linux" ]; then
    warn "recon tools (subfinder/httpx/naabu) are used only inside the Linux sandbox; installing on ${uname_s} is for convenience only"
  fi
  if ! have go; then
    warn "go toolchain not found – skipping recon tools"
  else
    export GOBIN="$BINDIR"
    say "subfinder ${SUBFINDER_VERSION}"; go install "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}" || warn "subfinder install failed (check SUBFINDER_VERSION)"
    say "httpx ${HTTPX_VERSION}";         go install "github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}"             || warn "httpx install failed (check HTTPX_VERSION)"
    say "naabu ${NAABU_VERSION}";         go install "github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION}"          || warn "naabu install failed (naabu needs libpcap headers + raw-socket caps on the host)"
  fi
fi

echo
say "Done. Installed binaries in $BINDIR:"
for t in syft grype subfinder httpx naabu; do
  [ -x "$BINDIR/$t" ] && printf '   %-10s %s\n' "$t" "$("$BINDIR/$t" version 2>/dev/null | head -1 || echo present)"
done
echo
case ":$PATH:" in
  *":$BINDIR:"*) : ;;
  *) warn "Add $BINDIR to PATH, or point Synapse at the binaries explicitly:"
     echo "     export PATH=\"$BINDIR:\$PATH\""
     echo "     # or: export SYNAPSE_SYFT_BIN=$BINDIR/syft ; export SYNAPSE_GRYPE_BIN=$BINDIR/grype" ;;
esac
