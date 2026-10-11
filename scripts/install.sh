#!/usr/bin/env bash
# User-level installer for AVHSOL: no sudo, no changes to your shell files.
#
#   scripts/install.sh                      build and install to ~/.local
#   scripts/install.sh --prefix DIR         install to DIR instead (bin/ and share/avhsol/ are created inside)
#   scripts/install.sh --with-harness       also copy the built pi harness (needs Node; for simulated-tool scenarios and `hunt`)
#   scripts/install.sh --uninstall [--purge]   remove what this script installed (--purge also removes your runs and keys)
#
# Installs: bin/avhsol, bin/avhsol-proxy, bin/avhsol-sandbox, share/avhsol/{scenarios,seeds,targets}.
# Your signing key and settings live in ~/.config/avhsol, runs and the threat-intel cache in ~/.local/share/avhsol.
set -euo pipefail

PREFIX="${HOME}/.local"
WITH_HARNESS=0
UNINSTALL=0
PURGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
    --with-harness) WITH_HARNESS=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
done

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$PREFIX/bin"
SHARE="$PREFIX/share/avhsol"
CONFIG="${AVHSOL_CONFIG:-$HOME/.config/avhsol}"
STATE="${AVHSOL_STATE:-$HOME/.local/share/avhsol}"
MANIFEST="$SHARE/.installed"

if [ "$UNINSTALL" = 1 ]; then
  if [ -f "$MANIFEST" ]; then
    while IFS= read -r f; do [ -n "$f" ] && rm -f -- "$f"; done < "$MANIFEST"
  fi
  rm -rf -- "$SHARE/scenarios" "$SHARE/seeds" "$SHARE/targets" "$SHARE/pi" "$MANIFEST"
  rmdir "$SHARE" 2>/dev/null || true
  echo "removed AVHSOL from $PREFIX"
  if [ "$PURGE" = 1 ]; then rm -rf -- "$CONFIG" "$STATE"; echo "removed $CONFIG and $STATE"; else echo "kept your runs and keys in $STATE and $CONFIG (use --purge to delete them)"; fi
  exit 0
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1 ($2)" >&2; exit 1; }; }
need go "Go 1.22 or newer builds the control plane: https://go.dev/dl/"
need cargo "Rust builds the guard proxy and the sandbox: https://rustup.rs"

echo "== building the control plane (Go)"
( cd "$REPO/core" && go build -trimpath -o bin/avhsol ./cmd/avhsol )
echo "== building the guard proxy and sandbox (Rust, release)"
( cd "$REPO/guard" && cargo build --release -q -p avhsol-proxy -p avhsol-sandbox )

mkdir -p "$BIN" "$SHARE"
: > "$MANIFEST.new"
put() { install -m 0755 "$1" "$BIN/$2"; echo "$BIN/$2" >> "$MANIFEST.new"; }
put "$REPO/core/bin/avhsol" avhsol
put "$REPO/guard/target/release/avhsol-proxy" avhsol-proxy
put "$REPO/guard/target/release/avhsol-sandbox" avhsol-sandbox

for d in scenarios seeds targets; do
  rm -rf -- "${SHARE:?}/$d"
  cp -R "$REPO/$d" "$SHARE/$d"
done
# generated seeds belong to a person's threat-intel sync, not to the package
rm -f "$SHARE/seeds/intel-generated.yaml"

if [ "$WITH_HARNESS" = 1 ]; then
  if [ ! -f "$REPO/pi/packages/avhsol/src/rpc.ts" ]; then echo "no pi harness in $REPO/pi" >&2; exit 1; fi
  echo "== copying the pi harness (large; needs Node to run)"
  rm -rf -- "$SHARE/pi"
  mkdir -p "$SHARE/pi"
  ( cd "$REPO/pi" && tar cf - --exclude=.git --exclude='*.log' . ) | ( cd "$SHARE/pi" && tar xf - )
fi

mv "$MANIFEST.new" "$MANIFEST"
mkdir -p "$CONFIG" "$STATE"
chmod 700 "$CONFIG" "$STATE"
if [ ! -f "$CONFIG/signing.key" ]; then
  AVHSOL_HOME="$SHARE" "$BIN/avhsol" keygen -out "$CONFIG/signing.key" >/dev/null
  echo "created your trace-signing key in $CONFIG (keep it private)"
fi

echo
echo "installed AVHSOL to $PREFIX"
case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo "NOTE: $BIN is not on your PATH. Add this to your shell profile:"; echo "      export PATH=\"$BIN:\$PATH\"" ;;
esac
cat <<MSG

Next:
  cd /path/to/your/agent && avhsol .      read the code, then attack it in a sandbox and write the report
  avhsol                                  the menu
  claude mcp add avhsol -- avhsol mcp     use AVHSOL from Claude Code
For the attack step set AVHSOL_LLM_BASE_URL, AVHSOL_LLM_MODEL and AVHSOL_LLM_API_KEY (the key stays in your environment).
MSG
