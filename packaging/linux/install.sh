#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Install a TrailGuard Linux deployment bundle.

Usage:
  ./install.sh [options]

Options:
  --install-dir <dir>   Install root (default: /opt/trailguard)
  --link-dir <dir>      Symlink directory (default: /usr/local/bin)
  --force-config        Overwrite existing config files
  --no-symlink          Do not create command symlinks
  -h, --help            Show this help

Examples:
  sudo ./install.sh
  ./install.sh --install-dir "$HOME/.local/trailguard" --link-dir "$HOME/.local/bin"
EOF
}

PACKAGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/trailguard"
LINK_DIR="/usr/local/bin"
FORCE_CONFIG=0
NO_SYMLINK=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    --link-dir)
      LINK_DIR="$2"
      shift 2
      ;;
    --force-config)
      FORCE_CONFIG=1
      shift
      ;;
    --no-symlink)
      NO_SYMLINK=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[install] unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

for required in install mkdir cp ln rm; do
  command -v "$required" >/dev/null 2>&1 || {
    echo "[install] missing required command: $required" >&2
    exit 1
  }
done

mkdir -p \
  "$INSTALL_DIR/bin" \
  "$INSTALL_DIR/config" \
  "$INSTALL_DIR/artifacts" \
  "$INSTALL_DIR/reports" \
  "$INSTALL_DIR/logs" \
  "$INSTALL_DIR/docs"

install -m 0755 "$PACKAGE_ROOT/bin/trailguard" "$INSTALL_DIR/bin/trailguard"
for wrapper in "$PACKAGE_ROOT"/bin/trailguard-*; do
  install -m 0755 "$wrapper" "$INSTALL_DIR/bin/$(basename "$wrapper")"
done

for src in "$PACKAGE_ROOT"/config/*.toml; do
  cfg="$(basename "$src")"
  dst="$INSTALL_DIR/config/$cfg"
  if [[ -f "$dst" && "$FORCE_CONFIG" -ne 1 ]]; then
    echo "[install] preserving existing config: $dst"
  else
    install -m 0644 "$src" "$dst"
  fi
done

install -m 0644 "$PACKAGE_ROOT/QUICKSTART.txt" "$INSTALL_DIR/QUICKSTART.txt"
install -m 0644 "$PACKAGE_ROOT/BUILDINFO.txt" "$INSTALL_DIR/BUILDINFO.txt"
install -m 0644 "$PACKAGE_ROOT/docs/DEPLOYMENT.md" "$INSTALL_DIR/docs/DEPLOYMENT.md"
install -m 0755 "$PACKAGE_ROOT/uninstall.sh" "$INSTALL_DIR/uninstall.sh"

if [[ "$NO_SYMLINK" -ne 1 ]]; then
  mkdir -p "$LINK_DIR"
  for cmd in trailguard trailguard-snapshot trailguard-monitor trailguard-analyze trailguard-report trailguard-static-scan; do
    ln -sfn "$INSTALL_DIR/bin/$cmd" "$LINK_DIR/$cmd"
  done
fi

cat <<EOF
[install] TrailGuard installed to: $INSTALL_DIR
[install] Artifact root:           $INSTALL_DIR/artifacts
[install] Report root:             $INSTALL_DIR/reports
[install] Config root:             $INSTALL_DIR/config

Next steps:
  1. Review config:      $INSTALL_DIR/config/default.toml
  2. Static triage:      ${LINK_DIR}/trailguard-static-scan
  3. Snapshot only:      ${LINK_DIR}/trailguard-snapshot
  4. Realtime watch:     ${LINK_DIR}/trailguard-monitor --duration 300
  5. Analyze latest:     ${LINK_DIR}/trailguard-analyze
  6. Generate HTML:      ${LINK_DIR}/trailguard-report
EOF
