#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Uninstall TrailGuard from a Linux host.

Usage:
  ./uninstall.sh [options]

Options:
  --install-dir <dir>  Install root (default: /opt/trailguard)
  --link-dir <dir>     Symlink directory (default: /usr/local/bin)
  --purge-data         Remove the full install root including config and evidence
  -h, --help           Show this help
EOF
}

INSTALL_DIR="/opt/trailguard"
LINK_DIR="/usr/local/bin"
PURGE_DATA=0

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
    --purge-data)
      PURGE_DATA=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[uninstall] unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

for cmd in trailguard trailguard-snapshot trailguard-monitor trailguard-analyze trailguard-report trailguard-static-scan; do
  rm -f "$LINK_DIR/$cmd"
done

if [[ "$PURGE_DATA" -eq 1 ]]; then
  rm -rf "$INSTALL_DIR"
  echo "[uninstall] removed install root: $INSTALL_DIR"
else
  rm -rf "$INSTALL_DIR/bin" "$INSTALL_DIR/docs"
  rm -f "$INSTALL_DIR/QUICKSTART.txt" "$INSTALL_DIR/BUILDINFO.txt" "$INSTALL_DIR/uninstall.sh"
  echo "[uninstall] removed executables and docs; config/artifacts/reports/logs preserved in $INSTALL_DIR"
fi
