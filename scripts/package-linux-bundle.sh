#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Build a self-contained Linux deployment bundle for TrailGuard.

Usage:
  ./scripts/package-linux-bundle.sh [options]

Options:
  --output-dir <dir>    Bundle output directory (default: ./dist)
  --target <triple>     Cargo target triple (default: x86_64-unknown-linux-musl)
  --profile <name>      Config profile: standard or fast (default: standard)
  --bundle-name <name>  Override bundle directory / tarball stem
  --ebpf-object <path>  Use a prebuilt eBPF object for embedding
  --skip-ebpf           Build without embedding any eBPF object
  --require-ebpf        Fail packaging if no eBPF object can be embedded
  --no-sidecar          Do not emit .sha256 / offline sidecar files
  --keep-staging        Keep expanded bundle directory after tarball creation
  -h, --help            Show this help

Notes:
  - Run this script on a Linux build host.
  - The script auto-checks nightly/rust-src/bpf-linker for native eBPF builds.
  - If local eBPF build prerequisites are missing, it falls back to the repo
    prebuilt object when available.
  - If no eBPF object can be embedded and --require-ebpf is not set, the
    packaged binary still works and falls back to polling where needed.
EOF
}

need_cmd() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || {
    echo "[package] missing required command: $name" >&2
    exit 1
  }
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
  else
    echo "unavailable"
  fi
}

copy_file() {
  local src="$1"
  local dst="$2"
  local mode="$3"
  install -m "$mode" "$src" "$dst"
}

check_ebpf_build_requirements() {
  have_cmd cargo || return 1
  have_cmd rustc || return 1
  have_cmd bpf-linker || return 1

  cargo +nightly --version >/dev/null 2>&1 || return 1
  local sysroot
  sysroot="$(rustc +nightly --print sysroot 2>/dev/null || true)"
  [[ -n "$sysroot" ]] || return 1
  [[ -f "$sysroot/lib/rustlib/src/rust/library/Cargo.lock" ]] || return 1
  return 0
}

prepare_embedded_ebpf() {
  local ebpf_manifest="$REPO_ROOT/crates/collector-linux-ebpf/ebpf/Cargo.toml"
  local repo_prebuilt="$REPO_ROOT/crates/collector-linux-ebpf/prebuilt/linux/trailguard-ebpf.bpfel"
  local ebpf_target_dir="$REPO_ROOT/target/package-ebpf"

  EFFECTIVE_EBPF_OBJECT=""
  EFFECTIVE_EBPF_MODE="disabled"
  EFFECTIVE_EBPF_SOURCE="none"
  EFFECTIVE_EBPF_NOTE="embedded eBPF disabled"

  if [[ "$SKIP_EBPF" -eq 1 ]]; then
    EFFECTIVE_EBPF_NOTE="embedded eBPF explicitly disabled by --skip-ebpf"
    return 0
  fi

  if [[ -n "$REQUESTED_EBPF_OBJECT" ]]; then
    EFFECTIVE_EBPF_OBJECT="$REQUESTED_EBPF_OBJECT"
    EFFECTIVE_EBPF_MODE="embedded"
    EFFECTIVE_EBPF_SOURCE="explicit"
    EFFECTIVE_EBPF_NOTE="using explicitly provided eBPF object"
    return 0
  fi

  if check_ebpf_build_requirements; then
    echo "[package] building native eBPF object"
    mkdir -p "$ebpf_target_dir"
    if cargo +nightly build \
      --release \
      --manifest-path "$ebpf_manifest" \
      --target bpfel-unknown-none \
      -Z build-std=core \
      --target-dir "$ebpf_target_dir"; then
      EFFECTIVE_EBPF_OBJECT="$ebpf_target_dir/bpfel-unknown-none/release/trailguard-ebpf"
      EFFECTIVE_EBPF_MODE="embedded"
      EFFECTIVE_EBPF_SOURCE="local-build"
      EFFECTIVE_EBPF_NOTE="embedded native eBPF object built during packaging"
      return 0
    fi
    if [[ -f "$repo_prebuilt" ]]; then
      echo "[package] local eBPF build failed; using repo prebuilt object"
      EFFECTIVE_EBPF_OBJECT="$repo_prebuilt"
      EFFECTIVE_EBPF_MODE="embedded"
      EFFECTIVE_EBPF_SOURCE="repo-prebuilt"
      EFFECTIVE_EBPF_NOTE="local eBPF build failed; used repo prebuilt fallback"
      return 0
    fi
    if [[ "$REQUIRE_EBPF" -eq 1 ]]; then
      echo "[package] failed to build required eBPF object and no repo prebuilt fallback exists" >&2
      exit 1
    fi
    echo "[package] warning: local eBPF build failed and no fallback object exists; packaging without embedded eBPF" >&2
    EFFECTIVE_EBPF_NOTE="local eBPF build failed and no repo prebuilt fallback exists"
    return 0
  fi

  if [[ -f "$repo_prebuilt" ]]; then
    echo "[package] using repo prebuilt eBPF object"
    EFFECTIVE_EBPF_OBJECT="$repo_prebuilt"
    EFFECTIVE_EBPF_MODE="embedded"
    EFFECTIVE_EBPF_SOURCE="repo-prebuilt"
    EFFECTIVE_EBPF_NOTE="local eBPF build requirements unavailable; used repo prebuilt fallback"
    return 0
  fi

  if [[ "$REQUIRE_EBPF" -eq 1 ]]; then
    echo "[package] local eBPF build requirements unavailable and no repo prebuilt fallback exists" >&2
    exit 1
  fi

  echo "[package] warning: no usable eBPF object source found; packaging without embedded eBPF" >&2
  EFFECTIVE_EBPF_NOTE="local eBPF build requirements unavailable and no repo prebuilt fallback exists"
  return 0
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/dist"
TARGET_TRIPLE="x86_64-unknown-linux-musl"
CONFIG_PROFILE="standard"
BUNDLE_NAME=""
KEEP_STAGING=0
SKIP_EBPF=0
REQUIRE_EBPF=0
NO_SIDECAR=0
EFFECTIVE_EBPF_OBJECT=""
REQUESTED_EBPF_OBJECT=""
EFFECTIVE_EBPF_MODE="disabled"
EFFECTIVE_EBPF_SOURCE="none"
EFFECTIVE_EBPF_NOTE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --target)
      TARGET_TRIPLE="$2"
      shift 2
      ;;
    --profile)
      CONFIG_PROFILE="$2"
      shift 2
      ;;
    --bundle-name)
      BUNDLE_NAME="$2"
      shift 2
      ;;
    --ebpf-object)
      REQUESTED_EBPF_OBJECT="$2"
      shift 2
      ;;
    --skip-ebpf)
      SKIP_EBPF=1
      shift
      ;;
    --require-ebpf)
      REQUIRE_EBPF=1
      shift
      ;;
    --no-sidecar)
      NO_SIDECAR=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --keep-staging)
      KEEP_STAGING=1
      shift
      ;;
    *)
      echo "[package] unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

case "$CONFIG_PROFILE" in
  standard|fast)
    ;;
  *)
    echo "[package] unsupported profile: $CONFIG_PROFILE (expected: standard|fast)" >&2
    exit 1
    ;;
esac

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[package] this bundle builder must run on a Linux build host" >&2
  exit 1
fi

need_cmd cargo
need_cmd tar
need_cmd install
need_cmd date

mkdir -p "$OUTPUT_DIR"

if [[ -z "$BUNDLE_NAME" ]]; then
  BUNDLE_PREFIX="trailguard-linux"
  if [[ "$CONFIG_PROFILE" != "standard" ]]; then
    BUNDLE_PREFIX="${BUNDLE_PREFIX}-${CONFIG_PROFILE}"
  fi
  BUNDLE_NAME="${BUNDLE_PREFIX}-${TARGET_TRIPLE//[^A-Za-z0-9._-]/-}-$(date -u +%Y%m%dT%H%M%SZ)"
fi

if [[ "$TARGET_TRIPLE" == *musl* ]] && command -v rustup >/dev/null 2>&1; then
  rustup target add "$TARGET_TRIPLE" >/dev/null 2>&1 || true
fi

prepare_embedded_ebpf

if [[ -n "$EFFECTIVE_EBPF_OBJECT" && ! -f "$EFFECTIVE_EBPF_OBJECT" ]]; then
  echo "[package] eBPF object not found: $EFFECTIVE_EBPF_OBJECT" >&2
  exit 1
fi

echo "[package] building trailguard for $TARGET_TRIPLE"
if [[ -n "$EFFECTIVE_EBPF_OBJECT" ]]; then
  TRAILGUARD_EBPF_OBJECT_PATH="$EFFECTIVE_EBPF_OBJECT" \
    cargo build --release -p trailguard --target "$TARGET_TRIPLE" --manifest-path "$REPO_ROOT/Cargo.toml"
elif [[ "$SKIP_EBPF" -eq 1 || "$EFFECTIVE_EBPF_MODE" == "disabled" ]]; then
  TRAILGUARD_DISABLE_EMBEDDED_EBPF=1 \
    cargo build --release -p trailguard --target "$TARGET_TRIPLE" --manifest-path "$REPO_ROOT/Cargo.toml"
else
  cargo build --release -p trailguard --target "$TARGET_TRIPLE" --manifest-path "$REPO_ROOT/Cargo.toml"
fi

BINARY_PATH="$REPO_ROOT/target/$TARGET_TRIPLE/release/trailguard"
[[ -f "$BINARY_PATH" ]] || {
  echo "[package] built binary not found: $BINARY_PATH" >&2
  exit 1
}

STAGING_DIR="$OUTPUT_DIR/$BUNDLE_NAME"
TARBALL_PATH="$OUTPUT_DIR/$BUNDLE_NAME.tar.gz"
SHA256_PATH="$TARBALL_PATH.sha256"
OFFLINE_README_PATH="$OUTPUT_DIR/$BUNDLE_NAME-OFFLINE.txt"
rm -rf "$STAGING_DIR" "$TARBALL_PATH"
rm -f "$SHA256_PATH" "$OFFLINE_README_PATH"

mkdir -p \
  "$STAGING_DIR/bin" \
  "$STAGING_DIR/config" \
  "$STAGING_DIR/docs"

DEFAULT_CONFIG_SOURCE="$REPO_ROOT/config/default.toml"
if [[ "$CONFIG_PROFILE" == "fast" ]]; then
  DEFAULT_CONFIG_SOURCE="$REPO_ROOT/config/default-fast.toml"
fi

copy_file "$BINARY_PATH" "$STAGING_DIR/bin/trailguard" 0755
for cfg in "$REPO_ROOT"/config/*.toml; do
  cfg_name="$(basename "$cfg")"
  if [[ "$cfg_name" == "default.toml" ]]; then
    continue
  fi
  copy_file "$cfg" "$STAGING_DIR/config/$cfg_name" 0644
done
copy_file "$DEFAULT_CONFIG_SOURCE" "$STAGING_DIR/config/default.toml" 0644
copy_file "$REPO_ROOT/packaging/linux/install.sh" "$STAGING_DIR/install.sh" 0755
copy_file "$REPO_ROOT/packaging/linux/uninstall.sh" "$STAGING_DIR/uninstall.sh" 0755
copy_file "$REPO_ROOT/packaging/linux/QUICKSTART.txt" "$STAGING_DIR/QUICKSTART.txt" 0644
copy_file "$REPO_ROOT/docs/deployment-package.md" "$STAGING_DIR/docs/DEPLOYMENT.md" 0644

for wrapper in "$REPO_ROOT"/packaging/linux/bin/*; do
  copy_file "$wrapper" "$STAGING_DIR/bin/$(basename "$wrapper")" 0755
done

cat >"$STAGING_DIR/BUILDINFO.txt" <<EOF
bundle_name=$BUNDLE_NAME
build_time_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
target_triple=$TARGET_TRIPLE
config_profile=$CONFIG_PROFILE
binary_sha256=$(sha256_file "$BINARY_PATH")
ebpf_mode=$EFFECTIVE_EBPF_MODE
ebpf_source=$EFFECTIVE_EBPF_SOURCE
ebpf_note=$EFFECTIVE_EBPF_NOTE
ebpf_object=$(if [[ -n "$EFFECTIVE_EBPF_OBJECT" ]]; then printf '%s' "$EFFECTIVE_EBPF_OBJECT"; else printf 'none'; fi)
ebpf_object_sha256=$(if [[ -n "$EFFECTIVE_EBPF_OBJECT" ]]; then sha256_file "$EFFECTIVE_EBPF_OBJECT"; else printf 'none'; fi)
binary_path=$(basename "$BINARY_PATH")
EOF

tar -C "$OUTPUT_DIR" -czf "$TARBALL_PATH" "$BUNDLE_NAME"

if [[ "$NO_SIDECAR" -ne 1 ]]; then
  TARBALL_SHA256="$(sha256_file "$TARBALL_PATH")"
  printf '%s  %s\n' "$TARBALL_SHA256" "$(basename "$TARBALL_PATH")" >"$SHA256_PATH"

  cat >"$OFFLINE_README_PATH" <<EOF
TrailGuard Offline Distribution Notes
====================================

Bundle:
  $(basename "$TARBALL_PATH")

Checksum file:
  $(basename "$SHA256_PATH")

Recommended files to transfer together:
  $(basename "$TARBALL_PATH")
  $(basename "$SHA256_PATH")

Integrity verification on the target host:
  sha256sum -c $(basename "$SHA256_PATH")

If sha256sum is unavailable, compare manually:
  expected: $TARBALL_SHA256

Offline install:
  tar -xzf $(basename "$TARBALL_PATH")
  cd $BUNDLE_NAME
  sudo ./install.sh

Non-root install:
  ./install.sh --install-dir "\$HOME/.local/trailguard" --link-dir "\$HOME/.local/bin"

Recommended offline transfer methods:
  - scp / sftp within an isolated admin network
  - signed internal artifact repository
  - removable media with checksum verification before install

Operational notes:
  - This bundle contains a native Linux binary and bundled configs.
  - Runtime eBPF support still depends on host kernel capability and privilege.
  - If runtime eBPF is unavailable, TrailGuard falls back to polling-based monitoring.
  - Preserve BUILDINFO.txt with the bundle for audit trail and binary provenance.
EOF
fi

echo "[package] bundle directory: $STAGING_DIR"
echo "[package] bundle tarball:   $TARBALL_PATH"
if [[ "$NO_SIDECAR" -ne 1 ]]; then
  echo "[package] bundle sha256:    $SHA256_PATH"
  echo "[package] offline notes:    $OFFLINE_README_PATH"
fi
echo "[package] install on target:"
echo "  tar -xzf $(basename "$TARBALL_PATH")"
echo "  cd $BUNDLE_NAME && sudo ./install.sh"

if [[ "$KEEP_STAGING" -ne 1 ]]; then
  rm -rf "$STAGING_DIR"
  echo "[package] removed staging directory (use --keep-staging to keep it)"
fi
