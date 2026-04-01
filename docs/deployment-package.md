# Linux Deployment Bundle

TrailGuard ships a Linux deployment bundle for fast rollout of the native binary, default configs, rulesets, and install helpers.

The bundle includes:

- `trailguard`
- `trailguard-static-scan`
- `trailguard-snapshot`
- `trailguard-monitor`
- `trailguard-analyze`
- `trailguard-report`
- `config/default.toml`
- `config/default-fast.toml`
- `config/default-standard.toml`
- `config/rules.toml`
- `config/rules-miner.toml`
- `install.sh`
- `uninstall.sh`
- `QUICKSTART.txt`
- `BUILDINFO.txt`

## 1. Build the bundle

Run on a Linux build host:

```bash
./scripts/package-linux-bundle.sh
```

Default behavior:

- Target triple: `x86_64-unknown-linux-musl`
- Output directory: `./dist`
- Automatically checks local eBPF build requirements:
  - `cargo +nightly`
  - nightly `rust-src`
  - `bpf-linker`
- Prefers a locally built native eBPF object when requirements are present
- Falls back to the repo prebuilt object when local eBPF build is unavailable or fails
- Produces a no-embed build when `--skip-ebpf` is set

Examples:

```bash
./scripts/package-linux-bundle.sh
./scripts/package-linux-bundle.sh --profile fast
./scripts/package-linux-bundle.sh --target x86_64-unknown-linux-gnu
./scripts/package-linux-bundle.sh --bundle-name trailguard-linux-prod
./scripts/package-linux-bundle.sh --ebpf-object /path/to/trailguard-ebpf.bpfel
./scripts/package-linux-bundle.sh --skip-ebpf
./scripts/package-linux-bundle.sh --require-ebpf
./scripts/package-linux-bundle.sh --keep-staging
```

## 2. Output layout

Build output:

```text
dist/
  trailguard-linux-<target>-<timestamp>.tar.gz
```

Expanded layout:

```text
trailguard-linux-.../
  install.sh
  uninstall.sh
  QUICKSTART.txt
  BUILDINFO.txt
  bin/
    trailguard
    trailguard-static-scan
    trailguard-snapshot
    trailguard-monitor
    trailguard-analyze
    trailguard-report
  config/
    default.toml
    rules.toml
    rules-miner.toml
  docs/
    DEPLOYMENT.md
```

`BUILDINFO.txt` includes:

- build time
- target triple
- main binary SHA-256
- eBPF embedding mode
- eBPF source (`local-build`, `repo-prebuilt`, `explicit`, or `none`)
- eBPF object SHA-256

The package script also emits sidecar files next to the tarball by default:

- `<bundle>.tar.gz.sha256`
- `<bundle>-OFFLINE.txt`

## 3. Install on the target host

Root install:

```bash
tar -xzf trailguard-linux-*.tar.gz
cd trailguard-linux-*
sudo ./install.sh
```

Non-root install:

```bash
./install.sh --install-dir "$HOME/.local/trailguard" --link-dir "$HOME/.local/bin"
```

Default install paths:

```text
/opt/trailguard
/usr/local/bin/trailguard
/usr/local/bin/trailguard-static-scan
/usr/local/bin/trailguard-snapshot
/usr/local/bin/trailguard-monitor
/usr/local/bin/trailguard-analyze
/usr/local/bin/trailguard-report
```

## 4. Offline distribution

Copy these files together:

```text
trailguard-linux-<target>-<timestamp>.tar.gz
trailguard-linux-<target>-<timestamp>.tar.gz.sha256
trailguard-linux-<target>-<timestamp>-OFFLINE.txt
```

Verify integrity on the destination host before extracting:

```bash
sha256sum -c trailguard-linux-<target>-<timestamp>.tar.gz.sha256
```

If `sha256sum` is unavailable, the expected checksum is also present in the sidecar note and can be compared manually.

Recommended offline transfer paths:

- internal artifact repository
- admin-only `scp` / `sftp`
- removable media with checksum verification on both ends

Keep `BUILDINFO.txt`, the `.sha256` file, and the sidecar note with the case archive when possible.

## 5. Run after install

One-shot static triage:

```bash
trailguard-static-scan
```

Snapshot only:

```bash
trailguard-snapshot
```

Realtime monitor:

```bash
trailguard-monitor --duration 300
```

Analyze the latest artifact:

```bash
trailguard-analyze
```

Render the latest HTML report:

```bash
trailguard-report
```

Miner-focused rules:

```bash
TRAILGUARD_RULES=/opt/trailguard/config/rules-miner.toml trailguard-analyze
TRAILGUARD_RULES=/opt/trailguard/config/rules-miner.toml trailguard-report
TRAILGUARD_RULES=/opt/trailguard/config/rules-miner.toml trailguard-static-scan
```

## 6. Wrapper behavior

The bundled wrapper commands automatically handle:

- default config path
- timestamped output directories for `snapshot` and `monitor`
- latest artifact discovery for `analyze` and `report`
- ruleset switching via:
  - `TRAILGUARD_RULES`
  - `TRAILGUARD_ARTIFACT_ROOT`
  - `TRAILGUARD_REPORT_ROOT`
  - `TRAILGUARD_HOME`

## 7. Operational boundaries

- This package is currently optimized for `x86_64 Linux`
- `snapshot`, `analyze`, and `report` run on most Linux hosts with `/proc`
- Native `monitor` eBPF capture needs:
  - root or equivalent privilege
  - kernel support for eBPF, kprobe, tracepoint, and perf event
- If runtime eBPF is unavailable, TrailGuard falls back to polling instead of failing outright
- The evidence chain is a best-effort reconstruction, not absolute omniscience
