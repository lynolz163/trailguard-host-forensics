# TrailGuard

TrailGuard is a defensive host forensics and incident triage tool for Linux and Windows systems.

It focuses on four things:

- local evidence collection
- explainable detection
- evidence correlation and timeline reconstruction
- operator-friendly reporting

TrailGuard is designed for authorized investigation and response work. It does not implement offensive capabilities such as exploitation, privilege escalation, lateral movement, persistence deployment, or data exfiltration.

## Why TrailGuard

Many host triage tools stop at surfacing suspicious signals. TrailGuard aims to go one step further by turning process, file, network, auth, and persistence evidence into a reviewable evidence package with traceable conclusions.

Core design goals:

- unified data model across Linux and Windows collectors
- explainable rules loaded from config instead of black-box scoring
- dual persistence to SQLite and JSONL
- reproducible analysis outputs and HTML reporting
- evidence integrity through event hash chaining

## Current Capabilities

### Linux

- Process snapshot collection from `/proc`
- Process metadata including `pid`, `ppid`, `exe`, `cmdline`, `cwd`, start time, user, deleted paths, mapped modules, and suspicious flags
- Host baseline collection for identity, accounts, routes, DNS, mounts, firewall summaries, and login traces
- Network evidence collection through socket enumeration
- Persistence inspection for common `systemd`, `cron`, autostart, and startup paths
- High-risk file collection and hashing
- File monitoring through native filesystem notifications
- Near-real-time process and network monitoring through snapshot diffing
- Native eBPF realtime collection for `execve`, `connect`, `openat`, `renameat`, and related kernel events

### Windows

- Process snapshot collection
- Network snapshot collection
- Persistence inspection for `Run`, `RunOnce`, Startup folders, and scheduled tasks
- File monitoring through native filesystem notifications
- Near-real-time process and network monitoring through polling

## Investigation Outputs

TrailGuard produces an evidence package and an analysis/report set.

Typical output layout:

```text
artifacts/
  evidence.db
  events.jsonl
  collected_files/
    log_*.txt
    auth_*.txt
    meta_*.json

report/
  analysis.json
  timeline.jsonl
  timeline.md
  chains.mmd
  index.html
```

Key output formats:

- `SQLite` for structured querying and correlation
- `JSONL` for normalized raw event retention
- `HTML` for human-readable investigation reports
- `Mermaid` for quick chain visualization

## HTML Report

The HTML report is designed for review and handoff. It separates observed facts from inferred conclusions and links suspicious findings back to raw evidence references.

Current report coverage includes:

- event overview and case summary
- key risk objects
- timeline reconstruction
- IOC summary
- evidence-to-judgment mapping
- file, network, and persistence appendices
- suspicious process details including command line and working directory context where available

## Architecture

High-level workspace layout:

```text
/crates
  /common-model
  /storage-sqlite
  /rule-engine
  /correlator
  /reporter-html
  /collector-linux-proc
  /collector-linux-ebpf
  /collector-windows
  /cli
/config
/docs
/examples
/tests
```

Detailed architecture notes:

- [docs/architecture.md](docs/architecture.md)
- [docs/evidence-model.md](docs/evidence-model.md)
- [docs/deployment-package.md](docs/deployment-package.md)
- [docs/roadmap.md](docs/roadmap.md)

## Quick Start

Default config files:

- `config/default.toml`
- `config/rules.toml`
- `config/rules-miner.toml`

Basic workflow:

```bash
trailguard snapshot --output ./artifacts
trailguard analyze --input ./artifacts --report ./report
trailguard report --db ./artifacts/evidence.db --html ./report/index.html
```

Realtime monitoring example:

```bash
trailguard monitor --duration 300 --output ./artifacts
```

Miner-focused rules:

```bash
trailguard analyze --input ./artifacts --report ./report --rules ./config/rules-miner.toml
```

## Build

### Windows

```powershell
cargo build --release -p trailguard
```

### Linux

```bash
cargo build --release -p trailguard
```

Static musl build:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release -p trailguard --target x86_64-unknown-linux-musl
```

Linux eBPF object build requirements:

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo +nightly check --manifest-path crates/collector-linux-ebpf/ebpf/Cargo.toml --target bpfel-unknown-none -Z build-std=core
```

## Linux Deployment Bundle

TrailGuard includes a packaging script for producing a self-contained Linux deployment bundle:

```bash
./scripts/package-linux-bundle.sh
```

The generated bundle includes:

- `trailguard`
- helper wrapper commands such as `trailguard-snapshot` and `trailguard-report`
- default configs and rules
- install and uninstall scripts
- checksum sidecars for offline transfer

See [docs/deployment-package.md](docs/deployment-package.md) for packaging and deployment details.

## Evidence Integrity

All normalized events are hash chained before persistence:

- `prev_event_hash`
- `event_hash`

This helps preserve an auditable chain between raw event retention, structured storage, and rendered reporting.

## Operational Boundaries

- TrailGuard is a best-effort host evidence reconstruction tool, not a guarantee of full historical visibility.
- Snapshot-only evidence cannot recover activity that completed before collection if no supporting logs remain.
- Linux realtime collection is stronger when eBPF is available.
- Windows realtime collection currently relies on polling rather than ETW-native capture.
- Some enrichments such as signer data and reverse DNS are still incomplete.

## Testing

Run the test suite with:

```bash
cargo test
```

Selected coverage areas include:

- shared model serialization
- event hash chaining
- SQLite schema and persistence
- rule engine behavior
- process tree construction
- HTML report generation

## Safety Notice

TrailGuard is intended for defensive and authorized use only. Operators should ensure they have permission to collect host evidence and move resulting artifacts outside the target environment.

## License

MIT
