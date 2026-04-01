# Platform Test Strategy

Current automated coverage lives inside the Rust crates and runs with `cargo test`.

## Covered now

- unified model serde round-trip
- event hash chain
- SQLite schema read/write
- rule engine unit logic
- process tree construction
- HTML report rendering

## Fixture strategy for platform-specific evolution

When Linux or Windows specific collectors gain deeper functionality, keep tests deterministic with:

1. **serialized snapshot fixtures**
   - store captured `SnapshotBundle` JSON under `tests/fixtures/`
   - feed the correlator and rule engine without touching the live host

2. **collector parser fixtures**
   - Linux: sample `/proc/<pid>/stat`, `status`, `cmdline`, `systemd` unit files
   - Windows: sample `Run` registry exports, Startup folder entries, Scheduled Task XML

3. **event stream fixtures**
   - store normalized JSONL samples
   - validate hash-chain continuity and report output determinism

4. **mock filesystem notifications**
   - build synthetic `notify::Event` values and assert emitted `FileArtifact` / `Event`

This keeps platform tests runnable even when the local environment cannot reproduce the target operating system behavior directly.

## Linux host fixture

`collector-linux-proc` now ships a live Linux snapshot fixture:

- test file: `crates/collector-linux-proc/tests/linux_snapshot_fixture.rs`
- validates:
  - live `/proc` snapshot succeeds
  - host baseline is populated
  - current process identity enrichment works
  - configured command-log pseudo artifacts are emitted when `journalctl` / `dmesg` exist

Run it on a Linux host with:

```bash
cargo test -p collector-linux-proc --test linux_snapshot_fixture --target x86_64-unknown-linux-gnu
```

`collector-linux-ebpf` now also ships an ignored Linux-only integration fixture:

- test file: `crates/collector-linux-ebpf/tests/linux_host_fixture.rs`
- helper binary: `crates/collector-linux-ebpf/src/bin/trailguard-linux-fixture.rs`

The fixture exercises:

- native eBPF `NetConnect` capture
- local socket tuple enrichment via `/proc/<pid>/fd/<fd>` -> socket inode resolution
- native `PrivilegeChange` capture via successful `setresgid` and `setresuid`

`trailguard` CLI unit tests now also cover:

- `journalctl` command capture argument selection with `--since`
- command-log sidecar metadata rendering
- time-window filtering for text log excerpts
- command-log sidecar promotion into the analysis timeline

Run it on a Linux build host with root privileges and an available eBPF object:

```bash
cargo test -p collector-linux-ebpf --test linux_host_fixture -- --ignored --nocapture
```
