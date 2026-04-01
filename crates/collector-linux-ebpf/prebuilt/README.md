This directory stores a repo-local fallback eBPF object for `collector-linux-ebpf`.

- Default fallback path: `prebuilt/linux/trailguard-ebpf.bpfel`
- `build.rs` uses it automatically when:
  - the build host is not Linux
  - nightly `rust-src` is unavailable
  - `bpf-linker` is unavailable
  - local eBPF compilation fails
  - `TRAILGUARD_SKIP_EBPF_BUILD=1` is set

Refresh the fallback object on a Linux build host with:

```bash
source ~/.cargo/env
rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu
cargo install bpf-linker --locked
cd crates/collector-linux-ebpf/ebpf
cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core
cp target/bpfel-unknown-none/release/trailguard-ebpf \
  ../prebuilt/linux/trailguard-ebpf.bpfel
```
