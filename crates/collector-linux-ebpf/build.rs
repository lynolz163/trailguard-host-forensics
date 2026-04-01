use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const REPO_PREBUILT_REL: &str = "prebuilt/linux/trailguard-ebpf.bpfel";

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR missing"));
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR missing"));
    let generated = out_dir.join("embedded_ebpf.rs");
    let repo_prebuilt = manifest_dir.join(REPO_PREBUILT_REL);

    println!("cargo:rerun-if-env-changed=PATH");
    println!("cargo:rerun-if-env-changed=TRAILGUARD_DISABLE_EMBEDDED_EBPF");
    println!("cargo:rerun-if-env-changed=TRAILGUARD_SKIP_EBPF_BUILD");
    println!("cargo:rerun-if-env-changed=TRAILGUARD_EBPF_OBJECT_PATH");
    println!("cargo:rerun-if-changed=ebpf/Cargo.toml");
    println!("cargo:rerun-if-changed=ebpf/.cargo/config.toml");
    println!("cargo:rerun-if-changed=ebpf/src/main.rs");
    println!("cargo:rerun-if-changed=../linux-ebpf-shared/src/lib.rs");
    println!("cargo:rerun-if-changed={}", repo_prebuilt.display());

    if env::var("CARGO_CFG_TARGET_OS").ok().as_deref() != Some("linux") {
        write_stub(
            &generated,
            "embedded eBPF build is disabled on non-Linux targets",
        );
        return;
    }

    if env::var("TRAILGUARD_DISABLE_EMBEDDED_EBPF").ok().as_deref() == Some("1") {
        write_stub(
            &generated,
            "embedded eBPF object was explicitly disabled (TRAILGUARD_DISABLE_EMBEDDED_EBPF=1)",
        );
        return;
    }

    if let Ok(path) = env::var("TRAILGUARD_EBPF_OBJECT_PATH") {
        write_include(
            &generated,
            Path::new(&path),
            "using TRAILGUARD_EBPF_OBJECT_PATH",
        );
        return;
    }

    if env::var("TRAILGUARD_SKIP_EBPF_BUILD").ok().as_deref() == Some("1") {
        if try_use_repo_prebuilt(
            &generated,
            &repo_prebuilt,
            "using repo prebuilt eBPF object (TRAILGUARD_SKIP_EBPF_BUILD=1)",
        ) {
            return;
        }
        write_stub(
            &generated,
            "TRAILGUARD_SKIP_EBPF_BUILD=1 and no repo prebuilt eBPF object is available",
        );
        return;
    }

    let host_is_linux = env::var("HOST")
        .unwrap_or_default()
        .to_lowercase()
        .contains("linux");
    let dependency_status = if host_is_linux {
        check_build_dependencies()
    } else {
        Err("embedded eBPF auto-build requires a Linux build host".to_string())
    };

    match dependency_status {
        Ok(()) => match build_ebpf(&manifest_dir, &out_dir) {
            Ok(path) => write_include(&generated, &path, "embedded eBPF object built successfully"),
            Err(error) => {
                if !try_use_repo_prebuilt(
                    &generated,
                    &repo_prebuilt,
                    &format!("using repo prebuilt eBPF object after local build failed: {error}"),
                ) {
                    write_stub(
                        &generated,
                        &format!(
                            "embedded eBPF object build failed: {error}; install nightly + rust-src + bpf-linker or set TRAILGUARD_EBPF_OBJECT_PATH"
                        ),
                    );
                }
            }
        },
        Err(reason) => {
            if !try_use_repo_prebuilt(
                &generated,
                &repo_prebuilt,
                &format!(
                    "using repo prebuilt eBPF object because local build requirements are unavailable: {reason}"
                ),
            ) {
                write_stub(
                    &generated,
                    &format!(
                        "{reason}; install nightly + rust-src + bpf-linker or set TRAILGUARD_EBPF_OBJECT_PATH"
                    ),
                );
            }
        }
    }
}

fn check_build_dependencies() -> Result<(), String> {
    command_success(
        "cargo",
        ["+nightly", "--version"],
        "nightly cargo toolchain is unavailable",
    )?;

    let sysroot = command_output("rustc", ["+nightly", "--print", "sysroot"])
        .map_err(|error| format!("nightly rustc toolchain is unavailable: {error}"))?;
    let rust_src = Path::new(sysroot.trim()).join("lib/rustlib/src/rust/library/Cargo.lock");
    if !rust_src.exists() {
        return Err("nightly rust-src component is missing".to_string());
    }

    command_success(
        "bpf-linker",
        ["--version"],
        "bpf-linker is not available in PATH",
    )?;
    Ok(())
}

fn command_success<const N: usize>(
    program: &str,
    args: [&str; N],
    failure_message: &str,
) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("{failure_message}: {error}"))?;
    if !output.status.success() {
        return Err(format!("{failure_message}: exited with {}", output.status));
    }
    Ok(())
}

fn command_output<const N: usize>(program: &str, args: [&str; N]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("failed to invoke {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!("{program} exited with {}", output.status));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| format!("invalid UTF-8 from {program}: {error}"))
}

fn try_use_repo_prebuilt(generated: &Path, repo_prebuilt: &Path, message: &str) -> bool {
    if repo_prebuilt.is_file() {
        write_include(generated, repo_prebuilt, message);
        return true;
    }
    false
}

fn build_ebpf(manifest_dir: &Path, out_dir: &Path) -> Result<PathBuf, String> {
    let ebpf_manifest = manifest_dir.join("ebpf").join("Cargo.toml");
    let target_dir = out_dir.join("ebpf-target");
    let status = Command::new("cargo")
        .arg("+nightly")
        .arg("build")
        .arg("--release")
        .arg("--manifest-path")
        .arg(&ebpf_manifest)
        .arg("--target")
        .arg("bpfel-unknown-none")
        .arg("-Z")
        .arg("build-std=core")
        .arg("--target-dir")
        .arg(&target_dir)
        .status()
        .map_err(|error| format!("unable to invoke cargo +nightly: {error}"))?;

    if !status.success() {
        return Err(format!("cargo +nightly build returned status {status}"));
    }

    let built = target_dir.join("bpfel-unknown-none").join("release").join(
        if cfg!(target_os = "windows") {
            "trailguard-ebpf.exe"
        } else {
            "trailguard-ebpf"
        },
    );
    if !built.exists() {
        return Err(format!(
            "built eBPF object not found at {}",
            built.display()
        ));
    }

    let embedded = out_dir.join("trailguard-ebpf");
    fs::copy(&built, &embedded)
        .map_err(|error| format!("failed to copy {}: {error}", built.display()))?;
    Ok(embedded)
}

fn write_include(path: &Path, ebpf_object: &Path, message: &str) {
    let content = format!(
        r##"pub const HAS_EMBEDDED_EBPF: bool = true;
pub const BUILD_MESSAGE: &str = {message:?};
pub const EMBEDDED_EBPF: &[u8] = aya::include_bytes_aligned!(r#"{object}"#);
"##,
        object = ebpf_object.display(),
    );
    fs::write(path, content).expect("failed to write embedded_ebpf.rs");
}

fn write_stub(path: &Path, message: &str) {
    let content = format!(
        r#"pub const HAS_EMBEDDED_EBPF: bool = false;
pub const BUILD_MESSAGE: &str = {message:?};
pub const EMBEDDED_EBPF: &[u8] = &[];
"#
    );
    fs::write(path, content).expect("failed to write stub embedded_ebpf.rs");
}
