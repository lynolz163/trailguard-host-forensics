# TrailGuard

TrailGuard 是一个本地主机侧、防御型、授权排查型异常进程发现与取证工具。  
它强调 **快照采集 + 实时事件 + 关联分析 + 时间线 + 结构化证据包**，输出可复核的证据链，而不是只给一个“告警”。

> 本项目只做本机采集、检测、关联、取证、报告，不包含攻击、利用、横向移动、绕过检测、持久化投放、提权利用、远控或数据窃取能力。

## 项目定位

- 发现异常进程、异常执行链、异常文件落地、异常网络连接、异常持久化行为
- 输出 JSONL、SQLite、HTML、Mermaid 等可归档证据包
- 支撑入侵排查、溯源分析、复核与二次分析
- 第一阶段统一 Linux / Windows 数据模型与报告结构

## 当前能力

### Linux

- `/proc` 快照采集
  - 进程列表、父子关系、可执行路径、命令行、工作目录、启动时间、运行用户
  - 打开的 fd 数量
  - 映射的可执行模块
  - 已删除但仍被进程占用的文件
  - 进程基础可疑标记
- 系统基础信息采集
  - 主机名、内核版本、OS 版本、启动时间、采集时间、时区
  - 网卡、挂载、磁盘使用、路由、DNS、hosts、ARP/邻居表
  - 防火墙基础规则摘要（`nft` / `iptables`）
  - 当前用户、当前在线用户、最近登录、失败登录
  - `/etc/passwd`、`/etc/group`、`/etc/shadow` 状态摘要
- 网络证据
  - TCP/UDP 监听和连接
  - 本地/远端地址、状态、PID/进程归因
  - netns / socket inode / tuple source
- 持久化检查
  - `systemd service/timer`
  - `cron`
  - `rc.local`
  - `init.d`
  - `ld.so.preload`
  - shell 启动脚本
- 高风险文件采集
  - `/tmp`、`/var/tmp`、`/dev/shm`、`/etc`、`/usr/local/bin`、`/usr/bin`、`/root`、`/home`
  - Web 根目录可疑脚本
  - 文件大小、权限、属主、mtime/ctime/atime、SHA-256、ELF、SUID/SGID、隐藏文件标记
- 日志与认证文件留存
  - 常见系统日志路径元数据采集
  - 日志切片落盘到证据包
  - 敏感认证文件支持脱敏开关，默认不直接复制高敏感内容
- Linux 原生实时链路
  - eBPF `execve/execveat`
  - `sched_process_exec/sched_process_exit`
  - `connect`
  - `openat/openat2`
  - `renameat/renameat2`
  - `setuid/setgid/setresuid/setresgid/capset`
  - exec credential commit 溯源补强

### Windows

- 进程、路径、命令行、网络连接快照
- `Run/RunOnce`、Startup、Tasks 基础持久化快照
- 轮询式实时进程/网络差分
- 文件监控

## 可疑判定基础版

- 可执行文件位于 `/tmp`、`/var/tmp`、`/dev/shm` 等高风险目录
- 进程名伪装为常见系统进程名
- 已删除文件仍被进程占用
- `cwd` / `exe` 指向异常目录
- 命令行含矿池、钱包、下载执行等特征
- 关联异常网络连接
- 重复失败登录、远程高权限登录
- 隐藏可执行文件、风险目录下 SUID/SGID、最近修改的 web 脚本
- 最近修改的 `authorized_keys` / `sudoers` / `ld.so.preload` 等高敏感认证或启动材料
- 矿工样特征规则包
  - 常见矿池端口
  - `stratum` / `xmrig` / `minerd` / `wallet` / `randomx` 等关键字

## 输出内容

典型输出目录：

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

### HTML 报告章节

- 主机概览
- 执行摘要
- 网络证据
- 文件证据
- 持久化证据
- 规则命中说明
- 异常链详情
- 时间线
- IOC 清单
- 原始证据附录

## 构建

### Windows

```powershell
cargo build --release -p trailguard
```

### Linux

普通构建：

```bash
cargo build --release -p trailguard
```

`musl` 静态构建：

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release -p trailguard --target x86_64-unknown-linux-musl
```

Linux eBPF 内嵌对象构建建议在 Linux 主机完成：

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo +nightly check --manifest-path crates/collector-linux-ebpf/ebpf/Cargo.toml --target bpfel-unknown-none -Z build-std=core
```

## 运行

默认配置：

- `config/default.toml`
- `config/rules.toml`
- `config/rules-miner.toml`

### 快照

```bash
trailguard snapshot --output ./artifacts
```

### 监控

```bash
trailguard monitor --duration 300 --output ./artifacts
```

### 分析

```bash
trailguard analyze --input ./artifacts --report ./report
```

### 报告

```bash
trailguard report --db ./artifacts/evidence.db --html ./report/index.html
```

### 挖矿专项规则包

```bash
trailguard analyze --input ./artifacts --report ./report --rules ./config/rules-miner.toml
```

## 运行建议

- 快照时长通常取决于进程数、网络连接数、扫描目录规模和日志量
- 常规 Linux 主机静态快照通常在数秒到几十秒级
- 如果启用了大范围高风险目录扫描，耗时会明显增加
- 建议最少执行：

```bash
trailguard snapshot --output ./artifacts
trailguard analyze --input ./artifacts --report ./report
trailguard report --db ./artifacts/evidence.db --html ./report/index.html
```

## 已知边界

- 对“程序启动前已发生且系统无日志保留”的行为，无法保证完整恢复
- 证据链是“最大化恢复”，不是绝对全知
- Linux 快照网络归因仍以用户态枚举为主，eBPF 负责增强实时链路
- Windows 当前实时链路仍是轮询式，不是 ETW 原生实现
- signer、离线 DNS 反查等能力仍待增强

## 测试

当前已覆盖：

- 统一模型序列化/反序列化
- 事件哈希链测试
- SQLite schema 读写
- 规则引擎单元测试
- 进程树构建测试
- HTML 报告生成测试

运行：

```bash
cargo test
```

## 文档

- `docs/architecture.md`
- `docs/evidence-model.md`
- `docs/roadmap.md`

## Latest Linux additions

- Added `collection.log_time_window_hours` for command-backed log capture windows.
- Added `collection.linux.command_log_collectors = ["journalctl", "dmesg"]`.
- `snapshot` now stages command output sidecars under `artifacts/collected_files/` when those commands exist.
- Captured `journalctl` / `dmesg` lines are now promoted into analysis timeline output and HTML report timeline.
- Added Linux `/proc` host fixture:

```bash
cargo test -p collector-linux-proc --test linux_snapshot_fixture --target x86_64-unknown-linux-gnu
```
