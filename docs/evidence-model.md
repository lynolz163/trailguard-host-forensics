# Evidence Model

## ProcessIdentity

`ProcessIdentity` 是贯穿快照、实时、分析、报告的统一进程实体。

- `entity_key`：稳定键，避免 PID 复用歧义
- `pid` / `ppid`
- `start_time`
- `exe` / `cmdline` / `cwd`
- `user`
- `hash_sha256`
- `signer`（Windows 预留）
- `fd_count`
- `mapped_modules`
- `deleted_paths`
- `suspicious_flags`
- `first_seen` / `last_seen`
- `is_running`

Linux 侧稳定键使用 `platform + pid + start_time`。

## Event

统一事件记录：

- `event_id`
- `ts_wall`
- `ts_mono`
- `source`
- `event_type`
- `entity_key`
- `parent_entity_key`
- `severity`
- `fields`
- `raw_ref`
- `prev_event_hash`
- `event_hash`

### 完整性设计

事件在写入时自动形成哈希链：

1. `raw_ref` 指向 JSONL 行引用
2. `prev_event_hash` 继承上一条事件
3. `event_hash` 对规范化事件内容做 SHA-256

这样可用于发现篡改或中间插删。

## NetConnection

- `entity_key`
- `protocol`
- `local_addr`
- `remote_addr`
- `dns_name`
- `direction`
- `state`
- `net_namespace`
- `observation_source`
- `socket_inode`
- `ts`

这允许把主机侧监听、容器 netns、eBPF connect、/proc socket tuple 补全结果串起来。

## FileArtifact

`FileArtifact` 既表示快照中的文件证据，也表示实时文件事件产生的文件对象。

- `entity_key`
- `category`
- `path`
- `file_id`
- `op`
- `sha256`
- `size`
- `owner`
- `group`
- `mode`
- `mtime`
- `ctime`
- `atime`
- `is_hidden`
- `is_suid`
- `is_sgid`
- `is_executable`
- `is_elf`
- `content_ref`
- `notes`
- `ts`

常见 `category`：

- `process_executable`
- `deleted_mapping`
- `auth_file`
- `log_file`
- `app_log_file`
- `risk_scan`
- `command_log`
- `persistence`
- `watch_path`
- `ebpf_file`

`content_ref` 指向证据包中的原始文件副本、切片或脱敏元数据文件。

## PersistenceArtifact

- `entity_key`
- `mechanism`
- `location`
- `value`
- `ts`

常见机制：

- `systemd`
- `cron`
- `autostart`
- `run_key`
- `startup_folder`
- `scheduled_task`
- `persistence_file`

## HostInfo

`HostInfo` 保存主机基线。

- 主机身份：`host_id`、`hostname`、`platform`、`collector`
- 时间：`collected_at`、`boot_time`、`timezone`
- 系统版本：`kernel_version`、`os_version`
- 环境：`environment_summary`
- 当前用户：`current_user`
- 网络：`interfaces`、`routes`、`dns`、`hosts_entries`、`neighbors`
- 存储：`mounts`、`disks`
- 防火墙：`firewall_rules`
- 登录痕迹：`current_online_users`、`recent_logins`、`failed_logins`
- 账户：`user_accounts`、`groups`

## RuleMatch

每条规则命中都必须可解释：

- `rule_id`
- `entity_key`
- `severity`
- `why_matched`
- `evidence_refs`
- `facts`

`evidence_refs` 可以指向：

- 原始事件 ID
- 文件路径
- 持久化位置
- 网络端点
- 其他证据对象

## AnalysisBundle

`AnalysisBundle` 是分析阶段的稳定输出：

- `host_overview`
- `suspicious_processes`
- `top_chains`
- `timeline`
- `process_tree`
- `rule_matches`
- `dataset`

报告层只消费这个结构，从而保证 `analyze` 与 `report` 结果可重复。

## Timeline 输出

分析阶段额外落地：

- `timeline.jsonl`
- `timeline.md`

统一字段：

- `timestamp`
- `source`
- `category`
- `subject`
- `detail`
- `severity`

时间线来源当前包括：

- 原始事件流
- 文件 `mtime/ctime`
- 登录 / 失败登录记录
- 持久化对象
- 规则推断项
