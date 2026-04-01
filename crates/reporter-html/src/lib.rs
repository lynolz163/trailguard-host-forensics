use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::Result;
use chrono::{Duration, Utc};
use common_model::{
    AnalysisBundle, CorrelatedChain, EventType, HostInfo, LoginRecord, ProcessIdentity, Severity,
};
use html_escape::encode_text;
use serde_json::Value;

/// Simple static HTML reporter with Mermaid graph output.
pub struct HtmlReporter {
    max_raw_events: usize,
}

struct ConclusionView {
    severity: Severity,
    attack_established: bool,
    confidence: u32,
    summary: String,
    reasons: Vec<String>,
}

struct ContainerView {
    entity: String,
    runtime: String,
    container_id: String,
    image: String,
    namespaces: String,
    endpoints: String,
    refs: String,
}

struct SampleView {
    entity: String,
    display: String,
    path: String,
    sha256: String,
    cmdline: String,
    content_ref: String,
    yara: String,
    strings: String,
    notes: String,
}

struct ExclusionView {
    category: String,
    subject: String,
    rationale: String,
    refs: String,
}

struct EvidenceMapView {
    event_id: String,
    event_type: String,
    entity: String,
    ts: String,
    raw_ref: String,
    source_ref: String,
    content_ref: String,
    note: String,
}

struct TimelineFocusView {
    ts: chrono::DateTime<Utc>,
    source: String,
    category: String,
    subject: String,
    detail: String,
    severity: Severity,
    nature: &'static str,
    refs: Vec<String>,
}

struct EventOverviewView {
    nature: String,
    primary_objects: String,
    current_status: String,
    impact_scope: String,
    disposition: String,
    evidence_strength: String,
    summary: String,
}

struct RiskObjectView {
    name: String,
    fingerprint: String,
    severity: Severity,
    risk_score: u32,
    running: bool,
    primary_path: String,
    sha256: String,
    users: Vec<String>,
    first_seen: String,
    last_seen: String,
    instances: Vec<String>,
    cmdlines: Vec<String>,
    process_chains: Vec<String>,
    remote_endpoints: Vec<String>,
    persistence_locations: Vec<String>,
    rule_ids: Vec<String>,
    evidence_refs: Vec<String>,
    content_refs: Vec<String>,
    container_context: Vec<String>,
    facts: Vec<String>,
    inferences: Vec<String>,
    pending_checks: Vec<String>,
    impact: String,
}

struct IocView {
    kind: String,
    value: String,
    object: String,
    note: String,
    refs: String,
}

struct JudgmentView {
    title: String,
    level: &'static str,
    statement: String,
    support: Vec<String>,
    status: &'static str,
}

struct ActionView {
    phase: &'static str,
    target: String,
    action: String,
    rationale: String,
    refs: Vec<String>,
}

impl HtmlReporter {
    pub fn new(max_raw_events: usize) -> Self {
        Self { max_raw_events }
    }

    pub fn render_html(&self, analysis: &AnalysisBundle) -> Result<String> {
        let process_map = analysis
            .dataset
            .processes
            .iter()
            .map(|process| (process.entity_key.clone(), process))
            .collect::<HashMap<_, _>>();
        let mermaid = self.render_mermaid(analysis);
        let conclusion = build_conclusion_view(analysis);
        let exclusions = build_exclusion_views(analysis);
        let containers = build_container_views(analysis, &process_map);
        let samples = build_sample_views(analysis, &process_map);
        let evidence_map = build_evidence_map_views(analysis);
        let timeline_focus = build_timeline_focus_views(analysis);
        let risk_objects = build_risk_object_views(analysis, &process_map, &samples, &containers);
        let overview = build_event_overview_view(analysis, &conclusion, &risk_objects);
        let iocs = build_ioc_views(&risk_objects);
        let judgments = build_judgment_views(&conclusion, &risk_objects);
        let actions = build_action_views(&risk_objects);

        let mut html = String::new();
        html.push_str(
            r#"<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>TrailGuard 安全取证调查报告</title>
<script type="module">
import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
mermaid.initialize({ startOnLoad: true, securityLevel: 'loose' });
</script>
<style>
body{font-family:Arial,"PingFang SC","Microsoft YaHei",sans-serif;background:#0b1020;color:#e9eef7;margin:0;line-height:1.7}
main{max-width:1320px;margin:0 auto;padding:28px 24px 72px}
h1,h2,h3{color:#f5f7fb;margin:0 0 12px}
p{margin:8px 0 0}
section,article,details{background:#131a2d;border:1px solid #26314e;border-radius:16px;padding:20px;margin:18px 0}
.hero{background:linear-gradient(135deg,#17213a,#0f1729);padding:24px}
.hero-grid,.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
.metric-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}
.card,.metric{background:#18213a;border:1px solid #2b3658;border-radius:14px;padding:14px}
.metric strong{display:block;font-size:20px;margin-top:6px}
.muted{color:#9eb0d4;font-size:12px}
.section-lead{margin-top:0;color:#c5d4f3}
.badge{display:inline-block;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:700;border:1px solid transparent;margin:0 8px 8px 0}
.critical{background:rgba(255,114,114,.16);color:#ffb4b4}.high{background:rgba(255,184,108,.16);color:#ffd9ae}.medium{background:rgba(245,230,99,.14);color:#fff5ad}.low{background:rgba(134,239,172,.14);color:#c8ffd9}
.status-pos{background:rgba(248,113,113,.14);color:#ffd4d4}.status-neu{background:rgba(96,165,250,.14);color:#dbeafe}.status-fact{background:rgba(96,165,250,.16);color:#dbeafe}.status-review{background:rgba(253,224,71,.14);color:#fff4b3}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:10px;border-bottom:1px solid #223150;vertical-align:top;word-break:break-word}
th{color:#dbe4fb}
code,pre{background:#08101f;border:1px solid #1f2b45;border-radius:8px}
code{padding:2px 6px;white-space:pre-wrap}
pre{padding:12px;white-space:pre-wrap;overflow-x:auto}
.facts{border-left:4px solid #60a5fa;padding-left:12px;margin:12px 0}
.empty{color:#9eb0d4;background:#18213a;border:1px dashed #33466b;border-radius:12px;padding:14px}
.list-tight{margin:8px 0 0;padding-left:20px}
.list-tight li{margin:4px 0}
.object-grid{display:grid;grid-template-columns:1.2fr .8fr;gap:16px}
.stack{display:flex;flex-wrap:wrap;gap:8px}
.pill{display:inline-flex;align-items:center;padding:4px 8px;border-radius:999px;background:#10182a;border:1px solid #2b3658;color:#dbe4fb;font-size:12px}
.evidence-list code{display:inline-block;margin:0 6px 6px 0}
.mermaid{overflow-x:auto;padding-top:8px}
details > summary{cursor:pointer;font-weight:700}
.appendix details{background:#10182a}
@media (max-width:1100px){.hero-grid,.grid,.metric-grid,.object-grid{grid-template-columns:1fr}}
</style></head><body><main>"#,
        );
        html.push_str(r#"<h1>TrailGuard 安全取证调查报告</h1>"#);
        html.push_str(r#"<p class="muted">本页按“先结论、后对象、再回证据”的顺序组织。所有原始事件、UUID、路径、哈希、IOC 与规则编号均在后续映射或附录中完整保留。</p>"#);
        html.push_str(&render_event_overview_section(&overview, &conclusion));
        html.push_str(&render_conclusion_section(&conclusion));
        html.push_str(&render_risk_objects_section(&risk_objects));
        html.push_str(&render_key_timeline_section(&timeline_focus));
        html.push_str(&render_ioc_section(&iocs));
        html.push_str(&render_judgment_mapping_section(&judgments, &evidence_map));
        html.push_str(&render_actions_section(&actions));
        html.push_str(r#"<section><h2>辅助图谱</h2><p class="section-lead">用于快速理解对象、落地文件、外联与持久化线索之间的关系，不作为唯一结论依据。</p><div class="mermaid">"#);
        html.push_str(&encode_text(&mermaid));
        html.push_str("</div></section>");
        html.push_str(r#"<div class="appendix">"#);
        html.push_str(&render_appendix_section(
            analysis,
            analysis.dataset.host.as_ref(),
            &exclusions,
            &containers,
            &samples,
            self.max_raw_events,
        )?);
        html.push_str("</div>");
        html.push_str("</main></body></html>");
        Ok(html)
    }

    pub fn render_mermaid(&self, analysis: &AnalysisBundle) -> String {
        let mut graph = String::from("flowchart TD\n");
        for chain in &analysis.top_chains {
            graph.push_str(&format!(
                "subgraph {}[\"{}\"]\n",
                sanitize_id(&chain.chain_id),
                chain.title.replace('"', "'"),
            ));
            for process_key in &chain.process_keys {
                graph.push_str(&format!(
                    "  {}[\"{}\"]\n",
                    sanitize_id(process_key),
                    process_key.replace('"', "'"),
                ));
            }
            for pair in chain.process_keys.windows(2) {
                graph.push_str(&format!(
                    "  {} --> {}\n",
                    sanitize_id(&pair[0]),
                    sanitize_id(&pair[1]),
                ));
            }
            for path in &chain.file_paths {
                graph.push_str(&format!(
                    "  {} --> {}[\"{}\"]\n",
                    sanitize_id(&chain.process_keys.last().cloned().unwrap_or_default()),
                    sanitize_id(path),
                    path.replace('"', "'"),
                ));
            }
            for remote in &chain.remote_endpoints {
                graph.push_str(&format!(
                    "  {} --> {}((\"{}\"))\n",
                    sanitize_id(&chain.process_keys.last().cloned().unwrap_or_default()),
                    sanitize_id(remote),
                    remote.replace('"', "'"),
                ));
            }
            for location in &chain.persistence_locations {
                graph.push_str(&format!(
                    "  {} --> {}{{\"{}\"}}\n",
                    sanitize_id(&chain.process_keys.last().cloned().unwrap_or_default()),
                    sanitize_id(location),
                    location.replace('"', "'"),
                ));
            }
            graph.push_str("end\n");
        }
        graph
    }

    fn render_chain(
        &self,
        chain: &CorrelatedChain,
        analysis: &AnalysisBundle,
        process_map: &HashMap<String, &ProcessIdentity>,
    ) -> String {
        let refs = chain
            .event_refs
            .iter()
            .map(|reference| {
                if analysis
                    .dataset
                    .events
                    .iter()
                    .any(|event| event.event_id == *reference)
                {
                    format!(
                        "<a href=\"#event-{}\">{}</a>",
                        encode_text(reference),
                        encode_text(reference)
                    )
                } else {
                    format!("<code>{}</code>", encode_text(reference))
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        let terminal = chain
            .process_keys
            .last()
            .and_then(|key| process_map.get(key).copied());
        let cmdline = terminal
            .map(cmdline_text)
            .unwrap_or_else(|| "-".to_string());
        let cwd = terminal.map(cwd_text).unwrap_or_else(|| "-".to_string());

        format!(
            "<article><h3>{}</h3><p class=\"{}\">风险分：{}，严重级别：{}</p><p>{}</p><p><strong>进程链：</strong> {}</p><p><strong>文件：</strong> {}</p><p><strong>网络：</strong> {}</p><p><strong>持久化：</strong> {}</p><p><strong>规则：</strong> {}</p><p><strong>终点命令行：</strong> <code>{}</code></p><p><strong>引用：</strong> {}</p></article>",
            encode_text(&chain.title),
            severity_class(chain.severity),
            chain.risk_score,
            chain.severity,
            encode_text(&chain.summary),
            encode_text(&chain.process_keys.join(" -> ")),
            encode_text(&chain.file_paths.join(", ")),
            encode_text(&chain.remote_endpoints.join(", ")),
            encode_text(&chain.persistence_locations.join(", ")),
            encode_text(&chain.rule_ids.join(", ")),
            encode_text(&cmdline),
            refs,
        )
        .replacen(
            "</code></p><p><strong>",
            &format!(
                "</code></p><p><strong>终点工作目录：</strong> <code>{}</code></p><p><strong>",
                encode_text(&cwd)
            ),
            1,
        )
    }
}

fn severity_class(severity: common_model::Severity) -> &'static str {
    match severity {
        common_model::Severity::Critical => "critical",
        common_model::Severity::High => "high",
        common_model::Severity::Medium => "medium",
        common_model::Severity::Low => "low",
        common_model::Severity::Info => "low",
    }
}

fn severity_label(severity: common_model::Severity) -> &'static str {
    match severity {
        common_model::Severity::Critical => "严重",
        common_model::Severity::High => "高",
        common_model::Severity::Medium => "中",
        common_model::Severity::Low => "低",
        common_model::Severity::Info => "提示",
    }
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

fn kv(label: &str, value: &str) -> String {
    format!(
        "<div class=\"card\"><span class=\"muted\">{}</span><br><strong>{}</strong></div>",
        encode_text(label),
        encode_text(value)
    )
}

fn format_ts(ts: chrono::DateTime<Utc>) -> String {
    ts.to_rfc3339()
}

fn cmdline_text(process: &ProcessIdentity) -> String {
    if process.cmdline.is_empty() {
        process.exe.clone().unwrap_or_else(|| "-".to_string())
    } else {
        process.cmdline.join(" ")
    }
}

fn cwd_text(process: &ProcessIdentity) -> String {
    process.cwd.clone().unwrap_or_else(|| "-".to_string())
}

fn join_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(", ")
    }
}

fn unique_join(values: Vec<String>) -> String {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for value in values {
        if !value.is_empty() && seen.insert(value.clone()) {
            out.push(value);
        }
    }
    if out.is_empty() {
        "-".to_string()
    } else {
        out.join(", ")
    }
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn event_type_label(event_type: EventType) -> &'static str {
    match event_type {
        EventType::ProcessSnapshot => "ProcessSnapshot",
        EventType::ProcessStart => "ProcessStart",
        EventType::ProcessExit => "ProcessExit",
        EventType::NetConnect => "NetConnect",
        EventType::FileObserved => "FileObserved",
        EventType::FileCreate => "FileCreate",
        EventType::FileWrite => "FileWrite",
        EventType::Rename => "Rename",
        EventType::PersistenceObserved => "PersistenceObserved",
        EventType::PersistenceCreate => "PersistenceCreate",
        EventType::PrivilegeChange => "PrivilegeChange",
        EventType::RuleMatch => "RuleMatch",
        EventType::SnapshotComplete => "SnapshotComplete",
    }
}

fn login_ref(login: &LoginRecord) -> String {
    let mut refs = vec![login.source.clone()];
    if let Some(host) = &login.host {
        refs.push(host.clone());
    }
    if let Some(terminal) = &login.terminal {
        refs.push(terminal.clone());
    }
    if let Some(login_time) = login.login_time {
        refs.push(format_ts(login_time));
    }
    refs.join(", ")
}

fn is_root_ssh_login(login: &LoginRecord) -> bool {
    login
        .user
        .as_deref()
        .map(|user| user.eq_ignore_ascii_case("root"))
        .unwrap_or(false)
        && (login.source.to_lowercase().contains("ssh")
            || login
                .terminal
                .as_deref()
                .map(|value| value.starts_with("pts/"))
                .unwrap_or(false))
}

fn render_host_baseline_section(host: Option<&HostInfo>) -> String {
    let Some(host) = host else {
        return "<section><h2>主机概览</h2><div class='empty'>当前证据包未保留主机基础快照。</div></section>".to_string();
    };
    format!(
        "<section><h2>主机概览</h2><div class='grid'>{}{}{}{}{}{}{}{}{}</div></section>",
        kv("主机名", &host.hostname),
        kv("内核版本", host.kernel_version.as_deref().unwrap_or("-")),
        kv("OS 版本", host.os_version.as_deref().unwrap_or("-")),
        kv(
            "启动时间",
            &host
                .boot_time
                .map(format_ts)
                .unwrap_or_else(|| "-".to_string())
        ),
        kv("采集时间", &format_ts(host.collected_at)),
        kv("时区", host.timezone.as_deref().unwrap_or("-")),
        kv("当前用户", host.current_user.as_deref().unwrap_or("-")),
        kv("网卡数量", &host.interfaces.len().to_string()),
        kv("最近登录记录", &host.recent_logins.len().to_string())
    )
}

fn render_conclusion_section(view: &ConclusionView) -> String {
    let mut html = String::from(
        "<section><h2>核心结论</h2><p class='section-lead'>本节仅保留当前采集范围内可支撑的主判断，并明确区分结论强度。</p>",
    );
    html.push_str(&format!(
        "<p><span class='badge {}'>{}风险</span>{}<span class='badge status-neu'>置信度 {}%</span></p><p>{}</p><ul class='list-tight'>",
        severity_class(view.severity),
        severity_label(view.severity),
        if view.attack_established {
            "<span class='badge status-pos'>异常链已具备较强支撑</span>"
        } else {
            "<span class='badge status-review'>当前仍需补充核验</span>"
        },
        view.confidence,
        encode_text(&view.summary)
    ));
    for reason in &view.reasons {
        html.push_str(&format!("<li>{}</li>", encode_text(reason)));
    }
    html.push_str("</ul></section>");
    html
}

fn render_exclusion_section(rows: &[ExclusionView]) -> String {
    let mut html = String::from(
        "<section><h2>人工 / 白名单排除上下文</h2><p class='section-lead'>用于解释调查工具、授权登录或运维操作，避免将其误读为异常行为。</p>",
    );
    if rows.is_empty() {
        html.push_str(
            "<div class='empty'>当前未发现需要单独排除的人为或白名单上下文。</div></section>",
        );
        return html;
    }
    html.push_str("<table><thead><tr><th>类别</th><th>对象</th><th>说明</th><th>引用</th></tr></thead><tbody>");
    for row in rows {
        html.push_str(&format!(
            "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td><code>{}</code></td></tr>",
            encode_text(&row.category),
            encode_text(&row.subject),
            encode_text(&row.rationale),
            encode_text(&row.refs)
        ));
    }
    html.push_str("</tbody></table></section>");
    html
}

fn render_container_section(rows: &[ContainerView]) -> String {
    let mut html = String::from(
        "<section><h2>容器归因细节</h2><p class='section-lead'>展示 conmon / podman / netns 等关联，仅用于支持归因核查，不单独作为最终定性依据。</p>",
    );
    if rows.is_empty() {
        html.push_str("<div class='empty'>当前采集范围内未直接形成明确的容器归属证据，仍需结合运行时与命名空间信息继续核验。</div></section>");
        return html;
    }
    html.push_str("<table><thead><tr><th>实体</th><th>运行时</th><th>容器 ID</th><th>镜像</th><th>命名空间</th><th>关联端点</th><th>引用</th></tr></thead><tbody>");
    for row in rows {
        html.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td></tr>",
            encode_text(&row.entity),
            encode_text(&row.runtime),
            encode_text(&row.container_id),
            encode_text(&row.image),
            encode_text(&row.namespaces),
            encode_text(&row.endpoints),
            encode_text(&row.refs)
        ));
    }
    html.push_str("</tbody></table></section>");
    html
}

fn render_sample_section(rows: &[SampleView]) -> String {
    let mut html = String::from(
        "<section><h2>样本与文件特征</h2><p class='section-lead'>保留可执行样本的哈希、命令行、文件落点与轻量内容特征，便于复核和后续横向检索。</p>",
    );
    if rows.is_empty() {
        html.push_str(
            "<div class='empty'>当前未重建出可单列展示的可执行样本画像。</div></section>",
        );
        return html;
    }
    for row in rows {
        html.push_str(&format!(
            "<article><h3>{}</h3><div class='grid'>{}{}{}{}{}{}{}{}{}</div></article>",
            encode_text(&row.display),
            kv("实体", &row.entity),
            kv("路径", &row.path),
            kv("SHA-256", &row.sha256),
            kv("命令行", &row.cmdline),
            kv("内容引用", &row.content_ref),
            kv("YARA", &row.yara),
            kv("Strings", &row.strings),
            kv("备注", &row.notes),
            kv("展示名", &row.display)
        ));
    }
    html.push_str("</section>");
    html
}

fn render_timeline_focus_section(rows: &[TimelineFocusView]) -> String {
    let mut html = String::from("<section><h2>Timeline Reconstruction</h2>");
    if rows.is_empty() {
        html.push_str("<div class=\"empty\">No timeline rows were available for reconstruction.</div></section>");
        return html;
    }
    html.push_str(&format!(
        "<p class=\"muted\">Focused reconstruction window: <code>{}</code> to <code>{}</code>.</p>",
        encode_text(&format_ts(rows.first().map(|row| row.ts).unwrap())),
        encode_text(&format_ts(rows.last().map(|row| row.ts).unwrap()))
    ));
    let mut by_day = BTreeMap::<String, Vec<&TimelineFocusView>>::new();
    for row in rows {
        by_day
            .entry(row.ts.format("%Y-%m-%d").to_string())
            .or_default()
            .push(row);
    }
    for (day, items) in by_day {
        html.push_str(&format!(
            "<div class=\"card\"><h3>{}</h3>",
            encode_text(&day)
        ));
        for item in items {
            html.push_str(&format!(
                "<div class=\"facts\"><span class=\"badge {}\">{}</span><strong>{}</strong><br><span class=\"muted\">{} / {}</span><br>{}</div>",
                severity_class(item.severity),
                encode_text(&item.severity.to_string()),
                encode_text(&item.subject),
                encode_text(&item.source),
                encode_text(&item.category),
                encode_text(&item.detail)
            ));
        }
        html.push_str("</div>");
    }
    html.push_str("</section>");
    html
}

fn render_evidence_map_section(rows: &[EvidenceMapView]) -> String {
    let mut html = String::from("<section><h2>原始证据引用映射</h2>");
    if rows.is_empty() {
        html.push_str("<div class='empty'>当前未生成事件到原始证据的映射表。</div></section>");
        return html;
    }
    html.push_str("<table><thead><tr><th>UUID</th><th>类型</th><th>实体</th><th>时间</th><th>raw_ref</th><th>source_ref</th><th>content_ref</th><th>说明</th></tr></thead><tbody>");
    for row in rows {
        html.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>",
            encode_text(&row.event_id),
            encode_text(&row.event_type),
            encode_text(&row.entity),
            encode_text(&row.ts),
            encode_text(&row.raw_ref),
            encode_text(&row.source_ref),
            encode_text(&row.content_ref),
            encode_text(&row.note)
        ));
    }
    html.push_str("</tbody></table></section>");
    html
}

fn render_event_overview_section(
    overview: &EventOverviewView,
    conclusion: &ConclusionView,
) -> String {
    format!(
        "<section class='hero'><h2>事件总览</h2><p class='section-lead'>首页聚焦事件性质、主可疑对象、当前状态与处置优先级；其余细节均后置到对象、时间线与附录。</p><div class='hero-grid'><div class='card'><h3>执行摘要</h3><p>{}</p><p><span class='badge {}'>{}风险</span><span class='badge status-neu'>{}</span><span class='badge {}'>{}</span></p></div><div><div class='metric-grid'>{}{}{}{}</div><div class='grid' style='margin-top:16px'>{}{}</div></div></div></section>",
        encode_text(&overview.summary),
        severity_class(conclusion.severity),
        severity_label(conclusion.severity),
        encode_text(&overview.nature),
        if conclusion.attack_established {
            "status-pos"
        } else {
            "status-review"
        },
        encode_text(&overview.evidence_strength),
        kv("主可疑对象", &overview.primary_objects),
        kv("当前状态", &overview.current_status),
        kv("影响面", &overview.impact_scope),
        kv("建议动作", &overview.disposition),
        kv(
            "结论性质",
            if conclusion.attack_established {
                "当前证据链已形成较强支撑"
            } else {
                "当前仍需补充核验"
            }
        ),
        kv("证据强度", &overview.evidence_strength),
    )
}

fn render_risk_objects_section(rows: &[RiskObjectView]) -> String {
    let mut html = String::from(
        "<section><h2>关键风险对象</h2><p class='section-lead'>对重复的可疑链进行聚合，按对象展示实例、路径、外联、规则命中与待核验事项。</p>",
    );
    if rows.is_empty() {
        html.push_str("<div class='empty'>当前未形成可单列展示的关键风险对象。</div></section>");
        return html;
    }
    for row in rows {
        let support = unique_vec(
            row.evidence_refs
                .iter()
                .cloned()
                .chain(row.content_refs.iter().cloned())
                .chain(row.rule_ids.iter().cloned())
                .collect(),
        );
        html.push_str(&format!(
            "<article><h3>{}</h3><p><span class='badge {}'>{}风险</span><span class='badge status-neu'>风险分 {} 分</span><span class='badge status-neu'>{}</span></p><p>{}</p><div class='grid'>{}{}{}{}{}{}{}{}</div><div class='object-grid' style='margin-top:16px'><div class='card'><h3>事实</h3><ul class='list-tight'>{}</ul></div><div class='card'><h3>推断</h3><ul class='list-tight'>{}</ul></div></div><div class='object-grid' style='margin-top:16px'><div class='card'><h3>待核验</h3><ul class='list-tight'>{}</ul></div><div class='card'><h3>支撑证据</h3><ul class='list-tight evidence-list'>{}</ul></div></div><details><summary>查看实例、命令行与进程链</summary><div class='object-grid' style='margin-top:14px'><div class='card'><h3>实例列表</h3><ul class='list-tight'>{}</ul></div><div class='card'><h3>命令行与进程链</h3><ul class='list-tight'>{}{}</ul></div></div></details></article>",
            encode_text(&row.name),
            severity_class(row.severity),
            severity_label(row.severity),
            row.risk_score,
            encode_text(if row.running { "当前仍在运行" } else { "当前未直接观测到运行态" }),
            encode_text(&row.impact),
            kv("对象标识", &row.fingerprint),
            kv("主路径", &row.primary_path),
            kv("SHA-256", &row.sha256),
            kv("执行用户", &join_or_dash(&row.users)),
            kv("首次观测", &row.first_seen),
            kv("最后观测", &row.last_seen),
            kv("外联端点", &join_or_dash(&row.remote_endpoints)),
            kv("持久化线索", &join_or_dash(&row.persistence_locations)),
            list_items(&row.facts),
            list_items(&row.inferences),
            list_items(&row.pending_checks),
            list_items(&support),
            list_items(&row.instances),
            list_items(&row.cmdlines),
            list_items(&row.process_chains),
        ));
    }
    html.push_str("</section>");
    html
}

fn render_key_timeline_section(rows: &[TimelineFocusView]) -> String {
    let mut html = String::from(
        "<section><h2>关键时间线</h2><p class='section-lead'>时间线只保留每个时点新增的事实、推断或待核验线索，避免重复复述同一对象详情。</p>",
    );
    if rows.is_empty() {
        html.push_str("<div class='empty'>当前未形成可阅读的关键时间线。</div></section>");
        return html;
    }
    html.push_str("<table><thead><tr><th>时间</th><th>事件</th><th>性质</th><th>支撑证据</th></tr></thead><tbody>");
    for row in rows {
        html.push_str(&format!(
            "<tr><td><code>{}</code></td><td><strong>{}</strong><br><span class='muted'>{} / {}</span><br>{}</td><td><span class='badge {}'>{}</span></td><td><code>{}</code></td></tr>",
            encode_text(&format_ts(row.ts)),
            encode_text(&row.subject),
            encode_text(&row.source),
            encode_text(&row.category),
            encode_text(&row.detail),
            match row.nature { "fact" => "status-fact", "inference" => "status-pos", _ => "status-review" },
            encode_text(match row.nature { "fact" => "事实", "inference" => "推断", _ => "待核验" }),
            encode_text(&join_or_dash(&row.refs))
        ));
    }
    html.push_str("</tbody></table></section>");
    html
}

fn render_ioc_section(rows: &[IocView]) -> String {
    let mut html = String::from(
        "<section><h2>IOC 清单</h2><p class='section-lead'>统一汇总对象实例、路径、哈希、外联端点、持久化位置与规则编号，便于横向检索与封禁。</p>",
    );
    if rows.is_empty() {
        html.push_str("<div class='empty'>当前未提取到可直接汇总的 IOC。</div></section>");
        return html;
    }
    html.push_str("<table><thead><tr><th>类型</th><th>值</th><th>关联对象</th><th>说明</th><th>证据</th></tr></thead><tbody>");
    for row in rows {
        html.push_str(&format!(
            "<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
            encode_text(&row.kind),
            encode_text(&row.value),
            encode_text(&row.object),
            encode_text(&row.note),
            encode_text(&row.refs)
        ));
    }
    html.push_str("</tbody></table></section>");
    html
}

fn render_judgment_mapping_section(
    judgments: &[JudgmentView],
    evidence_map: &[EvidenceMapView],
) -> String {
    let mut html = String::from(
        "<section><h2>证据与判定映射</h2><p class='section-lead'>每条关键判定均回链到原始事件、路径、规则或样本引用，方便复核证据是否足以支撑结论。</p>",
    );
    if judgments.is_empty() {
        html.push_str("<div class='empty'>当前未形成可展示的判定映射。</div></section>");
        return html;
    }
    for row in judgments {
        let status_class = match row.status {
            "fact" => "status-fact",
            "strong" | "inference" => "status-pos",
            _ => "status-review",
        };
        let status_label = match row.status {
            "fact" => "事实层",
            "strong" => "高强度结论",
            "inference" => "推断层",
            _ => "待核验",
        };
        html.push_str(&format!(
            "<div class='card'><h3>{}</h3><p><span class='badge {}'>{}</span><span class='badge status-neu'>{}</span></p><p>{}</p><p><strong>支撑证据</strong></p><ul class='list-tight'>{}</ul></div>",
            encode_text(&row.title),
            status_class,
            encode_text(row.level),
            encode_text(status_label),
            encode_text(&row.statement),
            list_items(&row.support),
        ));
    }
    html.push_str("<details><summary>展开查看全部 UUID 与原始证据映射</summary>");
    html.push_str(&render_evidence_map_section(evidence_map));
    html.push_str("</details></section>");
    html
}

fn render_actions_section(rows: &[ActionView]) -> String {
    let mut html = String::from(
        "<section><h2>处置建议</h2><p class='section-lead'>对重复建议去重后，按立即处置、短期核查、后续复盘三层输出，便于直接执行。</p>",
    );
    if rows.is_empty() {
        html.push_str("<div class='empty'>当前未形成可执行的处置建议。</div></section>");
        return html;
    }
    for phase in ["立即处置", "短期核查", "后续复盘"] {
        let phase_rows = rows
            .iter()
            .filter(|row| row.phase == phase)
            .collect::<Vec<_>>();
        if phase_rows.is_empty() {
            continue;
        }
        html.push_str(&format!(
            "<div class='card'><h3>{}</h3>",
            encode_text(phase)
        ));
        for row in phase_rows {
            html.push_str(&format!(
                "<p><strong>{}</strong>：{}<br><span class='muted'>{} | 证据：{}</span></p>",
                encode_text(&row.target),
                encode_text(&row.action),
                encode_text(&row.rationale),
                encode_text(&join_or_dash(&row.refs))
            ));
        }
        html.push_str("</div>");
    }
    html.push_str("</section>");
    html
}

fn render_appendix_section(
    analysis: &AnalysisBundle,
    host: Option<&HostInfo>,
    exclusions: &[ExclusionView],
    containers: &[ContainerView],
    samples: &[SampleView],
    max_raw_events: usize,
) -> Result<String> {
    let mut html = String::from(
        "<section><h2>原始证据附录</h2><p class='muted'>以下内容默认折叠，供工程师复核、归档和回溯使用，不建议作为首页阅读入口。</p>",
    );
    html.push_str("<details><summary>主机背景信息</summary>");
    html.push_str(&render_host_baseline_section(host));
    html.push_str("</details>");
    html.push_str("<details><summary>人工 / 白名单排除上下文</summary>");
    html.push_str(&render_exclusion_section(exclusions));
    html.push_str("</details>");
    html.push_str("<details><summary>容器归因细节</summary>");
    html.push_str(&render_container_section(containers));
    html.push_str("</details>");
    html.push_str("<details><summary>样本详情页</summary>");
    html.push_str(&render_sample_section(samples));
    html.push_str("</details>");

    html.push_str("<details><summary>网络、文件与持久化原始表</summary><div class='grid'>");
    html.push_str("<div class='card'><h3>网络证据</h3><table><thead><tr><th>实体</th><th>协议</th><th>本地</th><th>远端</th><th>时间</th></tr></thead><tbody>");
    for conn in &analysis.dataset.net_connections {
        html.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
            encode_text(&conn.entity_key),
            encode_text(&conn.protocol),
            encode_text(&conn.local_addr),
            encode_text(&conn.remote_addr),
            encode_text(&format_ts(conn.ts))
        ));
    }
    html.push_str("</tbody></table></div>");
    html.push_str("<div class='card'><h3>文件证据</h3><table><thead><tr><th>实体</th><th>操作</th><th>路径</th><th>哈希</th><th>时间</th></tr></thead><tbody>");
    for artifact in &analysis.dataset.file_artifacts {
        html.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{:?}</td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td></tr>",
            encode_text(&artifact.entity_key),
            artifact.op,
            encode_text(&artifact.path),
            encode_text(artifact.sha256.as_deref().unwrap_or("-")),
            encode_text(&format_ts(artifact.ts))
        ));
    }
    html.push_str("</tbody></table></div>");
    html.push_str("</div><div class='card'><h3>持久化证据</h3><table><thead><tr><th>实体</th><th>机制</th><th>位置</th><th>值</th><th>时间</th></tr></thead><tbody>");
    for artifact in &analysis.dataset.persistence_artifacts {
        html.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td></tr>",
            encode_text(&artifact.entity_key),
            encode_text(&artifact.mechanism),
            encode_text(&artifact.location),
            encode_text(&artifact.value),
            encode_text(&format_ts(artifact.ts))
        ));
    }
    html.push_str("</tbody></table></div></details>");

    html.push_str("<details><summary>原始事件流与完整时间线</summary>");
    html.push_str("<div class='card'><h3>完整时间线</h3>");
    for entry in &analysis.timeline {
        html.push_str(&format!(
            "<p><code>{}</code> [{}] {}<br>{}</p>",
            encode_text(&format_ts(entry.ts)),
            if entry.is_inference {
                "推断"
            } else {
                "事实"
            },
            encode_text(&entry.label),
            encode_text(&join_or_dash(&entry.refs))
        ));
    }
    if analysis.timeline.is_empty() {
        html.push_str("<div class='empty'>当前无完整时间线条目。</div>");
    }
    html.push_str("</div>");
    for event in analysis.dataset.events.iter().take(max_raw_events) {
        html.push_str(&format!(
            "<details id='event-{}'><summary>{} / {} / {}</summary><div><p class='muted'>raw_ref=<code>{}</code><br>prev_event_hash=<code>{}</code><br>event_hash=<code>{}</code></p><pre>{}</pre></div></details>",
            encode_text(&event.event_id),
            encode_text(event_type_label(event.event_type)),
            encode_text(&event.event_id),
            encode_text(&format_ts(event.ts_wall)),
            encode_text(event.raw_ref.as_deref().unwrap_or("-")),
            encode_text(event.prev_event_hash.as_deref().unwrap_or("-")),
            encode_text(&event.event_hash),
            encode_text(&serde_json::to_string_pretty(event)?)
        ));
    }
    if analysis.dataset.events.is_empty() {
        html.push_str("<div class='empty'>当前无原始事件。</div>");
    }
    html.push_str("</details></section>");
    Ok(html)
}

fn list_items(items: &[String]) -> String {
    if items.is_empty() {
        "<li>无</li>".to_string()
    } else {
        items
            .iter()
            .map(|item| format!("<li>{}</li>", encode_text(item)))
            .collect::<Vec<_>>()
            .join("")
    }
}

fn build_conclusion_view(analysis: &AnalysisBundle) -> ConclusionView {
    let severity = analysis
        .top_chains
        .iter()
        .map(|chain| chain.severity)
        .chain(analysis.rule_matches.iter().map(|rule| rule.severity))
        .chain(analysis.suspicious_processes.iter().map(|row| row.severity))
        .max()
        .unwrap_or(Severity::Info);
    let attack_established = analysis.top_chains.iter().any(|chain| {
        chain.severity >= Severity::High
            && ((!chain.remote_endpoints.is_empty() && !chain.file_paths.is_empty())
                || !chain.persistence_locations.is_empty()
                || chain.rule_ids.len() >= 2)
    });
    let raw_refs = analysis
        .dataset
        .events
        .iter()
        .filter(|event| event.raw_ref.is_some())
        .count() as u32;
    let mut confidence = if analysis.top_chains.is_empty() {
        25
    } else {
        45
    };
    confidence += (analysis.rule_matches.len().min(3) as u32) * 10;
    confidence += if analysis.dataset.net_connections.is_empty() {
        0
    } else {
        10
    };
    confidence += if analysis.dataset.file_artifacts.is_empty() {
        0
    } else {
        10
    };
    confidence += if raw_refs > 0 { 10 } else { 0 };
    let confidence = confidence.min(95);

    let mut reasons = Vec::new();
    if let Some(chain) = analysis.top_chains.first() {
        reasons.push(format!(
            "异常链 `{}` 的严重度为 {}，风险分 {}。",
            chain.title,
            severity_label(chain.severity),
            chain.risk_score
        ));
        if !chain.remote_endpoints.is_empty() {
            reasons.push(format!(
                "该异常链已关联外联端点：{}。",
                join_or_dash(&chain.remote_endpoints)
            ));
        }
        if !chain.persistence_locations.is_empty() {
            reasons.push(format!(
                "当前采集范围内已观测到启动 / 持久化线索：{}。",
                join_or_dash(&chain.persistence_locations)
            ));
        }
    }
    if !analysis.rule_matches.is_empty() {
        reasons.push(format!(
            "已纳入 {} 条可解释规则命中。",
            analysis.rule_matches.len()
        ));
    }
    if raw_refs > 0 {
        reasons.push(format!(
            "证据包包含 {} 条带原始引用的事件，可回溯原始字段与哈希链。",
            raw_refs
        ));
    }

    ConclusionView {
        severity,
        attack_established,
        confidence,
        summary: if attack_established {
            "当前证据包已形成一条高风险异常执行链，显示主机存在需要立即处置的可疑执行活动；结论基于现有采集范围，仍建议结合原始日志继续复核。".to_string()
        } else {
            "当前已观测到高风险异常线索，但证据链尚不足以单独完成最终定性，建议继续补采并复核。"
                .to_string()
        },
        reasons,
    }
}

fn build_exclusion_views(analysis: &AnalysisBundle) -> Vec<ExclusionView> {
    let mut rows = Vec::new();
    for process in &analysis.dataset.processes {
        let lower = cmdline_text(process).to_lowercase();
        if lower.contains("trailguard")
            || process.display_name().to_lowercase().contains("trailguard")
        {
            rows.push(ExclusionView {
                category: "调查工具".to_string(),
                subject: format!("{} ({})", process.display_name(), process.entity_key),
                rationale:
                    "命中 TrailGuard 采集或报告进程特征，可视作授权排查上下文，除非另有相反证据。"
                        .to_string(),
                refs: process.entity_key.clone(),
            });
        }
    }
    if let Some(host) = analysis.dataset.host.as_ref() {
        for login in &host.recent_logins {
            if is_root_ssh_login(login) {
                rows.push(ExclusionView {
                    category: "授权登录".to_string(),
                    subject: format!(
                        "root ssh from {} on {}",
                        login.host.as_deref().unwrap_or("-"),
                        login.terminal.as_deref().unwrap_or("-")
                    ),
                    rationale: "主机登录记录中存在 root SSH 上下文，可能解释部分人工核查产生的进程或文件操作。".to_string(),
                    refs: login_ref(login),
                });
            }
        }
    }
    rows
}

fn build_container_views(
    analysis: &AnalysisBundle,
    process_map: &HashMap<String, &ProcessIdentity>,
) -> Vec<ContainerView> {
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    for chain in &analysis.top_chains {
        let processes = chain
            .process_keys
            .iter()
            .filter_map(|key| process_map.get(key).copied())
            .collect::<Vec<_>>();
        let runtime = processes.iter().find_map(|process| detect_runtime(process));
        let container_id = processes
            .iter()
            .find_map(|process| detect_container_id(process));
        let image = processes.iter().find_map(|process| detect_image(process));
        let namespaces = unique_join(
            analysis
                .dataset
                .net_connections
                .iter()
                .filter(|connection| chain.process_keys.contains(&connection.entity_key))
                .filter_map(|connection| connection.net_namespace.clone())
                .collect(),
        );
        if runtime.is_none() && container_id.is_none() && image.is_none() && namespaces == "-" {
            continue;
        }
        let entity = chain
            .process_keys
            .last()
            .cloned()
            .unwrap_or_else(|| chain.chain_id.clone());
        if !seen.insert(entity.clone()) {
            continue;
        }
        rows.push(ContainerView {
            entity,
            runtime: runtime.unwrap_or_else(|| "疑似容器运行时".to_string()),
            container_id: container_id.unwrap_or_else(|| "-".to_string()),
            image: image.unwrap_or_else(|| "-".to_string()),
            namespaces,
            endpoints: join_or_dash(&chain.remote_endpoints),
            refs: join_or_dash(&chain.event_refs),
        });
    }
    rows
}

fn build_sample_views(
    analysis: &AnalysisBundle,
    process_map: &HashMap<String, &ProcessIdentity>,
) -> Vec<SampleView> {
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    for artifact in &analysis.dataset.file_artifacts {
        if !(artifact.is_executable
            || artifact.is_elf
            || artifact.path.starts_with("/tmp")
            || artifact.path.starts_with("/dev/shm")
            || artifact.category.to_lowercase().contains("sample"))
        {
            continue;
        }
        if !seen.insert(artifact.path.clone()) {
            continue;
        }
        let process = process_map.get(&artifact.entity_key).copied();
        let mut yara = "未采集".to_string();
        let mut strings = Vec::new();
        let mut notes = Vec::new();
        for note in &artifact.notes {
            if let Some(value) = note.strip_prefix("yara=") {
                yara = value.to_string();
            } else if let Some(value) = note
                .strip_prefix("strings_preview=")
                .or_else(|| note.strip_prefix("strings="))
            {
                strings.extend(
                    value
                        .split('|')
                        .map(|item| item.trim().to_string())
                        .filter(|item| !item.is_empty()),
                );
            } else {
                notes.push(note.clone());
            }
        }
        rows.push(SampleView {
            entity: artifact.entity_key.clone(),
            display: process
                .map(|row| row.display_name())
                .unwrap_or_else(|| artifact.path.clone()),
            path: artifact.path.clone(),
            sha256: artifact.sha256.clone().unwrap_or_else(|| "-".to_string()),
            cmdline: process.map(cmdline_text).unwrap_or_else(|| "-".to_string()),
            content_ref: artifact
                .content_ref
                .clone()
                .unwrap_or_else(|| "-".to_string()),
            yara,
            strings: if strings.is_empty() {
                "未采集".to_string()
            } else {
                strings.join(", ")
            },
            notes: if notes.is_empty() {
                "-".to_string()
            } else {
                notes.join(", ")
            },
        });
    }
    rows
}

fn build_evidence_map_views(analysis: &AnalysisBundle) -> Vec<EvidenceMapView> {
    let content_ref_by_entity = analysis
        .dataset
        .file_artifacts
        .iter()
        .filter_map(|artifact| {
            artifact
                .content_ref
                .clone()
                .map(|content_ref| (artifact.entity_key.clone(), content_ref))
        })
        .collect::<HashMap<_, _>>();
    analysis
        .dataset
        .events
        .iter()
        .map(|event| EvidenceMapView {
            event_id: event.event_id.clone(),
            event_type: event_type_label(event.event_type).to_string(),
            entity: event.entity_key.clone(),
            ts: format_ts(event.ts_wall),
            raw_ref: event.raw_ref.clone().unwrap_or_else(|| "-".to_string()),
            source_ref: event
                .fields
                .get("source_ref")
                .and_then(value_as_string)
                .or_else(|| event.fields.get("path").and_then(value_as_string))
                .unwrap_or_else(|| "event-source".to_string()),
            content_ref: event
                .fields
                .get("content_ref")
                .and_then(value_as_string)
                .or_else(|| content_ref_by_entity.get(&event.entity_key).cloned())
                .unwrap_or_else(|| "-".to_string()),
            note: if event.prev_event_hash.is_some() {
                "哈希链事件".to_string()
            } else {
                "哈希链起点事件".to_string()
            },
        })
        .collect()
}

fn build_timeline_focus_views(analysis: &AnalysisBundle) -> Vec<TimelineFocusView> {
    let mut rows = Vec::new();
    for entry in &analysis.timeline {
        rows.push(TimelineFocusView {
            ts: entry.ts,
            source: if entry.is_inference {
                "分析引擎".to_string()
            } else {
                "时间线".to_string()
            },
            category: if entry.is_inference {
                "推断".to_string()
            } else {
                "事实".to_string()
            },
            subject: entry.label.clone(),
            detail: join_or_dash(&entry.refs),
            severity: entry.severity,
            nature: if entry.is_inference {
                "inference"
            } else {
                "fact"
            },
            refs: entry.refs.clone(),
        });
    }
    if let Some(host) = analysis.dataset.host.as_ref() {
        for login in &host.recent_logins {
            if let Some(login_time) = login.login_time {
                rows.push(TimelineFocusView {
                    ts: login_time,
                    source: login.source.clone(),
                    category: "login".to_string(),
                    subject: format!("{} login", login.user.as_deref().unwrap_or("unknown")),
                    detail: login_ref(login),
                    severity: Severity::Low,
                    nature: "fact",
                    refs: vec![login_ref(login)],
                });
            }
        }
    }
    for artifact in &analysis.dataset.file_artifacts {
        rows.push(TimelineFocusView {
            ts: artifact.ts,
            source: "file-artifact".to_string(),
            category: "file".to_string(),
            subject: artifact.path.clone(),
            detail: artifact.sha256.clone().unwrap_or_else(|| "-".to_string()),
            severity: if artifact.is_executable || artifact.is_elf {
                Severity::Medium
            } else {
                Severity::Low
            },
            nature: "fact",
            refs: vec![
                artifact.path.clone(),
                artifact
                    .content_ref
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
            ],
        });
    }
    let reference_ts = analysis
        .top_chains
        .iter()
        .map(|chain| chain.end_ts)
        .max()
        .unwrap_or_else(Utc::now);
    for rule in &analysis.rule_matches {
        rows.push(TimelineFocusView {
            ts: reference_ts,
            source: "rule-engine".to_string(),
            category: "rule-hit".to_string(),
            subject: format!("rule hit {}", rule.rule_id),
            detail: rule.why_matched.clone(),
            severity: rule.severity,
            nature: "inference",
            refs: rule.evidence_refs.clone(),
        });
    }
    rows.sort_by_key(|row| row.ts);
    if rows.is_empty() {
        return rows;
    }
    let end = rows.last().map(|row| row.ts).unwrap();
    let start = end - Duration::days(4);
    rows.into_iter()
        .filter(|row| row.ts >= start && row.ts <= end)
        .collect()
}

fn detect_runtime(process: &ProcessIdentity) -> Option<String> {
    let lower = cmdline_text(process).to_lowercase();
    ["conmon", "podman", "containerd", "docker", "crio"]
        .into_iter()
        .find(|needle| lower.contains(needle))
        .map(|needle| needle.to_string())
}

fn detect_container_id(process: &ProcessIdentity) -> Option<String> {
    for token in cmdline_text(process).split_whitespace() {
        if let Some(value) = token.strip_prefix("--cid=") {
            return Some(value.to_string());
        }
        if token.len() >= 12 && token.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Some(token.to_string());
        }
    }
    None
}

fn detect_image(process: &ProcessIdentity) -> Option<String> {
    let tokens = process
        .cmdline
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    for pair in tokens.windows(2) {
        if pair[0] == "--image" {
            return Some(pair[1].to_string());
        }
    }
    tokens
        .into_iter()
        .find(|token| {
            token.contains(':')
                && !token.starts_with('/')
                && (token.contains('/') || token.contains("sha256"))
        })
        .map(ToString::to_string)
}

fn unique_vec(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for value in values.into_iter().filter(|value| !value.trim().is_empty()) {
        if seen.insert(value.clone()) {
            result.push(value);
        }
    }
    result
}

fn build_event_overview_view(
    _analysis: &AnalysisBundle,
    conclusion: &ConclusionView,
    risk_objects: &[RiskObjectView],
) -> EventOverviewView {
    let primary_objects = if risk_objects.is_empty() {
        "未形成可聚合的高风险对象".to_string()
    } else {
        risk_objects
            .iter()
            .take(3)
            .map(|item| item.name.clone())
            .collect::<Vec<_>>()
            .join("、")
    };
    let running_count = risk_objects.iter().filter(|item| item.running).count();
    let endpoint_count = unique_vec(
        risk_objects
            .iter()
            .flat_map(|item| item.remote_endpoints.iter().cloned())
            .collect(),
    )
    .len();
    let persistence_count = unique_vec(
        risk_objects
            .iter()
            .flat_map(|item| item.persistence_locations.iter().cloned())
            .collect(),
    )
    .len();
    EventOverviewView {
        nature: if conclusion.attack_established {
            "高风险异常执行链".to_string()
        } else {
            "高风险异常线索".to_string()
        },
        primary_objects,
        current_status: if running_count > 0 {
            format!(
                "存在 {} 个仍处于运行态的高风险对象，建议优先隔离并保全现场。",
                running_count
            )
        } else {
            "当前未直接观测到仍在运行的高风险对象，但仍需继续开展离线复核。".to_string()
        },
        impact_scope: format!(
            "关键对象 {} 个；外联端点 {} 项；持久化线索 {} 项。",
            risk_objects.len(),
            endpoint_count,
            persistence_count
        ),
        disposition: if running_count > 0 || conclusion.attack_established {
            "建议立即处置".to_string()
        } else {
            "建议短期核查".to_string()
        },
        evidence_strength: format!(
            "{} / 置信度 {}%",
            severity_label(conclusion.severity),
            conclusion.confidence
        ),
        summary: conclusion.summary.clone(),
    }
}

fn build_risk_object_views(
    analysis: &AnalysisBundle,
    process_map: &HashMap<String, &ProcessIdentity>,
    samples: &[SampleView],
    containers: &[ContainerView],
) -> Vec<RiskObjectView> {
    #[derive(Default)]
    struct Accumulator {
        name: String,
        fingerprint: String,
        severity: Option<Severity>,
        risk_score: u32,
        running: bool,
        primary_path: String,
        sha256: String,
        users: Vec<String>,
        first_seen: Option<chrono::DateTime<Utc>>,
        last_seen: Option<chrono::DateTime<Utc>>,
        instances: Vec<String>,
        cmdlines: Vec<String>,
        cwds: Vec<String>,
        process_chains: Vec<String>,
        remote_endpoints: Vec<String>,
        persistence_locations: Vec<String>,
        rule_ids: Vec<String>,
        evidence_refs: Vec<String>,
        content_refs: Vec<String>,
        container_context: Vec<String>,
    }

    let sample_by_entity = samples
        .iter()
        .map(|sample| (sample.entity.clone(), sample))
        .collect::<HashMap<_, _>>();
    let container_by_entity = containers
        .iter()
        .map(|container| (container.entity.clone(), container))
        .collect::<HashMap<_, _>>();
    let mut grouped = BTreeMap::<String, Accumulator>::new();

    for chain in &analysis.top_chains {
        let terminal = chain
            .process_keys
            .last()
            .and_then(|key| process_map.get(key).copied());
        let sample = terminal
            .and_then(|process| sample_by_entity.get(&process.entity_key).copied())
            .or_else(|| {
                samples.iter().find(|sample| {
                    chain.file_paths.contains(&sample.path) || sample.display == chain.title
                })
            });
        let path = sample
            .map(|item| item.path.clone())
            .or_else(|| terminal.and_then(|process| process.exe.clone()))
            .or_else(|| chain.file_paths.first().cloned())
            .unwrap_or_else(|| chain.title.clone());
        let key = path.clone();
        let entry = grouped.entry(key.clone()).or_default();
        entry.name = sample
            .map(|item| item.display.clone())
            .or_else(|| terminal.map(|process| process.display_name()))
            .unwrap_or_else(|| chain.title.clone());
        entry.fingerprint = key;
        entry.severity = Some(
            entry
                .severity
                .map(|current| current.max(chain.severity))
                .unwrap_or(chain.severity),
        );
        entry.risk_score = entry.risk_score.max(chain.risk_score);
        entry.primary_path = path;
        entry.running |= terminal.map(|process| process.is_running).unwrap_or(false);
        if entry.sha256.is_empty() || entry.sha256 == "-" {
            entry.sha256 = sample
                .map(|item| item.sha256.clone())
                .or_else(|| terminal.and_then(|process| process.hash_sha256.clone()))
                .unwrap_or_else(|| "-".to_string());
        }
        if let Some(process) = terminal {
            if let Some(user) = &process.user {
                entry.users.push(user.clone());
            }
            entry.instances.push(format!(
                "{} / PID {} / entity {}",
                process.display_name(),
                process.pid,
                process.entity_key
            ));
            entry.cmdlines.push(cmdline_text(process));
            entry.cwds.push(cwd_text(process));
        }
        entry.process_chains.push(chain.process_keys.join(" -> "));
        entry
            .remote_endpoints
            .extend(chain.remote_endpoints.clone());
        entry
            .persistence_locations
            .extend(chain.persistence_locations.clone());
        entry.rule_ids.extend(chain.rule_ids.clone());
        entry.evidence_refs.extend(chain.event_refs.clone());
        if let Some(sample) = sample {
            if sample.content_ref != "-" {
                entry.content_refs.push(sample.content_ref.clone());
            }
        }
        if let Some(process) = terminal {
            if let Some(container) = container_by_entity.get(&process.entity_key) {
                entry.container_context.push(format!(
                    "运行时={} / container_id={} / image={} / netns={}",
                    container.runtime,
                    container.container_id,
                    container.image,
                    container.namespaces
                ));
                entry.evidence_refs.push(container.refs.clone());
            }
        }
        entry.first_seen = Some(
            entry
                .first_seen
                .map(|current| current.min(chain.start_ts))
                .unwrap_or(chain.start_ts),
        );
        entry.last_seen = Some(
            entry
                .last_seen
                .map(|current| current.max(chain.end_ts))
                .unwrap_or(chain.end_ts),
        );
    }

    let mut rows = grouped.into_values().map(|entry| {
        let users = unique_vec(entry.users);
        let remote_endpoints = unique_vec(entry.remote_endpoints);
        let persistence_locations = unique_vec(entry.persistence_locations);
        let rule_ids = unique_vec(entry.rule_ids);
        let evidence_refs = unique_vec(entry.evidence_refs);
        let content_refs = unique_vec(entry.content_refs);
        let container_context = unique_vec(entry.container_context);
        let instances = unique_vec(entry.instances);
        let cmdlines = unique_vec(entry.cmdlines);
        let cwds = unique_vec(entry.cwds);
        let process_chains = unique_vec(entry.process_chains);
        let instance_count = instances.len();
        let first_seen = entry.first_seen.map(format_ts).unwrap_or_else(|| "-".to_string());
        let last_seen = entry.last_seen.map(format_ts).unwrap_or_else(|| "-".to_string());
        let mut facts = vec![format!("在 {} 至 {} 的采集窗口内，观测到对象 {} 的 {} 个实例。", first_seen, last_seen, entry.name, instances.len())];
        if entry.primary_path != "-" {
            facts.push(format!("执行文件路径：{}。", entry.primary_path));
        }
        if entry.sha256 != "-" {
            facts.push(format!("样本 SHA-256：{}。", entry.sha256));
        }
        /*
        if !cwds.is_empty() && cwds.iter().any(|cwd| cwd != "-") {
            facts.push(format!("宸ヤ綔鐩綍锛歿}銆?, join_or_dash(&cwds)));
        }
        */
        if !cwds.is_empty() && cwds.iter().any(|cwd| cwd != "-") {
            facts.push(format!("cwd: {}.", join_or_dash(&cwds)));
        }
        if !remote_endpoints.is_empty() {
            facts.push(format!("已观测到外联端点：{}。", remote_endpoints.join("；")));
        }
        if !persistence_locations.is_empty() {
            facts.push(format!("当前采集范围内已观测到启动 / 持久化线索：{}。", persistence_locations.join("；")));
        }
        if !container_context.is_empty() {
            facts.push(format!("已发现运行时或命名空间关联：{}。", container_context.join("；")));
        }

        let mut inferences = Vec::new();
        if !rule_ids.is_empty() {
            inferences.push(format!("结合规则命中 {}，该对象具备高风险异常执行链特征。", rule_ids.join("、")));
        }
        if entry.primary_path.starts_with("/tmp") || entry.primary_path.starts_with("/dev/shm") || entry.primary_path.starts_with("/var/tmp") {
            inferences.push("对象位于高风险临时目录，结合执行与外联行为，建议按异常样本优先处置。".to_string());
        }
        if remote_endpoints.iter().any(|endpoint| endpoint.contains("3333") || endpoint.to_lowercase().contains("stratum"))
            || cmdlines.iter().any(|cmdline| cmdline.to_lowercase().contains("wallet")) {
            inferences.push("对象呈现出矿工样本常见的矿池通信或钱包参数特征，建议按高风险样本处理。".to_string());
        }

        let mut pending_checks = Vec::new();
        if persistence_locations.is_empty() {
            pending_checks.push("当前采集范围内未直接观测到明确持久化落点，仍需结合 systemd、cron、启动脚本与用户初始化文件继续核验。".to_string());
        }
        if container_context.is_empty() {
            pending_checks.push("当前未直接形成明确容器归属证据，仍需结合 conmon、podman、网络命名空间与编排配置继续核验。".to_string());
        }

        RiskObjectView {
            name: entry.name,
            fingerprint: entry.fingerprint,
            severity: entry.severity.unwrap_or(Severity::Info),
            risk_score: entry.risk_score,
            running: entry.running,
            primary_path: entry.primary_path,
            sha256: entry.sha256,
            users,
            first_seen,
            last_seen,
            instances,
            cmdlines,
            process_chains,
            remote_endpoints: remote_endpoints.clone(),
            persistence_locations: persistence_locations.clone(),
            rule_ids: rule_ids.clone(),
            evidence_refs: evidence_refs.clone(),
            content_refs: content_refs.clone(),
            container_context: container_context.clone(),
            facts,
            inferences,
            pending_checks,
            impact: format!("实例 {} 个 / 外联 {} 项 / 持久化线索 {} 项", instance_count, remote_endpoints.len(), persistence_locations.len()),
        }
    }).collect::<Vec<_>>();

    rows.sort_by(|a, b| {
        b.risk_score
            .cmp(&a.risk_score)
            .then_with(|| b.severity.cmp(&a.severity))
            .then_with(|| a.name.cmp(&b.name))
    });
    rows
}

fn build_ioc_views(risk_objects: &[RiskObjectView]) -> Vec<IocView> {
    let mut rows = Vec::new();
    for object in risk_objects {
        let refs = join_or_dash(&object.evidence_refs);
        for instance in &object.instances {
            rows.push(IocView {
                kind: "进程实例".to_string(),
                value: instance.clone(),
                object: object.name.clone(),
                note: "关键风险对象实例".to_string(),
                refs: refs.clone(),
            });
        }
        if object.primary_path != "-" {
            rows.push(IocView {
                kind: "文件路径".to_string(),
                value: object.primary_path.clone(),
                object: object.name.clone(),
                note: "关键执行文件".to_string(),
                refs: refs.clone(),
            });
        }
        if object.sha256 != "-" {
            rows.push(IocView {
                kind: "SHA-256".to_string(),
                value: object.sha256.clone(),
                object: object.name.clone(),
                note: "样本哈希".to_string(),
                refs: refs.clone(),
            });
        }
        for endpoint in &object.remote_endpoints {
            rows.push(IocView {
                kind: "远端地址".to_string(),
                value: endpoint.clone(),
                object: object.name.clone(),
                note: "外联端点".to_string(),
                refs: refs.clone(),
            });
        }
        for location in &object.persistence_locations {
            rows.push(IocView {
                kind: "持久化位置".to_string(),
                value: location.clone(),
                object: object.name.clone(),
                note: "已观测到的启动 / 持久化线索".to_string(),
                refs: refs.clone(),
            });
        }
        for rule_id in &object.rule_ids {
            rows.push(IocView {
                kind: "规则编号".to_string(),
                value: rule_id.clone(),
                object: object.name.clone(),
                note: "规则命中".to_string(),
                refs: refs.clone(),
            });
        }
    }
    let mut seen = BTreeSet::new();
    rows.into_iter()
        .filter(|row| seen.insert(format!("{}|{}|{}", row.kind, row.value, row.object)))
        .collect()
}

fn build_judgment_views(
    conclusion: &ConclusionView,
    risk_objects: &[RiskObjectView],
) -> Vec<JudgmentView> {
    let mut rows = vec![JudgmentView {
        title: "总体判断".to_string(),
        level: if conclusion.attack_established {
            "推断"
        } else {
            "待核验"
        },
        statement: conclusion.summary.clone(),
        support: conclusion.reasons.clone(),
        status: if conclusion.attack_established {
            "strong"
        } else {
            "review"
        },
    }];
    for object in risk_objects {
        rows.push(JudgmentView {
            title: format!("对象：{}", object.name),
            level: "事实",
            statement: format!(
                "已在当前采集范围内观测到对象 {} 的执行、路径与实例信息。",
                object.name
            ),
            support: unique_vec(
                object
                    .facts
                    .iter()
                    .cloned()
                    .chain(object.instances.iter().take(3).cloned())
                    .chain(object.content_refs.iter().cloned())
                    .chain(object.evidence_refs.iter().take(3).cloned())
                    .collect(),
            ),
            status: "fact",
        });
        rows.push(JudgmentView {
            title: format!("判定：{}", object.name),
            level: "推断",
            statement: if object.inferences.is_empty() {
                "当前对象存在异常迹象，但证据仍需进一步补强。".to_string()
            } else {
                object.inferences.join(" ")
            },
            support: unique_vec(
                object
                    .rule_ids
                    .iter()
                    .cloned()
                    .chain(object.remote_endpoints.iter().cloned())
                    .chain(object.persistence_locations.iter().cloned())
                    .chain(object.evidence_refs.iter().cloned())
                    .collect(),
            ),
            status: "inference",
        });
        if !object.pending_checks.is_empty() {
            rows.push(JudgmentView {
                title: format!("待核验：{}", object.name),
                level: "待核验",
                statement: object.pending_checks.join(" "),
                support: unique_vec(
                    object
                        .container_context
                        .iter()
                        .cloned()
                        .chain(object.evidence_refs.iter().cloned())
                        .collect(),
                ),
                status: "review",
            });
        }
    }
    rows
}

fn build_action_views(risk_objects: &[RiskObjectView]) -> Vec<ActionView> {
    let mut actions = Vec::new();
    for object in risk_objects {
        if object.running {
            actions.push(ActionView {
                phase: "立即处置",
                target: object.name.clone(),
                action: format!("优先隔离对象 {} 的运行实例，并阻断其当前对外连接；同步保全进程、样本与关键日志现场。", object.name),
                rationale: "对象处于运行态，继续存活将增加取证污染与潜在影响面。".to_string(),
                refs: object.evidence_refs.clone(),
            });
        }
        actions.push(ActionView {
            phase: "短期核查",
            target: object.name.clone(),
            action: format!("对路径 {} 对应样本执行只读保全、哈希复核，并比对同机 / 同环境是否存在同名或同哈希副本。", object.primary_path),
            rationale: "样本路径与哈希是后续横向检索和复核的关键锚点。".to_string(),
            refs: unique_vec(
                object
                    .content_refs
                    .iter()
                    .cloned()
                    .chain(object.evidence_refs.iter().cloned())
                    .collect(),
            ),
        });
        actions.push(ActionView {
            phase: "短期核查",
            target: object.name.clone(),
            action: if object.persistence_locations.is_empty() {
                format!("当前采集范围内未直接观测到 {} 的明确持久化落点，建议继续核查 systemd、cron、启动脚本与用户初始化文件。", object.name)
            } else {
                format!("核查 {} 关联的启动 / 持久化线索：{}。", object.name, object.persistence_locations.join("；"))
            },
            rationale: "启动链核查决定后续清理边界与复发风险。".to_string(),
            refs: object.evidence_refs.clone(),
        });
        actions.push(ActionView {
            phase: "后续复盘",
            target: object.name.clone(),
            action: if object.remote_endpoints.is_empty() {
                format!("补采对象 {} 相关历史网络、代理、DNS 与认证日志，核验其是否存在更早阶段的外联或横向痕迹。", object.name)
            } else {
                format!("围绕对象 {} 的外联端点 {} 开展同环境横向检索与历史流量复盘。", object.name, object.remote_endpoints.join("、"))
            },
            rationale: "用于补全事件时间线与影响范围。".to_string(),
            refs: object.evidence_refs.clone(),
        });
    }

    let mut seen = BTreeSet::new();
    actions
        .into_iter()
        .filter(|item| seen.insert(format!("{}|{}|{}", item.phase, item.target, item.action)))
        .collect()
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use common_model::{
        AnalysisBundle, Direction, DnsConfig, EnvironmentSummary, Event, EventSource, EventType,
        EvidenceDataset, FieldMap, FileArtifact, FileOp, FirewallRule, GroupEntry, HostInfo,
        HostOverview, HostsEntry, LoginRecord, MountInfo, NeighborEntry, NetConnection,
        NetworkInterface, OnlineUser, PersistenceArtifact, Platform, ProcessIdentity, ProcessNode,
        RouteEntry, RuleMatch, Severity, SuspiciousProcess, TimelineEntry, UserAccount,
    };
    use serde_json::json;

    use super::*;

    fn ts(day: u32, hour: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 3, day, hour, 0, 0).unwrap()
    }

    fn sample_host() -> HostInfo {
        HostInfo {
            host_id: "host:linux:demo".into(),
            hostname: "demo".into(),
            platform: Platform::Linux,
            collected_at: ts(27, 1),
            collector: "test".into(),
            kernel_version: Some("6.8.0".into()),
            os_version: Some("Ubuntu 24.04".into()),
            boot_time: Some(ts(22, 6)),
            timezone: Some("Asia/Shanghai".into()),
            environment_summary: EnvironmentSummary {
                total_vars: 2,
                highlights: BTreeMap::from([
                    ("PATH".to_string(), json!("/usr/bin")),
                    ("LANG".to_string(), json!("C.UTF-8")),
                ]),
            },
            current_user: Some("root".into()),
            interfaces: vec![NetworkInterface {
                name: "eth0".into(),
                mac_address: Some("00:11:22:33:44:55".into()),
                oper_state: Some("up".into()),
                mtu: Some(1500),
                addresses: vec!["172.20.0.56/24".into()],
            }],
            mounts: vec![MountInfo {
                source: "/dev/sda1".into(),
                target: "/".into(),
                fstype: "ext4".into(),
                options: vec!["rw".into()],
            }],
            disks: vec![common_model::DiskUsage {
                mount_point: "/".into(),
                total_bytes: 100,
                used_bytes: 50,
                available_bytes: 50,
            }],
            routes: vec![RouteEntry {
                destination: "default".into(),
                gateway: "172.20.0.1".into(),
                interface: "eth0".into(),
                flags: vec!["UG".into()],
                source: "proc".into(),
            }],
            dns: DnsConfig {
                nameservers: vec!["8.8.8.8".into()],
                search: vec![],
                raw_ref: Some("raw/dns.txt".into()),
            },
            hosts_entries: vec![HostsEntry {
                address: "127.0.0.1".into(),
                names: vec!["localhost".into()],
            }],
            neighbors: vec![NeighborEntry {
                address: "172.20.0.1".into(),
                hw_address: Some("aa:bb:cc:dd:ee:ff".into()),
                interface: Some("eth0".into()),
                state: Some("reachable".into()),
                source: "ip-neigh".into(),
            }],
            firewall_rules: vec![FirewallRule {
                backend: "nftables".into(),
                summary: "accept established".into(),
                raw_ref: Some("raw/nft.txt".into()),
            }],
            current_online_users: vec![OnlineUser {
                user: "root".into(),
                tty: Some("pts/0".into()),
                source: "who".into(),
            }],
            recent_logins: vec![LoginRecord {
                user: Some("root".into()),
                terminal: Some("pts/0".into()),
                host: Some("172.20.0.56".into()),
                login_time: Some(ts(27, 0)),
                logout_time: None,
                status: Some("still logged in".into()),
                source: "ssh".into(),
            }],
            failed_logins: vec![],
            user_accounts: vec![UserAccount {
                username: "root".into(),
                uid: 0,
                gid: 0,
                home: Some("/root".into()),
                shell: Some("/bin/bash".into()),
                password_state: Some("set".into()),
            }],
            groups: vec![GroupEntry {
                name: "root".into(),
                gid: 0,
                members: vec!["root".into()],
            }],
        }
    }

    fn sample_processes() -> Vec<ProcessIdentity> {
        vec![
            ProcessIdentity {
                entity_key: "proc:conmon".into(),
                pid: 200,
                ppid: 1,
                start_time: ts(27, 0),
                exe: Some("/usr/bin/conmon".into()),
                cmdline: vec![
                    "/usr/bin/conmon".into(),
                    "--cid=abcdef1234567890abcdef1234567890".into(),
                ],
                cwd: Some("/var/lib/containers".into()),
                user: Some("root".into()),
                hash_sha256: Some("aa".repeat(32)),
                signer: None,
                fd_count: Some(3),
                mapped_modules: vec![],
                deleted_paths: vec![],
                suspicious_flags: vec![],
                first_seen: ts(27, 0),
                last_seen: ts(27, 1),
                is_running: true,
            },
            ProcessIdentity {
                entity_key: "proc:miner".into(),
                pid: 300,
                ppid: 200,
                start_time: ts(27, 1),
                exe: Some("/tmp/sysupdate".into()),
                cmdline: vec![
                    "/tmp/sysupdate".into(),
                    "stratum+tcp://pool.example:3333".into(),
                    "--wallet".into(),
                    "wallet123".into(),
                ],
                cwd: Some("/tmp".into()),
                user: Some("root".into()),
                hash_sha256: Some("bb".repeat(32)),
                signer: None,
                fd_count: Some(9),
                mapped_modules: vec![],
                deleted_paths: vec![],
                suspicious_flags: vec!["tmp-exe".into()],
                first_seen: ts(27, 1),
                last_seen: ts(27, 1),
                is_running: true,
            },
            ProcessIdentity {
                entity_key: "proc:trailguard".into(),
                pid: 999,
                ppid: 1,
                start_time: ts(27, 1),
                exe: Some("/opt/trailguard/bin/trailguard-report".into()),
                cmdline: vec![
                    "trailguard-report".into(),
                    "--db".into(),
                    "/tmp/evidence.db".into(),
                ],
                cwd: Some("/opt/trailguard".into()),
                user: Some("root".into()),
                hash_sha256: Some("cc".repeat(32)),
                signer: None,
                fd_count: Some(5),
                mapped_modules: vec![],
                deleted_paths: vec![],
                suspicious_flags: vec![],
                first_seen: ts(27, 1),
                last_seen: ts(27, 1),
                is_running: true,
            },
        ]
    }

    fn sample_events() -> Vec<Event> {
        let mut first = Event::new(
            ts(27, 1),
            Some(1),
            EventSource::Ebpf,
            EventType::ProcessStart,
            "proc:miner",
            Some("proc:conmon".into()),
            Severity::High,
            FieldMap::from([
                ("path".into(), json!("/tmp/sysupdate")),
                ("source_ref".into(), json!("auditd:123")),
            ]),
        );
        first.raw_ref = Some("raw/process-start.json".into());
        first.seal(None).unwrap();

        let mut second = Event::new(
            ts(27, 1),
            Some(2),
            EventSource::Ebpf,
            EventType::NetConnect,
            "proc:miner",
            None,
            Severity::High,
            FieldMap::from([
                ("content_ref".into(), json!("files/sysupdate.bin")),
                ("remote".into(), json!("pool.example:3333")),
            ]),
        );
        second.raw_ref = Some("raw/net.json".into());
        second.seal(Some(first.event_hash.clone())).unwrap();
        vec![first, second]
    }

    fn sample_analysis() -> AnalysisBundle {
        let processes = sample_processes();
        let analysis = AnalysisBundle {
            host_overview: HostOverview {
                hostname: "demo".into(),
                platform: Platform::Linux,
                process_count: processes.len(),
                event_count: 2,
                suspicious_processes: 1,
                rule_match_count: 2,
                listening_ports: 1,
                remote_ip_count: 1,
                collected_file_count: 1,
            },
            suspicious_processes: vec![SuspiciousProcess {
                entity_key: "proc:miner".into(),
                display_name: "sysupdate".into(),
                risk_score: 96,
                severity: Severity::Critical,
                reasons: vec!["tmp executable".into(), "mining pool connection".into()],
                evidence_refs: vec!["raw/net.json".into()],
            }],
            top_chains: vec![CorrelatedChain {
                chain_id: "chain-1".into(),
                title: "Miner chain".into(),
                summary: "root ssh -> conmon -> sysupdate -> pool connection".into(),
                severity: Severity::Critical,
                risk_score: 96,
                process_keys: vec!["proc:conmon".into(), "proc:miner".into()],
                file_paths: vec!["/tmp/sysupdate".into()],
                remote_endpoints: vec!["pool.example:3333".into()],
                persistence_locations: vec!["/etc/systemd/system/sysupdate.service".into()],
                rule_ids: vec!["TG-MINER-POOL".into(), "TG-TMP-EXEC".into()],
                event_refs: vec!["raw/process-start.json".into(), "raw/net.json".into()],
                start_ts: ts(23, 12),
                end_ts: ts(27, 1),
            }],
            timeline: vec![
                TimelineEntry {
                    ts: ts(23, 12),
                    label: "file landed".into(),
                    severity: Severity::Medium,
                    entity_key: Some("proc:miner".into()),
                    refs: vec!["/tmp/sysupdate".into()],
                    is_inference: false,
                },
                TimelineEntry {
                    ts: ts(27, 1),
                    label: "net connect".into(),
                    severity: Severity::High,
                    entity_key: Some("proc:miner".into()),
                    refs: vec!["pool.example:3333".into()],
                    is_inference: false,
                },
            ],
            process_tree: vec![ProcessNode {
                entity_key: "proc:miner".into(),
                parent_entity_key: Some("proc:conmon".into()),
                pid: 300,
                ppid: 200,
                name: "sysupdate".into(),
                start_time: ts(27, 1),
                children: vec![],
            }],
            rule_matches: vec![
                RuleMatch {
                    rule_id: "TG-MINER-POOL".into(),
                    entity_key: "proc:miner".into(),
                    severity: Severity::Critical,
                    why_matched: "Connected to miner-like endpoint on port 3333.".into(),
                    evidence_refs: vec!["raw/net.json".into()],
                    facts: FieldMap::new(),
                },
                RuleMatch {
                    rule_id: "TG-TMP-EXEC".into(),
                    entity_key: "proc:miner".into(),
                    severity: Severity::High,
                    why_matched: "Executed from /tmp.".into(),
                    evidence_refs: vec!["raw/process-start.json".into()],
                    facts: FieldMap::new(),
                },
            ],
            dataset: EvidenceDataset {
                host: Some(sample_host()),
                processes,
                events: sample_events(),
                net_connections: vec![NetConnection {
                    entity_key: "proc:miner".into(),
                    protocol: "tcp".into(),
                    local_addr: "172.20.0.56:40912".into(),
                    remote_addr: "pool.example:3333".into(),
                    dns_name: Some("pool.example".into()),
                    direction: Direction::Outbound,
                    state: Some("established".into()),
                    net_namespace: Some("4026532993".into()),
                    observation_source: Some("ebpf-connect".into()),
                    socket_inode: Some(123),
                    ts: ts(27, 1),
                }],
                file_artifacts: vec![FileArtifact {
                    entity_key: "proc:miner".into(),
                    category: "sample".into(),
                    path: "/tmp/sysupdate".into(),
                    file_id: Some("inode:100".into()),
                    op: FileOp::Create,
                    sha256: Some("dd".repeat(32)),
                    size: Some(123456),
                    owner: Some("root".into()),
                    group: Some("root".into()),
                    mode: Some("0755".into()),
                    mtime: Some(ts(23, 12)),
                    ctime: Some(ts(23, 12)),
                    atime: Some(ts(27, 1)),
                    is_hidden: false,
                    is_suid: false,
                    is_sgid: false,
                    is_executable: true,
                    is_elf: true,
                    content_ref: Some("files/sysupdate.bin".into()),
                    notes: vec![
                        "strings_preview=stratum+tcp://pool.example:3333|wallet123|xmrig".into(),
                        "yara=not_configured".into(),
                    ],
                    ts: ts(23, 12),
                }],
                persistence_artifacts: vec![PersistenceArtifact {
                    entity_key: "proc:miner".into(),
                    mechanism: "systemd".into(),
                    location: "/etc/systemd/system/sysupdate.service".into(),
                    value: "ExecStart=/tmp/sysupdate".into(),
                    ts: ts(24, 10),
                }],
                ..EvidenceDataset::default()
            },
        };
        analysis
    }

    #[test]
    fn renders_priority_sections() {
        let reporter = HtmlReporter::new(20);
        let html = reporter.render_html(&sample_analysis()).unwrap();
        for needle in [
            "事件总览",
            "核心结论",
            "关键风险对象",
            "关键时间线",
            "IOC 清单",
            "证据与判定映射",
            "处置建议",
            "原始证据附录",
        ] {
            assert!(html.contains(needle), "missing section: {needle}");
        }
        assert!(html.contains("pool.example:3333"));
        assert!(html.contains("files/sysupdate.bin"));
        assert!(html.contains("trailguard-report"));
        assert!(html.contains("cwd: /tmp."));
    }

    #[test]
    fn renders_mermaid_graph() {
        let reporter = HtmlReporter::new(20);
        let graph = reporter.render_mermaid(&sample_analysis());
        assert!(graph.contains("Miner chain"));
        assert!(graph.contains("/tmp/sysupdate"));
        assert!(graph.contains("pool.example:3333"));
    }
}
