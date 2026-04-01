# Roadmap

## Implemented MVP

- Rust workspace with clear crate boundaries
- Unified process / event / network / file / persistence model
- SQLite + JSONL evidence package
- Hash-chained normalized event stream
- Linux `/proc` snapshot collector
- Linux eBPF native realtime collector (kprobe + tracepoint)
- Windows snapshot collector
- Monitor mode with:
  - process diff
  - network diff
  - filesystem notifications
- Explainable rules for:
  - risky executable location
  - abnormal parent chain
  - network anomalies
  - file drop anomalies
  - persistence linkage
  - privilege anomalies
- Correlator for:
  - process tree
  - risk scoring
  - suspicious chain generation
  - timeline generation
- HTML + Mermaid report output
- Linux one-click deployment bundle (`tar.gz` + installer + wrapper commands)

## Next

1. Linux eBPF enhancement
   - credential changes beyond `set*id` / `capset` / exec credential commits
   - `commit_creds`-style deeper kernel attribution where verifier-safe and portable
   - optional ring buffer path and loss telemetry

2. Windows ETW collector
   - native process/network/file events
   - signer and image load enrichment
   - service creation and token change events

3. Stronger persistence coverage
   - Windows services
   - scheduled task XML parsing
   - Linux shell profile and ld preload checks

4. Richer network enrichment
   - DNS resolution cache
   - ASN / geo tagging from offline sources
   - allowlist / baseline support

5. Advanced evidence export
   - DOT output
   - zipped artifact bundle
   - IOC export

6. Threat-focused rule packs
   - miner-like pool / command-line / persistence baselines
   - webshell dropper chain presets
   - container escape triage presets
