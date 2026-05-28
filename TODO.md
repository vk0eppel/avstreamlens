# AVStreamLens — TODO

---

## Bugs / Code Issues

- **Startup banner always appends `(+ PTP, IGMP)`** even for selections that don't need them (e.g. AVB-only, NDI-only). `cli::selected_protocol_display()` should compute the suffix conditionally, matching the actual `is_selected()` gating logic. (`src/cli.rs` / `src/main.rs`)

- **Dead `ProtocolChoice::All` check in `is_selected()`** — `expanded_protocols` is always fully-expanded by `includes()` before the loop starts, so `ProtocolChoice::All` is never in the slice. The early-return at `protocols.rs:184` is harmless but misleading. Remove it or add a comment. (`src/protocols.rs`)

- **Stale docstring in `report.rs`** — `print_report`'s doc comment still lists `SRT, RIST` which were removed. (`src/report.rs:48`)

- **SAP enrichment skips streams that already have a name** — `handle_sap` guards on `stats.sdp_name.is_none()`, so a SAP update that changes codec parameters mid-run is silently ignored. Consider re-enriching all fields (clock_hz, ptime_ms, expected_pt) unconditionally and only skipping the name if it would overwrite a user-visible one. (`src/capture.rs` — `handle_sap`)

---

## Missing Features

- **VLAN-ID filtering** — no per-VLAN filter is implemented; the tool processes all VLANs delivered by the capture interface. A `--vlan <id>` flag or interactive prompt could let the user narrow to a specific VLAN on trunk/SPAN ports. (`src/cli.rs`, BPF filter in `build_bpf_filter`)

- **`msrp_state` and `mvrp_vlans` never pruned** — AVB reservation state and VLAN registrations accumulate for the lifetime of the process. On long-running sessions this is unbounded. Prune `msrp_state` entries for stream IDs whose AVTP stream has been pruned; prune `mvrp_vlans` only if MVRP is no longer active (less clear-cut). (`src/capture.rs` — `reset_window`)

- **Dante AV video stream support** — Dante audio is fully implemented; Dante AV (Audinate's video-over-IP product) is not. Needs investigation of transport (UDP vs TCP), port ranges, and codec signalling used by Dante AV devices to determine detection heuristic. A new `DanteKind::VideoStream` variant or a separate `AvProtocol::DanteAv` would follow the existing handler pattern. (`src/protocols.rs`, `src/parser.rs`, `src/capture.rs`)

- **Review health score penalty weights** — the current penalty table was set heuristically. Worth a pass to validate weights feel right for real AV deployments: e.g. is −30 for a dead stream vs −25 for a lost PTP clock the right relative severity? Are the caps (loss capped at −10, EEE capped at −30) appropriate? (`src/stats.rs` — `calculate_score`)

- **`--interface` and `--protocol` CLI flags** — the interactive prompts block scripted/automated use. Skip prompts when these flags are provided: `./avstreamlens --interface en0 --protocol aes67,dante`. Minimal effort; `clap` or manual `std::env::args` parsing before the prompt blocks. (`src/cli.rs`, `src/main.rs`)

- **`--duration <seconds>` flag** — run for N seconds then exit with status 0 (healthy) or 1 (issues). Enables scripted health checks: `avstreamlens --interface en0 --protocol aes67 --duration 30 && echo OK`. (`src/main.rs` — report loop exit condition)

- **JSON output mode (`--output json`)** — emit newline-delimited JSON (one object per report cycle) for Grafana/Prometheus/`jq` integration. Add `serde::Serialize` to `StreamStats`, `PtpStats`, `NetworkHealth`; serialize at the point `print_report` is called. Log file format unchanged unless `--output json` is set. (`src/report.rs`, `src/stats.rs`)

- **`--quiet` / alert-only mode** — when `--quiet` is set, print nothing on a fully healthy cycle; print only the status line and active `⚠`/`💀` alerts otherwise. Eliminates noise when monitoring via `tail -f` or a log aggregator. (`src/report.rs` — `print_report`; `src/main.rs`)

- **`--no-color` flag / `NO_COLOR` env var** — strip ANSI escape codes from both console and log file output. Log files today contain raw ANSI codes that make `grep` harder. Honour the community-standard `NO_COLOR` env var automatically. (`src/report.rs` — all `\x1b[…m` sites; `src/capture.rs` — `emit`)

- **SAP re-announcement rate monitoring** — RFC 2974 requires SAP senders to re-announce every ~30 s. Track `last_sap_time` per stream in `sdp_cache`; alert when >90 s with no re-announcement while the RTP stream is still live. Catches sources that silently drop off SAP. (`src/capture.rs` — `handle_sap`; `src/stats.rs` — `StreamStats` or `sdp_cache` entry)

- **Dante unicast vs. multicast label** — display `[unicast]` or `[multicast]` next to Dante stream entries. The `is_multicast` field in `StreamStats` is already populated; this is a one-line display change. (`src/report.rs` — Dante stream entry formatting)

- **Redundant stream pairing (ST 2110 / AES67)** — productions often run dual-redundant streams (same SSRC, same codec, two different multicast groups). Detect pairs by matching SSRC + clock_hz + media_type and report them as `primary / redundant` with a combined health indicator. (`src/capture.rs` — post-dispatch pairing pass; `src/report.rs`)

- **RTCP reception reports** — AES67 and ST 2110 senders transmit RTCP SR/RR packets on `rtp_port + 1`. RR contains the sender's own loss fraction and jitter estimate, often more accurate than passive loss counting at the capture point. Add a `parse_rtcp()` parser; store `rtcp_loss_fraction` and `rtcp_jitter` in `StreamStats`; show in the stream entry. (`src/parser.rs` or `src/parser/rtcp.rs`; `src/stats.rs`; `src/capture.rs`)

- **PTP BMCA analysis** — when multiple PTP masters are visible, compute which would win the Best Master Clock Algorithm election (`clock_class → clock_accuracy → offsetScaledLogVariance → priority1/priority2`). Show "active grandmaster + N standby(s), best standby: …" in the Clock Sources section. Useful for validating redundant clock infrastructure. (`src/capture.rs` — `handle_ptp`; `src/stats.rs` — `PtpStats`; `src/report.rs`)

- **Stream count anomaly detection** — alert when the number of observed streams increases by more than 2× the rolling average over the last 3 windows (e.g. runaway Dante device flooding multicast). Track a short history of stream counts in `CaptureState`. (`src/capture.rs` — `reset_window`)

- **SDP file pre-load (`--sdp <file>`)** — allow a local SDP or multi-session SDP bundle to be loaded at startup to enrich streams before any SAP announcement arrives. Sets `clock_hz_confirmed`, `expected_pt`, `sdp_name`, `ptime_ms` from packet 1. (`src/cli.rs`; `src/capture.rs` — startup enrichment pass using existing `handle_sap` logic)

- **NMOS IS-04 discovery** — detect `_nmos-node._tcp` mDNS services and optionally query the NMOS Node API (`http://<host>:3000/x-nmos/node/v1.3/senders`) to enrich ST 2110 streams with sender names and SDP without relying on SAP. Significant addition; new `AvProtocol::Nmos` variant + HTTP client dependency. (`src/protocols.rs`, `src/parser/mdns.rs`, `src/capture.rs`)

---

## Platform Limitations (documented, tracked here for awareness)

- **NDI on loopback unsupported** — macOS loopback uses DLT_NULL (BSD null header, no Ethernet frame), and mDNS multicast doesn't flow over loopback. No fix planned; interface list already excludes `lo`/`lo0`. (`src/cli.rs`)

- **macOS VLAN tag stripping** — many macOS drivers strip the 802.1Q tag before pcap sees it, so per-VLAN stream attribution is unavailable on macOS even on trunk ports. Linux generally preserves the tag. No fix available at the application level.

- **Windows: no ANSI color in classic `cmd.exe`** — colour output requires Windows Terminal or VS Code. No fix planned; document in README under Platform Notes (already noted).

- **PAUSE / PFC frames consumed by NIC** — most NICs/drivers strip PAUSE and PFC frames at the MAC layer before pcap sees them. Absence of these alerts does NOT prove the link is congestion-free. Already documented in README; no fix available.

---

## Patterns to Follow When Extending

These aren't open bugs — they're invariants that must be preserved when adding new protocols or alerts:

- **"Selected AND observed" gate** for any new clock requirement: flag a missing clock only when (a) the relevant protocol is in `expanded_protocols` AND (b) at least one stream of that protocol has actually been observed. See `missing_ptp_clocks()` in `capture.rs`.

- **Alert dedup via `*_this_window` counters** for any new alert on a cumulative metric: keep the lifetime counter growing for history, but fire the alert only when the per-window delta is non-zero. See `lost_this_window`, `ts_discontinuities_this_window` in `stats.rs` and the corresponding reset in `reset_window()`.
