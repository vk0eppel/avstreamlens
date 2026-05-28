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
