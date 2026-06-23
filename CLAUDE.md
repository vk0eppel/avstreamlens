# CLAUDE.md

## Conventions
- Language: Rust  |  Framework: CLI  |  Style: Default Rust Style

## Key Components

| File | Purpose |
|---|---|
| `src/main.rs` | Entry point — owns pcap handle, 5s report timer, dynamic IGMP join drain, multicast/unicast byte counting. Thin driver |
| `src/capture.rs` | `CaptureState` + per-protocol handlers + `dispatch()` + `emit()` — all per-loop state and protocol-handler logic |
| `src/cli.rs` | CLI arg parsing (`--interface`, `--protocol`, `--read`, `--duration`, `--quiet`, `--no-color`, `--help`), interactive interface/protocol selection, BPF filter building |
| `src/parser.rs` | Top-level `detect_protocol` dispatcher + RTP + TCP + VLAN unwrap + multicast helpers; re-exports submodule API |
| `src/parser/sdp.rs` | SAP envelope (RFC 2974), SDP body (RFC 4566), `ts-refclk` normalisation |
| `src/parser/ptp.rs` | PTPv1 (IEEE 1588-2002) + PTPv2 (IEEE 1588-2008) message parser — used for both UDP PTP and L2 gPTP |
| `src/parser/avb.rs` | AVTP stream-id extraction + MSRP (802.1Qat) + MVRP (802.1Q) PDU parsers |
| `src/parser/avdecc.rs` | AVDECC ADP (IEEE 1722.1) frame parser — entity discovery without SPAN |
| `src/parser/lldp.rs` | LLDP TLV walker that surfaces the IEEE 802.3az EEE TLV |
| `src/parser/mdns.rs` | mDNS service-instance name extraction (Dante `_netaudio-cmc`/`_netaudio-arc`/`_netaudio`, NDI `_ndi`) |
| `src/parser/conmon.rs` | Dante ConMon (control & monitoring) frame parser — device liveness + channel count without SPAN |
| `src/parser/flow_control.rs` | 802.3x PAUSE / 802.1Qbb PFC frame classifier (EtherType 0x8808) |
| `src/protocols.rs` | Enums, constants, type definitions |
| `src/stats.rs` | Stream statistics — RTP, TCP, PTP, network health score |
| `src/report.rs` | Terminal reporting and log file output |

## Common Commands

```
cargo build --release   # build
cargo fmt               # format
cargo clippy -- -D warnings  # lint
cargo test              # run all 279 unit tests

# Release: bump version in Cargo.toml, commit, then:
git tag vX.Y.Z && git push --tags   # triggers .github/workflows/release.yml
```

## Release Process

- **Two workflows.** `.github/workflows/ci.yml` runs on every push/PR to `main` — `cargo clippy -- -D warnings` + `cargo test` across `ubuntu-22.04`/`macos-14`/`windows-2022`. `.github/workflows/release.yml` triggers on a pushed tag matching `v*.*.*` — builds 4 release binaries and attaches them to a GitHub Release
- **`verify-version` job runs first** in `release.yml` and fails the release before any matrix build starts if the tag (minus its `v` prefix) doesn't match `Cargo.toml`'s `version` — the tag drives artifact naming, so this guards against the two drifting apart
- **v1 target matrix** (4 artifacts): `aarch64-apple-darwin` + `x86_64-apple-darwin` (both built natively/cross on a single `macos-14` Apple Silicon runner — no `cross`/Docker needed for the x86_64 Darwin cross-build), `x86_64-unknown-linux-gnu` (`ubuntu-22.04`), `x86_64-pc-windows-msvc` (`windows-2022`). **Explicit non-goals**, not yet built: `aarch64-unknown-linux-gnu`, `aarch64-pc-windows-msvc`, a macOS universal/lipo binary
- **Windows build needs the Npcap SDK, not just the Npcap runtime.** The `pcap` crate links `Packet.lib`/`wpcap.lib` found via the `LIB` env var — there's no Cargo feature that avoids this. Both workflows download a **pinned** SDK version from `npcap.com/dist`, verify its SHA-256 against a checksum pinned in the workflow's `env:` block, then append its `Lib\x64` folder to `LIB`. npcap.com has no stable permalink/checksum API, so bump `NPCAP_SDK_VERSION` + `NPCAP_SDK_SHA256` together (in both workflow files) if the SDK ever needs updating, and expect the Windows leg to break if npcap.com reorganizes `/dist/` before that bump happens
- **Binaries are unsigned in v1** — no Apple notarization, no Windows Authenticode signing. README documents the Gatekeeper/SmartScreen bypass this requires of end users
- **Packaging**: each archive (`avstreamlens-{tag}-{target-triple}.tar.gz` or `.zip`) bundles the binary + `README.md` + `LICENSE`. Published via `softprops/action-gh-release`, chosen because it idempotently creates-or-appends-to the Release keyed by tag — safe for the 4 matrix legs to upload in parallel without a race
- **`Cargo.lock` is committed** (not gitignored) — standard for an application binary, keeps release builds reproducible as dependencies publish new semver-compatible versions over time

## Open Work

See **[TODO.md](TODO.md)** for the full list. Quick summary:

| Category | Items |
|---|---|
| Bugs / code issues | (none — all resolved) |
| Missing features | 802.1p PCP checking (AVB mandatory, AES67/ST2110 advisory); PTPv1 grandmaster NIC MAC display; VLAN-ID filter; Dante AV video; Dante mDNS TXT metadata enrichment (would confirm Transmitter Class); Via unicast audio (34336–34600) classification; health score review; JSON output; SAP re-announce monitor; redundant stream pairing; RTCP; PTP BMCA; SDP preload; NMOS IS-04 |
| Done, pending field check | ConMon device liveness + channel count; Dante SAP group 239.255.255.255 join; official ATP port detection (4321 / 14336–15359) |
| Platform limitations | NDI loopback unsupported; macOS VLAN tag stripping; Windows `cmd.exe` no ANSI color; PAUSE/PFC NIC-consumed |

---

## Architecture

### General
- **Test harness**: 279 unit tests in `#[cfg(test)]` modules across `parser.rs` + `parser/{sdp,ptp,avb,avdecc,lldp,mdns,flow_control,conmon}.rs`, `stats.rs`, and `capture.rs` — run with `cargo test`. Each parser submodule keeps its own fixtures and tests. `capture.rs` tests exercise handlers with hand-built IP/UDP/RTP byte buffers (see `ip_udp_rtp()` helper); no pcap dependency in tests
- Logging: timestamped `.log` files written on every run in the working directory; `Logger::log()` flushes after every write so the last report survives SIGINT
- **`emit_line(logger, color, text)`** (`report.rs`, next to `ansi()`) is the single place report sections pair file output with coloured console output. Every report section used to repeat `logger.log(&x); println!("{}", ansi(c, &x));` at each call site (~20 sites across `print_discovery`, the Clock Sources loop, the Streams loop, AVB MSRP/VLAN lines, Network Status). Lines where the logged text and the printed text intentionally differ (the header rule block, the pcap-drops stats line) are NOT call sites for `emit_line` — they stay as separate `logger.log` / `println!` calls because collapsing them would change what's written to the log file
- Bitrate computed as `byte_delta / elapsed_secs` — never assumed 1s exactly
- All modules follow the same pattern: parse → stats → report

### Parser Layout (`parser.rs` + `parser/`)
- **`parser.rs`** holds the `detect_protocol` dispatcher and only the small, shared bits: VLAN unwrap, multicast classification, RTP, TCP, the Dante port heuristic, ST2110 PT/port classifier. Submodules are declared with `pub mod ...` and their public functions are re-exported with `pub use ...::*` so external consumers (`main.rs`, `capture.rs`) keep using `crate::parser::parse_foo` regardless of which submodule `parse_foo` lives in
- **`parser/sdp.rs`** — SAP envelope (RFC 2974) → SDP body (RFC 4566); `parse_ts_refclk` normalises `ptp=IEEE1588-2008:<id>:<domain>` to colon-separated lowercase bytes matching `PtpStats::last_grandmaster`
- **`parser/ptp.rs`** — `parse_ptp` auto-detects PTPv1 vs PTPv2 from byte 1 low nibble; PTPv1 has two wire encodings (separate-byte vs nibble-packed) selected by byte 0 == 0x11. PTPv1 `gmClockIdentifier` is filtered against a hard allowlist of known IEEE 1588 clock-source codes (`GPS`, `ATOM`, `NTP`, `HAND`, `INIT`, `DFLT`, `PPS`, `ACTS`, …) — Dante leaves arbitrary junk bytes here (`FR`, `FV`, `@`, high bytes) that vary frame-to-frame; the allowlist suppresses all of them cleanly
- **`parser/avb.rs`** — `parse_avtp_stream_id` (sv-bit guarded), `parse_msrp` (TalkerAdvertise/TalkerFailed/Listener), `parse_mvrp` (VLAN registration). MSRP/MVRP share the IEEE 802.1Q vector-attribute format
- **`parser/lldp.rs`** — TLV walker; emits `AvProtocol::LldpEee` only when the EEE TLV (OUI 00-12-0F, subtype 0x05) is present AND a wake-up time is non-zero
- **`parser/mdns.rs`** — `extract_mdns_instance_name` finds the DNS-label-encoded service needle, then walks length-prefixed labels backward to find the longest valid printable-ASCII instance name. Used by `extract_dante_name` (tries `\x0d_netaudio-cmc` → `\x0d_netaudio-arc` → `\x09_netaudio`) and `extract_ndi_name` (needle `\x04_ndi`). **QR-bit guard in `detect_protocol`**: mDNS packets are only classified as Dante/NDI discovery when DNS flags byte `payload[2] & 0x80 != 0` (QR=1, response). Without this, outgoing mDNS queries from the local machine — which contain the same service-label bytes in the question section — would register the local machine's IP as a discovered Dante/NDI device. **Startup mDNS probe** (`main.rs::send_mdns_startup_probe`): at startup, AVStreamLens sends a PTR query for `_netaudio-arc._udp.local`, `_netaudio-cmc._udp.local`, `_netaudio._udp.local` to `224.0.0.251:5353`. Devices respond unicast (from port 5353, to our random port) with compressed DNS PTR records. The `detect_protocol` check includes `src_port == 5353` so these unicast responses are classified. `extract_dante_name` falls back to `extract_instance_from_ptr_response` which parses the DNS structure (skip questions → walk answer records → read first label of first PTR RDATA) instead of byte-searching for the service needle, which is replaced by a compression pointer in responses
- **`parser/flow_control.rs`** — `parse_flow_control` classifies 0x8808 frames by MAC-control opcode: `0x0001` → `FlowControlKind::Pause`, `0x0101` → `FlowControlKind::PriorityFlowControl`. Returns `None` for unknown opcodes. **Known limitation:** most NICs/drivers consume PAUSE/PFC at the MAC layer before pcap sees them. Absence of these alerts does NOT prove pause isn't happening upstream — it just means this NIC didn't surface them
- **Adding a new protocol parser** = create `parser/<name>.rs`, declare `pub mod <name>;` in `parser.rs`, re-export its public functions with `pub use <name>::...`, add a branch in `detect_protocol`. Tests live in the same file as the parser

### Capture Module (`capture.rs`)
- **`CaptureState`** owns the shared per-loop maps (streams, tcp_streams, sdp_cache, ptp_domains, eee_ports), `network_health`, `bytes_this_window`, **four protocol-family substates** (`dante: DanteState`, `ndi: NdiState`, `igmp: IgmpState`, `avb: AvbState` — see below), the dynamic-IGMP-join queue: `pending_join_groups: Vec<Ipv4Addr>` (handlers push new `239.x.x.x` groups here; drained by `main.rs` after each dispatch) and `joined_multicast: HashSet<Ipv4Addr>` (written by `main.rs` after a successful `join_multicast_v4` so handlers can skip groups already joined), and the PTPv1 follower census: `ptpv1_followers: HashMap<Ipv4Addr, Instant>` (populated in `handle_ptp` on every Delay_Req msg 0x01; pruned after 15s in `reset_window`). Also: `local_ips: HashSet<Ipv4Addr>` (capture interface's own IPs, populated in `main.rs` at startup, used to exclude the capture machine from Dante/NDI device discovery). `main.rs` holds exactly one `CaptureState` for the lifetime of the process
- **Protocol-family substates** — four structs grouping each family's fields with its own `reset_window`/`check_*` methods, so a check is testable with just the substate + supporting maps, no full `CaptureState`. Pattern: the substate owns its **fields + `reset_window` + `check_*`/`record_*`**; the per-packet **`handle_*` methods stay on `CaptureState`** and mutate `self.<family>.*` (handlers touch shared maps like `streams`/`local_ips`/`network_health`, so they can't move onto a substate). `CaptureState::reset_window()` delegates to each substate's `reset_window()`.
  - **`DanteState`** (`dante`): `sources: HashSet<Ipv4Addr>`, `names: HashMap<Ipv4Addr, String>`, `conmon: HashMap<Ipv4Addr, ConmonDevice>`, `unverified_windows: HashMap<Ipv4Addr, u32>` (counts consecutive Windows where a source has no ConMon activity and no active stream), `transmitter_class: HashMap<Ipv4Addr, TransmitterClass>`. Methods: `reset_window(streams)`, `unverified()` (owns `UNVERIFIED_THRESHOLD = 3` next to the counter it judges — returns the `HashSet<Ipv4Addr>` of sources at or past threshold; the report layer only renders this, it doesn't recompute it), `check_conmon_bridge()`, `check_ip_config()`, `check_follower_census(ptpv1_followers, ptp_domains)`, `record_tx_class()`
  - **`NdiState`** (`ndi`): `sources: HashSet<Ipv4Addr>`, `names: HashMap<Ipv4Addr, String>` — both session-lifetime, never pruned, so NdiState has no `reset_window`. Bitrate aggregation (`aggregate_ndi_bitrate`) stays on `CaptureState` because it reads the shared `streams`/`tcp_streams` maps, not these fields
  - **`IgmpState`** (`igmp`): `joins_seen: HashMap<(Ipv4Addr,Ipv4Addr), Instant>`, `querier_ips_this_window: HashSet<Ipv4Addr>`, `querier_version: Option<u8>`, `v3_report_seen_this_window: bool`. Methods: `reset_window()` (clears the two per-window fields, prunes `joins_seen` by TTL), `check_multiple_queriers(&mut NetworkHealth)`, `check_version_mismatch()`. **Querier identity** (IP, MAC, interval, last-query) lives on `NetworkHealth`, not here, because the score penalty reads it there — so `check_multiple_queriers` takes `&mut NetworkHealth` (and sets `multiple_queriers_this_window`), and `check_igmp_query_interval()` (which reads only `NetworkHealth`) stays on `CaptureState`. The `network_health.multiple_queriers_this_window` reset stays in `CaptureState::reset_window`
  - **`AvbState`** (`avb`): `avtp_streams: HashMap<[u8;8], AvtpStreamStats>`, `msrp_state: HashMap<[u8;8], MsrpDeclaration>`, `mvrp_vlans: HashSet<u16>`, `avdecc_entities: HashMap<[u8;8], AvdeccEntity>`. Single `reset_window()` carries the coupled pruning invariants: prune silent AVTP streams → prune MSRP to surviving AVTP stream-ids → clear MVRP VLANs when no AVTP remains → expire AVDECC entities past `valid_time + 10s`. Grouping these four was the strongest deletion-test case — the cross-references want one method
- **One `handle_*` method per protocol** (e.g. `handle_aes67`, `handle_dante`, `handle_ptp`). Each takes already-parsed inputs (`l2_payload: &[u8]`, `frame_bytes: u64`, `now: Instant`, plus protocol-specific fields carried on the `AvProtocol` variant — e.g. the AVTP sequence counter rides inside `AvProtocol::Avb { seq }`) — never a raw `pcap::Packet`. This is what makes handlers unit-testable
- **Handlers do not touch IO.** They mutate `CaptureState` and return `Vec<Alert>`. The dispatch layer prints + logs. The `PtpEvent` pattern in `stats.rs` is the same idea applied one layer deeper (data layer returns events; handler layer turns them into `Alert`s)
- **`Alert { level: AlertLevel, message: String }`** with constructors `Alert::info/good/warn/error`. `emit(&[Alert], &mut Logger)` maps level → ANSI color (none/32/33/31) and prints + logs in one place. Adding a new severity or alert format is a single-site change
- **`dispatch(state, proto, l2_payload, frame_bytes, now, logger)`** is the only entry point `main.rs` calls per packet — matches `AvProtocol`, calls the right handler, emits returned alerts
- **`state.check_ptp_timeouts()` / `state.check_stream_count_anomaly()` / `state.aggregate_ndi_bitrate()` / `state.reset_window()` / `state.missing_ptp_clocks(&expanded)`** are the periodic-cycle helpers `main.rs` calls every 5s. Window-reset prunes silent streams via `STREAM_PRUNE_SECS = STREAM_TIMEOUT_SECS * 2` (named constant in `capture.rs`). `check_stream_count_anomaly()` is called **before** `reset_window` so the count reflects streams active during the window; it maintains a rolling 3-entry `stream_count_history: Vec<usize>` and fires a `Warn` alert when the current total (RTP + TCP + AVTP) exceeds 2× the 3-window average — requires a full baseline of 3 windows before alerting. Four Dante/PTP periodic checks are computed in `do_report` and carried into `print_report` inside the `ReportSnapshot` (as `&[Alert]` fields — see Report Layer below), rendered inline in their target sections rather than emitted as free-standing output: `state.dante.check_ip_config()` + `state.dante.check_conmon_bridge()` → Discovered section; `state.dante.check_follower_census(&state.ptpv1_followers, &state.ptp_domains)` + `check_ptp_sync_conflict()` → Clock Sources section. `check_follower_census()` names specific missing devices (`dante.sources − ptpv1_followers − grandmaster_ip`) using `dante.names`; falls back to count-based when GM IP not yet observed. `check_ip_config()` fires only for mixed (some link-local, some routable) and subnet-split cases — all-link-local is a valid Dante deployment and produces no alert
- **"Selected AND observed" rule** for clock requirements: `missing_ptp_clocks` only flags a clock family when (a) the user's selection includes a protocol that uses it AND (b) at least one stream of that family has been observed (`state.streams.values().any(...)` or `!state.avb.avtp_streams.is_empty()`). Without the "observed" gate, picking "All" on a pure-AES67 network warned about missing gPTP just because AVB was in the expanded set. Apply the same gate to any future requirement that depends on protocol selection
- **Per-family clock alerts**: `missing_ptp_clocks` returns `Vec<MissingClock { kind: MissingClockKind, affected: Vec<&'static str> }>` rather than a bool. Kinds are `Ptpv2` (AES67/ST2110), `Ptp` (Dante — v1 or v2), `Gptp` (AVB — L2 only). The report layer renders one red line per entry: `⚠ No <clock> clock — <protos> may lose sync`. AES67 + ST2110 missing the same PTPv2 produce ONE entry with two affected protocols, not two entries
- Adding a new protocol = one new variant in `protocols::AvProtocol` + one new `handle_*` method + one new arm in `dispatch()`. No edits to `main.rs`

### Protocol Dispatch
- **Entry point**: `detect_protocol_unwrapped(eth, raw_et, l2_payload)` holds all the dispatch logic; `main.rs` peels VLAN tags once with `unwrap_vlan` and passes the result in, so the tag stack isn't walked twice per packet. (`detect_protocol(&eth)` — which unwraps then delegates — exists only as a test-module convenience wrapper.) Both names are used interchangeably below to mean "the dispatcher."
- Detection order (first match wins):
  `MSRP → LLDP → Flow-control (PAUSE/PFC) → MVRP → AVTP/AVB → gPTP → IGMP → SAP → mDNS → **Dante ConMon (8700–8708 + "Audinate" signature)** → Dante control → UDP PTP → **Dante ATP (239.255/16:4321 or both ports 14336–15359 — pre-RTP-gate, ATP is not RTP)** → RTP gate → **Dante audio (port heuristic)** → **Dante multicast (239.255/16 block)** → AES67 → ST2110`
- **Dante audio runs before AES67/ST2110 IP checks** — Dante multicast (239.255.x.x) would otherwise match `is_st2110_multicast`. Two Dante-audio gates: `is_likely_dante_audio` (strict — both src AND dst ports even in 5000–6000, for unicast) then `is_dante_multicast` (dst in `239.255.0.0/16` AND dst port even in 5000–6000 — catches multicast transmit flows whose source port is out of range, which the strict gate misses and the ST2110 catch-all would otherwise steal)
- **Always processed regardless of user selection**: only LLDP/EEE (`AvProtocol::is_selected()` returns `true` unconditionally only for `LldpEee`)
- **Gated on protocol selection** via `is_selected()`:
  - PTP → AES67, ST2110, Dante, or AVB selected
  - IGMP → AES67, ST2110, or Dante selected (IP multicast protocols)
  - SAP → AES67 or ST2110 selected
  - All other protocols → gated by their own `ProtocolChoice` variant
- Protocol selection pre-expanded once: `expanded_protocols: Vec<ProtocolChoice>` computed before the loop
- The `should_process` guard is simply `proto.is_selected(&expanded_protocols)` — no hardcoded overrides remain
- BPF always includes `(ether proto 0x88cc)` (LLDP), `(ether proto 0x88f7)` (gPTP), and `(ether proto 0x8808)` (PAUSE/PFC); `tcp` added for NDI; `all_protocols_filter` includes all EtherTypes + tcp
- Multicast IP association: 239.69.*=AES67, all other 239.x.x.x=ST2110
- UDP PTP `protocol_kind` labels: version-based not application-based — PTPv1 → `"PTPv1"`, PTPv2 → `"PTPv2"`, L2 gPTP → `"AVB"`

### Capture Loop & Stream Lifecycle
- **Report block is at the TOP of the loop for live capture**, before `cap.next_packet()` — so it fires even when pcap times out on quiet L2-only networks. For offline replay the report is triggered by pcap timestamp delta (every 5s of capture time) at the BOTTOM of the loop, after packet processing; a final report is printed at EOF (`pcap::Error::NoMorePackets`)
- `streams` and `tcp_streams` pruned after each 5s report: silent >20s removed; TCP `Terminated` removed immediately
- `ptp_domains` and `sdp_cache` never pruned (bounded by design)
- Per-window counters reset after each 5s report: `gap_events`, `max_iat_ms`, `pt_mismatches`, `dscp_violations`, `ssrc_changes`, `lost_this_window`, `ts_discontinuities_this_window`, `reorders_this_window`, `packets_this_window` (StreamStats) + `pause_frames_this_window`, `pfc_frames_this_window` (CaptureState) — alerts and score penalties reflect the current window, not the stream's lifetime. Exception: `observed_dscp: Option<u8>` is set once on the first packet and never reset — it is a lifetime property of the stream used at report time to distinguish Dante DVS (DSCP=0) from misconfigured hardware (wrong non-zero DSCP)
- **Alert dedup pattern**: cumulative counters (`lost_packets`, `ts_discontinuities`) keep growing forever; alerts fire only when the corresponding `*_this_window` delta is non-zero. Without this, a single old loss re-alerted every 5s for the rest of the run. Apply the same pattern when adding alerts on any cumulative metric. Exception: `reorders_this_window` is not cumulative (reorders don't accumulate to a lifetime total) — its alert fires when the per-window count is non-zero AND the reorder rate exceeds 1%
- All protocol arms set `last_packet_time = Some(now)` so pruning applies uniformly
- IGMP Join deduplication: `igmp_joins_seen: HashMap<(Ipv4Addr, Ipv4Addr), Instant>` — cleared on Leave; entries older than 5 minutes pruned each report cycle (handles hosts that disappear without sending Leave); Queries/Unknowns always print
- **VLAN-tagged frames**: `unwrap_vlan()` in `parser.rs` peels 802.1Q / 802.1ad / QinQ tags before dispatch — L2 AVB protocols work on tagged networks. Return type is `Option<(u16, &[u8])>` — EtherType and the stripped payload. **PCP (802.1p priority) is not currently extracted or checked** — 802.1p PCP checking is a planned feature (see TODO.md and the "PCP (802.1p) — planned" note under AVB below); when it lands, `unwrap_vlan` will additionally return the outermost tag's PCP and thread it through `dispatch()` to the handlers. No VLAN-ID filtering is implemented; the app processes whatever VLANs the capture interface receives. Operator-facing guidance (trunk vs access vs SPAN, macOS tag-stripping, QinQ caveat) lives in README.md under "Capture Setup — Monitoring One or Multiple VLANs"

### CLI Flags & Interface Listing
- **`parse_cli_args()`** reads `std::env::args()` before any interactive prompt. Recognised flags: `--interface`/`-i`, `--protocol`/`-p`, `--read`/`-r`, `--duration`/`-d`, `--quiet`/`-q`, `--no-color`/`--no-colour`, `--help`/`-h`. Unknown flags exit with an error. Returns `CliArgs { interface, protocols, read_file, duration, quiet, no_color }`
- `--interface <name>` — passed to `resolve_interface_by_name()`, which does an exact match against the pcap device list and exits with a clear message if not found. Bypasses the interactive listing entirely
- `--protocol <list>` — comma-separated names (`all`, `audio`, `video`, `aes67`, `avb`, `dante`, `ndi`, `st2110`, case-insensitive) or interactive-mode numbers (0–7). Parsed by `parse_protocol_str()`. Bypasses the interactive protocol prompt entirely
- `--duration` / `-d <seconds>` — run for exactly N seconds then exit with code 0 (health score = 100%) or 1 (any penalty). The exit check fires after each 5s report cycle, so at least one full window is always captured. Enables scripted health checks: `avstreamlens -i en0 -p aes67 --duration 30 && echo OK`
- `--quiet` / `-q` — when set, `print_report` suppresses all stdout output on fully healthy cycles (no stream issues, no missing clocks, no pcap drops). When issues are present the full report is printed. The log file always receives the full report regardless of this flag. Designed for `tail -f`/log-aggregator use. `quiet` is carried on `ReportSession` (see Report Layer below), not passed positionally
- **`--read` / `-r <file>`** — offline pcap replay from a `.pcap` or `.pcapng` file. **No root required.** Opens via `pcap::Capture::from_file()`; BPF filter still applied; 5s report windows driven by pcap packet timestamps (`packet.header.ts.tv_sec`) rather than wall clock; exits with 0/1 at EOF after a final report. Protocol defaults to `All` when `--read` is given without `--protocol` (avoids interactive prompt). IGMP joins and mDNS startup probe are skipped. `cap.stats()` not called (pcap drop line shows `None`). The capture loop is a generic `run_loop<T: pcap::Activated>()` in `main.rs` — both `pcap::Active` and `pcap::Offline` implement `Activated`, so live and offline share one loop body with `is_offline: bool` for the few behavioral differences. Periodic check helpers extracted into `emit_periodic_alerts()` and `do_report()` to avoid duplication between the top-of-loop and EOF paths. `no_flows_diagnostic_shown: bool` lives in `run_loop` on the `ReportSession` struct (see Report Layer below) and is passed by `&mut ReportSession` through `do_report` → `print_report` → `print_discovery` to suppress the no-active-flows diagnostic after its first appearance in a session
- **Interactive fallback**: when interface/protocol flags are absent `main.rs` calls `select_interface()` / `prompt_protocol_selection()` as before — the interactive path is fully intact
- Interface list filtered: `lo`/`lo0`, `utun*`, `awdl*`, `llw*`, `bridge*`, `vpn*`, `docker*`, `veth*`, `virbr*`, `ap1`, `anpi*` (iPhone USB), `gif*` (IPv6 tunnel), `stf*` (6to4 tunnel)
- `lo`/`lo0` excluded: macOS loopback uses DLT_NULL (4-byte BSD null header, no Ethernet frame) — incompatible with Ethernet parser; mDNS multicast also does not flow over loopback
- macOS port names via `macos_port_names()` → `networksetup -listallhardwareports`; IPv4 address shown; Enter selects interface 0 by default
- Startup banner: live mode → `📡 Listening on en0  for AES67, Dante  (+ PTP, IGMP)  streams`; offline mode → `📁 Replaying file.pcapng  —  Dante  (+ PTP, IGMP)`. The `(+ PTP, IGMP)` suffix is shown only when those protocols are relevant to the selection

---

## Protocol Reference

### AES67
- **Transport**: UDP multicast 239.69.*
- **Detection**: `is_aes67_multicast(dst_ip)` after RTP version check
- **Clock**: PTPv2 via UDP ports 319/320; ts-refclk cross-check validates SDP-claimed grandmaster against wire
- **Health metrics**: loss (RFC 3550 seq, signed-delta — negative delta = reorder, counted separately in `reorders_this_window`, not added to loss), jitter (RFC 3550 EWMA, sign-preserving), SSRC changes, TS discontinuities, signal gaps, payload type validation, DSCP EF(46) per-stream; reorder alert fires when `reorders_this_window / total_packets > 1%` (802.1p PCP checking is planned, not yet implemented — see AVB below)
- `clock_hz_confirmed` gates TS discontinuity detection — set (1) at stream creation if SDP found, (2) retroactively when SAP arrives, or (3) automatically inferred from consecutive RTP timestamp deltas: `StreamStats::try_infer_clock_hz()` collects 8 positive deltas in `ts_delta_samples: Vec<i64>`, takes the mode, and matches against a priority-ordered table of known (clock_hz, ptime_ms) pairs (48 kHz first: Δ6/12/24/48/96/192/384/480/960; then 44.1 kHz: Δ441/882). Sets `clock_hz`, `ptime_ms`, `clock_hz_confirmed` on match. Stops accumulating once confirmed; SDP always takes precedence
- `expected_pt` from SDP `a=rtpmap`; `pt_mismatches` counts mismatches per packet within the 5s window
- Signal gap: `gap_events` fires when IAT > 50ms; alert requires **≥2 events per 5s window** (single spike = pcap scheduling noise); `max_iat_ms` tracks worst case; both reset per 5s window
- PTP correction field stored as `last_offset_ns` (nanoseconds, after ÷65536); alert if abs > 1µs
- Alert `⚠ Stream not announced (no SAP)` when >10 packets with no SDP enrichment (AES67/Dante/ST2110 only — AVB/NDI never have SDP)

### Dante
- **Transport**: UDP unicast or multicast (239.255.x.x); discovery via mDNS (`_netaudio-cmc._udp` / `_netaudio-arc._udp` on firmware 4.x+, `_netaudio._udp` legacy)
- **Detection**: `is_likely_dante_audio()` requires BOTH src AND dst ports in 5000–6000 (even) — prevents false positives from ephemeral source ports. Plus `is_dante_multicast()` (`239.255.0.0/16`, Dante's default multicast block): a multicast-destined flow with dst port even in 5000–6000 is classified Dante even when the source port is out of range, so multicast transmit flows aren't stolen by the ST2110 catch-all. **Tradeoff** (see TODO field-verification): an ST2110 deployment using `239.255.x.x` with an even 5000–6000 dst port would be mislabelled Dante — uncommon since `239.255/16` is Dante-specific
- **ATP detection (official Audinate ports)**: a pre-RTP-gate check in `detect_protocol` classifies `239.255/16` dst port **4321** (multicast ATP audio) and flows with **both ports in 14336–15359** (unicast audio/video) as Dante. ATP framing is not RTP — `handle_dante` falls back to `StreamStats::update_non_rtp()` (packets/bitrate/presence only, `rtp_seen` stays false) and the report renders `N pkts | X Mbps (ATP framing — loss/jitter unavailable)` instead of fake 0% loss. `rtp_seen` also gates the "not announced (no SAP)" alert. Field verification of which ports real devices use is pending (TODO.md)
- **ConMon (control & monitoring)**: `parser/conmon.rs::parse_conmon()` — UDP 8700–8708 (multicast `224.0.0.230–233`), validated by ASCII `"Audinate"` at payload offset 16–23 plus a BE length field at [2..4] (padding-tolerant). Extracts the sender MAC ([8..14]) and, from 8705 metering frames ("MBC" tag at 0x2a, count at 0x44), the channel count. ConMon is **link-local multicast — never IGMP-snooped** — so it proves device liveness at ~33 pkts/s from any port, no SPAN. `dante.conmon: HashMap<Ipv4Addr, ConmonDevice>` (pruned after `CONMON_PRUNE_SECS = 60` of silence in `DanteState::reset_window`); ConMon IPs are also inserted into `dante.sources`. Report: `Dante live (ConMon: N)` line in the Discovered section, names cross-referenced from `dante.names`. The ConMon check runs before the Dante-control port check (they overlap on 8700); non-ConMon payloads on 8700/8800 still classify as `DanteKind::Control`. **ConMon is the verification signal for Dante device identity** — `DanteState::unverified()` flags a device in `dante.sources` without ConMon activity or active streams for ≥3 consecutive Windows; this catches management NICs and non-Dante devices that respond to Dante mDNS queries (e.g. a console's secondary NIC)
- **DSCP hierarchy** (Audinate official): CS7 (56) for time-critical PTP events; EF (46) for audio and regular PTP; Best Effort (0) intentionally used by Dante Virtual Soundcard (DVS) — software Dante does not apply DSCP markings to avoid bursting high-priority traffic from a general-purpose OS. No PCP requirement — Dante's QoS mechanism is DSCP-only. **DSCP violation is gated on Transmitter Class** (see below): DSCP 0 from a DVS/Via-classed flow is expected and counts no violation/penalty; DSCP 0 (or any wrong value) from Hardware or an unclassified flow still flags. `observed_dscp: Option<u8>` set once, never reset.
- **Transmitter Class** (Hardware / DVS / Via): a property of each Dante Audio Flow identifying what kind of implementation sources it. Pure verdict function `classify_transmitter(&TransmitterSignals)` in `protocols.rs` (returns `TransmitterVerdict { class, confidence, signals }`) over four independent signals in strict precedence: (1) **control-plane port fingerprint** — `dante_control_plane_class()` maps the DVS (38700–38708/38800/38900/8899), Via (28700–28708/28800/28900/4777/24440…/34336–34600), and FPGA-hardware (8751, 61440–61951) port families to a class; detected in `detect_protocol` as `DanteKind::ControlPlane`, accumulated per source IP in `DanteState::transmitter_class` via `DanteState::record_tx_class()` (DVS/Via override Hardware; ConMon records Hardware) → **Confirmed**; (2) **timing regularity** — `StreamStats::timing_metronomic()` (coefficient of variation over `iat_samples`): metronomic → Hardware, noisy → DVS; **overrides the DSCP signal** so a re-marked hardware source isn't mistaken for software → **Inferred**; (3) **TTL 128** (Windows host) → DVS, corroborating; (4) **DSCP 0 alone** → weakest **Hint**. Inferred software defaults to DVS — distinguishing DVS from Via needs the control plane. Rendered inline in the Streams section: `· DVS (confirmed)` / `· DVS (likely, N signals)` / `· DVS (possible — no QoS marking)`. Control-plane signals are unicast (need a Mirror Port); timing is the fallback when only multicast audio is visible. `handle_dante`'s `AudioStream` branch builds one `TransmitterSignals` per packet (after `min_ttl`/`observed_dscp` are updated for that packet) for the stored, displayed verdict. The DSCP-violation gate calls **`protocols::is_software_ignoring_dscp(&signals)`** rather than building its own second signals literal at the call site — the override (`dscp_zero` forced `false`) lives inside the function next to `classify_transmitter` itself, the one place that knows the signal precedence. This is the fix for a recurring drift: an earlier version built two independent `TransmitterSignals` literals at the call site and they diverged (the gating one silently dropped `ttl` too), so a Windows-hosted DVS source visible only via TTL was displayed as DVS yet still flagged for a DSCP violation; centralizing the override removes the second call site that could drift again.
- **Clock**: PTPv1 via UDP ports 319/320; grandmaster from Sync body (bytes 50–55 UUID, byte 61 stratum, bytes 62–65 ident); PTPv1 layout auto-detected by **`payload[0]`**: `0x11` → nibble-packed (hdr_shift=2), else separate-byte (hdr_shift=0); subdomain → domain: _DFLT=0, _ALT1=1, _ALT2=2, _ALT3=3, anything else → 0. **Limitation**: DDM / Dante Director uses custom user-defined subdomains (e.g. `H~O$L`) that don't match these four names — they silently map to 0, so all DDM domains appear as domain 0
- **Device names**: extracted from mDNS DNS labels via `extract_dante_name()` (tries CMC → ARC → legacy); stored in `dante.names: HashMap<Ipv4Addr, String>`; `DanteKind::Discovery { device_name }` carries name to dispatch. **Retroactive naming**: when a name is learned, existing Dante streams from that source IP (matched via `StreamStats::src_ip`) with no name yet are backfilled — a stream seen before the device's mDNS announcement is no longer nameless forever. Name written once (same rule as SAP session names). **Self-exclusion**: `handle_dante` and `handle_ndi_discovery` skip `dante.sources`/`ndi.sources` insertion when `src` is in `local_ips` — prevents the capture machine itself from appearing as a discovered device when it runs Dante/NDI software or sends the mDNS startup probe
- **Stream key includes src AND dst**: `"Dante {src} → {dst}:{dst_port}"` — one device can transmit several flows from the same source port to different destinations (e.g. multiple multicast groups); the old `src:port` key merged them, interleaving sequence numbers into false loss
- **`AvProtocol::Dante`**: `{ kind, src, dst, dst_port }` — `dst` is the destination IP; used in `handle_dante` to set `is_multicast` and fill `dst_ip`/`dst_port` via `StreamStats::new_with_info`
- **Health metrics**: all RTP metrics (same as AES67), DSCP EF(46) checked per packet
- `requires_valid_ptp_clock()` returns `true` for Dante — "no clock source" warning fires if PTPv1 disappears
- Default `ptime_ms = 1.0` (48 samples at 48kHz) for TS discontinuity tolerance
- Alert `⚠ Dante clock or subscription issue` for loss > **0.1%** or jitter > 15ms (0% threshold caused false positives from pcap scheduling noise)
- **TTL routing detection**: `StreamStats::min_ttl` (lifetime minimum) set in `handle_dante` AudioStream from `ip.get_ttl()`; report emits `⚠ Dante traffic routed (TTL N)` when `min_ttl < 64` (Linux/macOS sources start at 64; any router hop → ≤63). Windows sources (TTL=128) are not caught by this threshold — documented in code comment.
- **Multiple preferred masters**: `PtpInfo::stratum` (added field, PTPv1 Sync only) → `PtpStats::sync_senders_this_window: HashMap<Ipv4Addr, u8>` populated in `PtpStats::update()` on PTPv1 Sync; `CaptureState::check_ptp_sync_conflict()` called from `main.rs` before `reset_window()`: two senders with stratum 0 → Error "Multiple preferred masters in domain N"; any two senders → Warn "Multiple PTP Sync senders"

### NDI
- **Transport**: TCP (dynamic ports 5960–5980); discovery via mDNS `_ndi._tcp`
- **Detection**: IP-based — `ndi_sources: HashSet<Ipv4Addr>` populated from mDNS; any TCP to/from a known IP counted; port-range matching removed (caused double-counting)
- **Source names**: `extract_ndi_name()` (needle `\x04_ndi`); stored in `ndi_names: HashMap<Ipv4Addr, String>`; `NdiKind::Discovery { source_name }` carries name
- **Health metrics**: packet count, dead stream, bitrate (aggregated from `tcp_streams` by IP match every 5s), TCP quality (Healthy/Degrading/Critical/Terminated), retransmissions, RST/FIN
- NDI stream `dst_ip` is set so bitrate aggregation loop can match it
- NDI TCP detection: `detect_protocol` returns `AvProtocol::Tcp` for any IPv4 TCP segment (a stateless decode, no NDI awareness); `is_selected()` gates it on NDI like every other protocol; `CaptureState::handle_tcp()` does the is-this-actually-NDI narrowing (port range, or a source/dest IP already known from mDNS) and owns the per-connection `tcp_streams` quality state plus the `"NDI {ip}"` display entry. Loopback unsupported (DLT_NULL + no mDNS multicast)
- **SRT and RIST removed**: WAN contribution protocols — caused noise on local AV networks; SRT control packet signature overlapped with NDI

### ST2110
- **Transport**: UDP multicast 239.x.x.x (not 239.69.*)
- **Detection**: `is_st2110_multicast(dst_ip)`; stream type from port convention (last digit: 4=video, 6=audio, 8=anc) then RTP PT
- **Clock**: PTPv2, same as AES67
- **Health metrics**: all RTP metrics (same as AES67), DSCP per-stream: video (2110-20) accepts EF/CS5/AF41; audio/anc require EF(46) only
- 2110-20 video: `clock_hz_confirmed = true` immediately (90kHz is always correct per spec, no SDP needed)
- 2110-30 audio: default `ptime_ms = 1.0` for TS discontinuity tolerance
- Alert `⚠ Stream type unknown` when classified as 2110-??

### AVB
- **Transport**: L2 Ethernet — AVTP (0x22F0), MSRP (0x22EA), MVRP (0x88F5), gPTP (0x88F7), AVDECC ADP (0x22F0, byte0=0xFA)
- **AVDECC ADP** (IEEE 1722.1 discovery): `avdecc_entities: HashMap<[u8;8], AvdeccEntity>` keyed by entity_id EUI-64; parsed by `parser/avdecc.rs::parse_adp()`. Destination MAC `91:E0:F0:01:00:00` is a globally registered multicast — **bridges MUST forward it** (unlike gPTP link-local `01:80:C2:00:00:0E`). This is why Milan Manager / Hive see every device without a SPAN port. Byte 0 of the AVTP payload = `0xFA` (cd=1, subtype=0x7A). ADP layout: `[1]`=message_type (0=AVAILABLE, 1=DEPARTING, 2=DISCOVER), `[4-11]`=entity_id, `[12-19]`=entity_model_id (OUI = vendor), `[20-23]`=entity_capabilities (CLASS_A=0x100, CLASS_B=0x200, AEM=0x08), `[24-25]`=talker_sources, `[26-27]`=talker_caps (AUDIO=0x200, VIDEO=0x400), `[28-29]`=listener_sinks, `[30-31]`=listener_caps, `[36-39]`=available_index, `[40-47]`=gptp_grandmaster_id, `[48]`=gptp_domain. ENTITY_DEPARTING removes the entity immediately; ENTITY_DISCOVER is ignored. Entities pruned when `last_seen > valid_time_secs + 10s`. Displayed in "📡 Discovered (AVDECC)" section. `handle_avdecc_adp()` in capture.rs emits an Info alert on first detection and on available_index change (state change)
- **AVTP**: `avtp_streams: HashMap<[u8;8], AvtpStreamStats>` per stream_id (sv=1, bytes 4–11); subtype decoded via `avtp_subtype_name()` (0x00=IEC 61883, 0x02=CRF, 0x7E=MAAP…); sequence loss via `AvtpStreamStats::update_seq()` on byte 2 counter (8-bit wrap-safe, signed-i8 reorder filter mirrors the RTP fix); bitrate from Ethernet frame sizes
- **MSRP**: `parse_msrp()` extracts TalkerAdvertise (bandwidth, VLAN, priority), TalkerFailed (failure code at `first_value[33]`), Listener state; `msrp_state: HashMap<[u8;8], MsrpDeclaration>`; TalkerFailed alert immediate, decoded via `protocols::msrp_failure_reason()` over the full 802.1Qat Table 35-6 set (1–19, e.g. 8 = egress port not AVB-capable) with a numeric fallback — always shows `(code N: reason)`
- **MVRP**: `parse_mvrp()` extracts VLAN IDs; `mvrp_vlans: HashSet<u16>` — presence confirms L2 VLAN QoS; alert if AVTP active but no MVRP
- **PCP (802.1p) — planned, NOT yet implemented** (tracked in TODO.md; no `pcp`/`pcp_violations` code exists today). Design intent for when it lands: IEEE 802.1BA does not mandate specific PCP values in data frames — the authoritative source is the MSRP TalkerAdvertise `priority` field (already parsed, `first_value[20] >> 5`), which declares the PCP value the talker will use. The switch configures the CBS shaper from that reservation. The correct check is therefore: **observed frame PCP ≠ MSRP-declared priority for that stream_id** → the frame lands in the wrong queue, CBS doesn't protect it. Without a TalkerAdvertise in `msrp_state` for the stream, the expected PCP is unknown and no check fires. Intended penalty: −15/stream. PCP would be read from the outermost VLAN tag (requires `unwrap_vlan` to surface it first); untagged frames produce no alert. AES67/ST2110 would get a PCP=6 advisory (warn only, no score penalty); Dante/NDI no PCP check (Dante QoS is DSCP-only)
- All four AVB maps live on `AvbState` (the `avb` substate); `AvbState::reset_window()` prunes them per cycle: `avtp_streams` pruned by silence, `msrp_state` pruned to match surviving `avtp_streams` entries, `mvrp_vlans` cleared when `avtp_streams` is empty (MVRP is periodic — the switch re-registers within seconds when AVB resumes), `avdecc_entities` expired past `valid_time + 10s`

### mDNS name extraction (shared)
- `extract_mdns_instance_name(payload, needle)` in `parser.rs`: finds DNS-label-encoded service, extracts preceding instance name (1–63 bytes, printable ASCII, longest match)
- Used by `extract_dante_name()` (tries `\x0d_netaudio-cmc` → `\x0d_netaudio-arc` → `\x09_netaudio`) and `extract_ndi_name()` (needle `\x04_ndi`)

---

## Shared Infrastructure

### PTP / Clock Sources
- Domains keyed by `(domain, version)` — separates Dante PTPv1 from AES67/ST2110 PTPv2 on same domain number
- PTPv2 minimum: 34 bytes (common header) — allows Sync (44b) and P_Delay (54b) to create domain entries, not just Announce (64b)
- Grandmaster detected from Announce (PTPv2 ≥64b) or Sync body (PTPv1); alerts: DETECTED / CHANGED / LOST
- Grandmaster identity in the report (`report.rs` `(Some(gm), true)` arm): prefer a discovered Dante device name (cross-ref `grandmaster_src_ip` against `dante.names`), else for PTPv1 drop the gmClockUuid (a Dante firmware constant `00:00:00:01:00:1d`, useless as an ID) and show only the IP, else (PTPv2/gPTP) show the EUI-64. `grandmaster_src_ip` is captured in `PtpStats::update` only on the grandmaster-bearing message (Sync v1 / Announce v2) so a follower's Delay_Req can't overwrite the GM's IP (vs `last_src_ip` which follows any sender)
- Clock loss via `PtpStats::check_timeout()` in the 5s report loop — **not in `update()`** which only runs on packet arrival
- gPTP display: ✓ grandmaster from Announce, ○ clock source EUI-64 (`last_clock_id`, set from any PTPv2 message), ❌ no traffic. The ○ line distinguishes `seen_sync` (a real Sync 0x00 arrived → "Sync seen, no Announce") from a Pdelay-only endpoint (only P_Delay_Req 0x02 → "peer-delay requests only — link partner may not be gPTP-capable") — the latter, with no Pdelay_Resp, fingerprints a non-AVB switch port
- Clock quality formatted at parse time: PTPv2 class → `ptp_class_str()` (6=locked, 7=free-running, 135=holdover, 165=default, 187/255=slave-only) + `ptp_accuracy_str()` (e.g. 0x20=< 100ns); PTPv1 stratum + ident (GPS, ATOM…)
- Correction field stored as nanoseconds (`÷ 65536`); shown in Clock Sources if non-zero; alert if abs > 1µs
- **Path-delay tracking**: `min_path_delay_ns` / `max_path_delay_ns` recorded from every `Delay_Resp` (0x09) and `P_Delay_Resp` (0x03); reset on grandmaster change so the spread reflects the current clock. Reported as `path delay: 500ns – 1.2µs (spread 700ns)  ~N hops` where `N = min_path_delay_ns / 5_000` (rough: 5µs per gigabit switch), suppressed at N=0. Alerts: spread > 10µs → "unstable link (EEE, half-duplex, or cable)"; absolute > 1ms → "too many hops between this node and grandmaster". **Dante latency advisory** (PTPv1 only, N ≥ 3): `ℹ N hops: Dante latency should be ≥ Xms` using Audinate's published minimums — N 3–4 → 0.5ms, N 5–9 → 2ms, N ≥ 10 → 5ms
- `ts-refclk` cross-check: every 5s, `parse_ts_refclk()` extracts claimed grandmaster EUI-64+domain from SDP and compares against active `ptp_domains`

### SAP / SDP
- SAP processed only when AES67 or ST2110 is selected — no other protocol uses SDP announcements
- SAP silent — no console/log output; enriches stream stats: `clock_hz`, `ptime_ms`, `channels`, `sdp_name`, `expected_pt`, sets `clock_hz_confirmed = true`
- **`StreamStats::apply_sdp(media, session_name)`** is the single seam for SDP → stream field transfer, called both from `handle_sap` (retroactively, for every existing stream a new announcement matches) and from `handle_aes67`/`handle_st2110` (at stream creation, via `CaptureState::find_sdp_media()`, when a cached SDP already matches the port). Technical fields (`clock_hz`, `ptime_ms`, `channels`, `expected_pt`, `sdp_rtpmap`) always re-apply, so a mid-run codec change takes effect immediately; `sdp_name` is written once and never overwritten, avoiding display flicker on a session rename. One function owns both seams so they can't drift — they previously did (AES67 skipped `ptime_ms`, ST2110 skipped `channels`, on stream creation)
- Enrichment is **retroactive** for existing streams: a stream seen before SAP arrives is fully updated on next announcement
- `sdp_cache: HashMap<session_id, SdpSession>` never pruned; needed for ts-refclk cross-check
- `parse_ts_refclk(s)` normalizes `ptp=IEEE1588-2008:<eui64>:<domain>` / `ptp=IEEE1588-2002:<uuid>:<domain>` to lowercase colon-separated bytes matching `PtpStats::last_grandmaster`

### IGMP
- Processed only when AES67, ST2110, or Dante is selected (IP multicast protocols); suppressed for NDI-only and AVB-only
- `igmp_joins_seen` deduplicates Join prints per (src, group); Queries always printed
- **General vs Group-Specific Query** (`handle_igmp`): only a **General Query** — destination = the all-systems group `224.0.0.1` (`protocols::IGMP_ALL_SYSTEMS`) — establishes querier identity. It alone updates `igmp_querier_ip`/`igmp_querier_mac`, advances `last_igmp_query` (the silence timer) and `igmp_query_interval_secs`, inserts into `igmp.querier_ips_this_window` (conflict detection), and sets `querier_version`. A **Group-Specific Query** (destination = the queried group, e.g. `224.0.1.129`) is membership verification, not election — it is rendered as an informational line but does **not** touch any querier state. This matters because IGMP-snooping switches commonly emit RFC 4541 group-specific verification queries sourced from `0.0.0.0`; counting those as queriers produced a phantom "Multiple IGMP queriers" conflict (−15 + misleading "disable querier" advice) and a bogus `interval 0s` from the rapid group-specific burst. Gating on `224.0.0.1` is the RFC-correct definition of querier election
- Querier absence penalizes health score only when active multicast streams exist (−10 pts); "silent" threshold is interval-aware via `NetworkHealth::querier_silent_after_secs()` ≈ 2× the observed query interval (default 260s), per RFC 3376 "Other Querier Present Interval" — a fixed 130s left too little margin on a default 125s querier
- **Multiple queriers**: `IgmpState::check_multiple_queriers(&mut NetworkHealth, has_active_multicast)` fires an `Error` alert and sets `multiple_queriers_this_window` (−15 score penalty in `collect_penalties`) when ≥2 distinct General-Query source IPs are seen in one Window. **Gated on `has_active_multicast`** (`CaptureState::has_active_multicast()`, computed in `emit_periodic_alerts`) — same rule as the querier-absent penalty: IGMP querier topology only matters when multicast is actually flowing, so an idle/non-AV segment stays silent rather than docking the score
- `igmp_query_interval_secs` tracks detected interval between consecutive queries — shown in footer as `(interval Xs)`; `igmp_querier_mac: Option<[u8; 6]>` on `NetworkHealth` stores the Ethernet source MAC of the last querier — shown in the footer alongside the IP as `[xx:xx:xx:xx:xx:xx]` to identify the physical switch even when it has different IPs on different interfaces. `AvProtocol::Igmp` carries `src_mac: [u8; 6]` extracted from the Ethernet frame in `detect_protocol`
- **IGMPv3 Membership Report parsing** (`IgmpType::MembershipReportV3 { groups: Vec<Ipv4Addr> }`): type `0x22` is now parsed separately from IGMPv2 Join (`0x16`). `parse_igmpv3_report()` in `parser.rs` walks the Group Records (RFC 3376 §4.2): `payload[6..7]` = num_records, then per record: `[0]` record_type, `[1]` aux_data_len, `[2-3]` num_sources, `[4-7]` multicast address; offset advances by `8 + 4*num_sources + 4*aux_data_len`. Extracted groups are pushed to `CaptureState::pending_join_groups` by `handle_igmp` (filtered to `239.x.x.x` only)
- **Dynamic IGMP join bootstrap**: startup joins `224.0.0.22` (IGMPv3 all-routers, normally flooded) + PTP groups + SAP `224.2.127.254` + Dante's SAP group `239.255.255.255` (per Audinate's port list; inside the snooped 239.255/16 block, so the join is required). From SAP, `handle_sap` pushes stream multicast IPs from `SdpMedia.connection` ("IN IP4 x.x.x.x[/ttl]"). From IGMPv3 reports, `handle_igmp` pushes all `239.x.x.x` groups. `main.rs` drains `pending_join_groups` after each `dispatch()` call: `should_join_group()` gates by octet[1] (69→AES67, 255→Dante, other→ST2110) against `expanded_protocols`; approved groups get a `UdpSocket::join_multicast_v4` call; socket kept in `mc_sockets: Vec<UdpSocket>` (process-lifetime); success written to `state.joined_multicast`. Limitation: Dante IGMPv2 on old switches sends reports to the group address (snooped), creating a chicken/egg that the v3 path cannot resolve
- **IGMPv2/IGMPv3 mismatch**: `IgmpState::check_version_mismatch()` warns when the active querier is IGMPv2 but an IGMPv3 Membership Report was seen this Window — Mac built-in Ethernet sends IGMPv3 reports that an IGMPv2 querier may not process, so affected Macs can silently lose Dante/AES67 multicast (workaround: USB/Thunderbolt Ethernet adapter). Info-only, no score penalty
- **Snooping-switch misconfiguration diagnostics** (`emit_periodic_alerts`, capture.rs, all info-only/no score penalty): `check_filter_unregistered_multicast()` fires after ≥2 consecutive cycles where ConMon is active but no mDNS/PTP/streams are visible — the fingerprint of a switch with "Filter Unregistered Multicast"/"Block Unknown Multicast" enabled (blocks non-link-local multicast while link-local `224.0.0.x` still floods); `check_high_multicast_bandwidth()` warns above Audinate's 80 Mbps multicast-bandwidth threshold with no IGMP querier present; `check_igmp_snooping_blocking_ptp()` warns when Dante devices are found but no PTP traffic and no querier — a snooping switch may be blocking PTP multicast (224.0.1.129); skipped in offline replay since pcap can't join groups there

### LLDP / EEE
- LLDP (0x88CC) always in BPF filter regardless of protocol selection
- `parse_lldp_eee()` returns `AvProtocol::LldpEee` only when EEE TLV (OUI 00-12-0F, subtype 0x05) present AND wake-up time > 0
- `eee_ports: HashMap<(chassis_id, port_id), (tx_wake_us, rx_wake_us)>` — alert on first detection per port
- Limitation: absence of detection does NOT confirm EEE is disabled (switch may not send LLDP)

---

## Report Design

### Report Layer (`report.rs`)
- **`ReportSnapshot<'a>`** (`#[derive(Clone, Copy)]`) is a single immutable view of everything one report renders — ~25 fields, all shared borrows (`&HashMap`, `&[Alert]`, …) or `Copy` scalars, so the struct is zero-copy and cheap to pass by `&`. It replaces the old 29-positional-argument `print_report` signature. `do_report` in `main.rs` builds it from `&state.*` borrows **after** `calculate_score` runs (which needs `&mut state.network_health`) and drops it **before** `state.reset_window()` (which needs `&mut state`). The four periodic-check `&[Alert]` slices (ip-config, conmon-bridge, follower-census, ptp-sync) are fields on the snapshot
- **`ReportSession { quiet: bool, no_flows_diagnostic_shown: bool }`** carries the small mutable per-session state `print_report` needs to thread down to `print_discovery`. Created once in `run_loop`, passed by `&mut` to every `do_report` call. `quiet` and the no-flows-diagnostic latch are no longer positional args
- `print_report(snap: &ReportSnapshot, session: &mut ReportSession, logger: &mut Logger)` destructures `*snap` at the top so the ~600-line body keeps its original local names. Adding a new field to a report = one field on `ReportSnapshot` + one line in the `do_report` builder, no signature churn
- **Audience**: AV engineers, not network admins — plain English alerts, no raw hex or packet counts
- **Report header**: cyan rule line + `AVStreamLens  ·  <timestamp>` + rule line — separates successive 5-second reports
- **Seven sections** (all use cyan `\x1b[36m` header + emoji); log file output matches console exactly:
  1. `🔬 Network Health — X%  |  AES67: N  |  Dante: N` — health score + stream counts; appears immediately after the rule block so the first glance shows whether anything is wrong. Timestamp is NOT repeated here — it is already in the header rule line above
  2. **Health Summary** — `build_health_summary()` (in `stats.rs`, method on `NetworkHealth`) returns one `⚠` bullet per factor deducting from the Health Score this Window; rendered in yellow directly under the score line. Stream issues collapse by category (`⚠ N stream(s) with <issue>`), infrastructure issues get individual bullets. **Both `build_health_summary` and `calculate_score` are now thin consumers of `NetworkHealth::collect_penalties()`** — a single function that returns `Vec<ScorePenalty>`, each variant carrying both its `deduction()` magnitude and its `into_bullet()` English. `calculate_score` sums the deductions; `build_health_summary` maps to bullets. The CONTEXT.md "Health Summary" biconditional (bullet ⇔ penalty) is therefore **structural, not convention-enforced** — they cannot drift because they read the same table. The test `score_and_summary_share_one_penalty_table` asserts `summary.len() == penalties.len()` and `score == 100 − Σdeductions`. Omitted entirely when the score is 100% (no status line at all on a healthy report). Factors that carry no score penalty (PAUSE/PFC) produce no `ScorePenalty` and therefore no bullet. **`collect_penalties`'s per-stream loop is itself a thin consumer of `StreamStats::diagnostics() -> Vec<StreamDiagnostic>`** (`stats.rs`) — the single seam for every per-stream Diagnostic, scored and informational alike (loss, jitter, ts-discontinuity, ssrc, gap, dscp, dead are scored; reorder, TTL routing, payload-type mismatch, no-SAP, unknown ST2110 type, and the AES67/Dante jitter hints are informational, `deduction() == 0.0`). The Streams-section per-stream alert lines (`report.rs`) render the same `diagnostics()` call directly — previously the two sites independently re-evaluated the same `StreamStats` fields and had already drifted (Dante's combined `loss_pct() > 0.1 || jitter_ms() > 15.0` hint used different numbers than the generic jitter penalty). **Loss scoring is window-scoped**, not lifetime: `StreamDiagnostic::PacketLoss`'s deduction comes from `loss_pct_this_window()` (new `packets_this_window` counter, reset each Window like its siblings) rather than the lifetime `loss_pct()` — a stream that stops losing now recovers its score next Window, matching the Health Score's own "quality within the current Window" definition; the *displayed* cumulative `%` in the alert text is unchanged. The 10–20ms jitter band is scored (2.0 deduction, feeds the Health Summary bullet) but — as before this change — has no per-stream report line (`StreamDiagnostic::HighJitter::message()` returns `None` below 20ms); only `>20ms` renders "High jitter" inline. `StreamDiagnostic::is_critical()` is the one variant (`Dead`) rendered red (💀) rather than yellow (⚠)
  3. `📇 Discovered:` — devices learned from multicast mDNS (Dante/NDI) and Dante ConMon, shown only when ≥1 device discovered; `print_discovery()` in `report.rs`. One `▸` line per verified device (`▸ "Name"   IP  (N tx flows)` or `▸ IP   (name pending)`); the `(N tx flows)` suffix shows the count of active stream map entries with `src_ip == device_ip && protocol == "Dante"` — unicast + multicast, RTP + ATP — omitted when zero. Unverified devices (mDNS-only for ≥3 windows, no ConMon, no stream) shown inline with `⚠` prefix: `⚠  "Name"   IP   (mDNS only, no ConMon)`. Subheader `  Dante (N)  · all live` shows total verified count and liveness suffix. No channel count displayed (field data showed incorrect counts on non-Brooklyn hardware). Periodic diagnostics rendered at the bottom of this section: `check_dante_ip_config()` (mixed link-local/routable, subnet split) and `check_dante_conmon_bridge()` (redundancy bridge). No-active-flows diagnostic (`⚠  Devices announced but no active flows — mirror port may be needed`) shown at most once per session; tracked via `no_flows_diagnostic_shown: &mut bool` threaded from `run_loop` through `do_report` into `print_report` and `print_discovery`
  4. `📡 Discovered (AVDECC — N entities):` — ADP-discovered AVDECC entities (conditional)
  5. `🕐 Clock Sources:` — PTP domains; periodic diagnostics rendered inline: `check_dante_follower_census()` (names specific devices not sending Delay_Req) and `check_ptp_sync_conflict()` (multiple preferred masters)
  6. `📡 Streams:` — unified list of all active streams (AES67, Dante, ST2110, NDI, AVB), no blank lines between entries
  7. `📊 Network Status:` — bandwidth + QoS/DSCP + IGMP querier + EEE + PAUSE/PFC + pcap capture stats. **One metric per line** (no `|`-joined rows) for at-a-glance scanning — `plain_line()` is the uncoloured sibling of `emit_line()` used for these. Always shown regardless of Health Score; pcap drops appear here only (tool limitation, never a Health Summary bullet)
- Stream entry format: `  ▸ Protocol  "Name"  [codec]  —  IP:port` / `    metrics line` / `    ⚠  alerts`
  - Protocol label: ST2110 subtypes shown as `ST2110-20` etc.; AES67 streams whose `src_ip` is in `dante.sources` shown as `AES67 (Dante: "Name")` or `AES67 (Dante)` — identifies Dante devices operating in AES67 mode
  - RTP streams (AES67/Dante/ST2110): metrics = `loss: X%  |  jitter: X ms  |  X Mbps`
  - NDI: metrics = `quality  |  X Mbps  |  retrans: N` (TCP quality, no RTP metrics)
  - AVB: metrics = `loss: X%  |  X Mbps` + MSRP/VLAN reservation state inline
- DSCP: validated **per stream** against protocol-appropriate expected values; alert inline in Streams section when wrong; footer shows summary across all streams
  - AES67 / ST2110-30 audio / ST2110-40 anc: EF (46) required
  - ST2110-20 video: EF (46), CS5 (40), or AF41 (34) accepted
  - Dante hardware: EF (46) for audio/PTP; CS7 (56) for time-critical PTP events. DSCP violation gated on Transmitter Class — DSCP 0 from a DVS/Via-classed flow is expected (no violation); DSCP 0 or any wrong value from Hardware/unclassified flags. `observed_dscp: Option<u8>` on `StreamStats` (set once, never reset) feeds the verdict and the gate
  - NDI / AVB: no DSCP check (TCP / Layer 2)
- PCP (802.1p): **planned, not yet implemented** — no PCP is extracted or rendered today. See the "PCP (802.1p) — planned" note under the AVB protocol section for the intended per-protocol behavior
- ECN congestion marks: penalise score (−2 each, capped −20) **and** shown as `⚠  ECN: N congestion mark(s)` in Network Health section
- EEE: shown only when detected — absence is NOT reported (switch may not send LLDP, so absence ≠ disabled)
- Clock Sources: protocol label prominent; domain number only when multiple domains
- **pcap capture stats**: `cap.stats()` is called once per 5s cycle just before `print_report`; result passed as `Option<(u32, u32, u32)>` (received, dropped, if_dropped). Rendered at the bottom of Network Status, one counter per line under a `📦` group marker: `📦 N pkts received` / `N kernel drop(s)` / `N interface drop(s)` / `N parsed`. Each drop line turns **red only when its own counter is non-zero** (so the offending counter stands out), and a trailing red line then warns that loss/jitter figures may be understated. Both `dropped` (kernel ring buffer overflow) and `if_dropped` (NIC-level drops before pcap) are shown — both corrupt measurements equally. Offline replay has no `cap.stats()`, so only `📦 N parsed` is shown

---

## Network Health

`calculate_score(&mut self, streams, tcp_streams, ptp_domains, msrp_state, eee_ports)` sums `collect_penalties(..)` (same args). The table below is the authored source of every `ScorePenalty` that function emits — add a row here **and** an arm in `collect_penalties` together; both the score and the Health Summary bullet then follow automatically.

| Factor | Penalty |
|---|---|
| Packet loss per stream | −loss% capped at −10 |
| Jitter > 20 ms | −5/stream |
| Jitter 10–20 ms | −2/stream |
| Timestamp discontinuities | −3 × count, capped at 5/stream |
| SSRC change | −10/stream × changes, capped at 3 |
| Dead stream | −30/stream |
| Signal gap ≥ 2 events > 50ms (per 5s window) | −10/stream |
| TCP Degrading | −5/stream |
| TCP Critical | −15/stream |
| TCP Terminated | −25/stream |
| TCP retransmissions | −0.5 each, capped at −10 |
| DSCP wrong (per stream with violations) | −5/stream, capped at −20 |
| ECN congestion marks | −2 each, capped at −20 |
| IGMP querier absent (multicast active) | −10 |
| Multiple IGMP queriers on segment (multicast active) | −15 |
| PTP clock confirmed lost | −25/domain |
| PTP traffic seen, no grandmaster | −15/domain |
| PTP grandmaster changed | −10/domain × changes, capped at 3 |
| MSRP TalkerFailed (AVB) | −20/failed reservation |
| EEE active on switch port | −15/port, capped at −30 |

---

## Agent skills

### Issue tracker

Issues live in GitHub Issues for this repo. See `docs/agents/issue-tracker.md`.

### Triage labels

Default label vocabulary (needs-triage, needs-info, ready-for-agent, ready-for-human, wontfix). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout — one `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
