# CLAUDE.md

## Conventions
- Language: Rust  |  Framework: CLI  |  Style: Default Rust Style

## Key Components

| File | Purpose |
|---|---|
| `src/main.rs` | Entry point — owns pcap handle, 5s report timer, post-dispatch IPv4/TCP tracking. Thin driver (~290 lines) |
| `src/capture.rs` | `CaptureState` + per-protocol handlers + `dispatch()` + `emit()` — all per-loop state and protocol-handler logic |
| `src/cli.rs` | Interface selection, protocol selection, BPF filter building |
| `src/parser.rs` | Top-level `detect_protocol` dispatcher + RTP + TCP + VLAN unwrap + multicast helpers; re-exports submodule API |
| `src/parser/sdp.rs` | SAP envelope (RFC 2974), SDP body (RFC 4566), `ts-refclk` normalisation |
| `src/parser/ptp.rs` | PTPv1 (IEEE 1588-2002) + PTPv2 (IEEE 1588-2008) message parser — used for both UDP PTP and L2 gPTP |
| `src/parser/avb.rs` | AVTP stream-id extraction + MSRP (802.1Qat) + MVRP (802.1Q) PDU parsers |
| `src/parser/lldp.rs` | LLDP TLV walker that surfaces the IEEE 802.3az EEE TLV |
| `src/parser/mdns.rs` | mDNS service-instance name extraction (Dante `_netaudio`, NDI `_ndi`) |
| `src/protocols.rs` | Enums, constants, type definitions |
| `src/stats.rs` | Stream statistics — RTP, TCP, PTP, network health score |
| `src/report.rs` | Terminal reporting and log file output |

## Common Commands

```
cargo build --release   # build
cargo fmt               # format
cargo clippy -- -D warnings  # lint
```

---

## Architecture

### General
- **Test harness**: 78 unit tests in `#[cfg(test)]` modules across `parser.rs` + `parser/{sdp,ptp,avb,lldp,mdns}.rs`, `stats.rs`, and `capture.rs` — run with `cargo test`. Each parser submodule keeps its own fixtures and tests. `capture.rs` tests exercise handlers with hand-built IP/UDP/RTP byte buffers (see `ip_udp_rtp()` helper); no pcap dependency in tests
- Logging: timestamped `.log` files written on every run in the working directory; `Logger::log()` flushes after every write so the last report survives SIGINT
- Bitrate computed as `byte_delta / elapsed_secs` — never assumed 1s exactly
- All modules follow the same pattern: parse → stats → report

### Parser Layout (`parser.rs` + `parser/`)
- **`parser.rs`** holds the `detect_protocol` dispatcher and only the small, shared bits: VLAN unwrap, multicast classification, RTP, TCP, the Dante port heuristic, ST2110 PT/port classifier. Submodules are declared with `pub mod ...` and their public functions are re-exported with `pub use ...::*` so external consumers (`main.rs`, `capture.rs`) keep using `crate::parser::parse_foo` regardless of which submodule `parse_foo` lives in
- **`parser/sdp.rs`** — SAP envelope (RFC 2974) → SDP body (RFC 4566); `parse_ts_refclk` normalises `ptp=IEEE1588-2008:<id>:<domain>` to colon-separated lowercase bytes matching `PtpStats::last_grandmaster`
- **`parser/ptp.rs`** — `parse_ptp` auto-detects PTPv1 vs PTPv2 from byte 1 low nibble; PTPv1 has two wire encodings (separate-byte vs nibble-packed) selected by byte 0 == 0x11
- **`parser/avb.rs`** — `parse_avtp_stream_id` (sv-bit guarded), `parse_msrp` (TalkerAdvertise/TalkerFailed/Listener), `parse_mvrp` (VLAN registration). MSRP/MVRP share the IEEE 802.1Q vector-attribute format
- **`parser/lldp.rs`** — TLV walker; emits `AvProtocol::LldpEee` only when the EEE TLV (OUI 00-12-0F, subtype 0x05) is present AND a wake-up time is non-zero
- **`parser/mdns.rs`** — `extract_mdns_instance_name` finds the DNS-label-encoded service needle, then walks length-prefixed labels backward to find the longest valid printable-ASCII instance name. Used by `extract_dante_name` (needle `\x09_netaudio`) and `extract_ndi_name` (needle `\x04_ndi`)
- **Adding a new protocol parser** = create `parser/<name>.rs`, declare `pub mod <name>;` in `parser.rs`, re-export its public functions with `pub use <name>::...`, add a branch in `detect_protocol`. Tests live in the same file as the parser

### Capture Module (`capture.rs`)
- **`CaptureState`** owns all per-loop HashMaps/HashSets (streams, tcp_streams, sdp_cache, ptp_domains, ndi_sources, ndi_names, dante_names, igmp_joins_seen, avtp_streams, msrp_state, mvrp_vlans, eee_ports), `network_health`, and `bytes_this_window`. `main.rs` holds exactly one `CaptureState` for the lifetime of the process
- **One `handle_*` method per protocol** (e.g. `handle_aes67`, `handle_dante`, `handle_ptp`). Each takes already-parsed inputs (`l2_payload: &[u8]`, `frame_bytes: u64`, `avtp_seq: Option<u8>`, `now: Instant`) — never a raw `pcap::Packet`. This is what makes handlers unit-testable
- **Handlers do not touch IO.** They mutate `CaptureState` and return `Vec<Alert>`. The dispatch layer prints + logs. The `PtpEvent` pattern in `stats.rs` is the same idea applied one layer deeper (data layer returns events; handler layer turns them into `Alert`s)
- **`Alert { level: AlertLevel, message: String }`** with constructors `Alert::info/good/warn/error`. `emit(&[Alert], &mut Logger)` maps level → ANSI color (none/32/33/31) and prints + logs in one place. Adding a new severity or alert format is a single-site change
- **`dispatch(state, proto, l2_payload, frame_bytes, avtp_seq, now, logger)`** is the only entry point `main.rs` calls per packet — matches `AvProtocol`, calls the right handler, emits returned alerts
- **`state.check_ptp_timeouts()` / `state.aggregate_ndi_bitrate()` / `state.reset_window()` / `state.ptp_requirement_met(&expanded)`** are the periodic-cycle helpers `main.rs` calls every 5s. Window-reset prunes silent streams via `STREAM_PRUNE_SECS = STREAM_TIMEOUT_SECS * 2` (named constant in `capture.rs`)
- **"Selected AND observed" rule** for clock requirements: `ptp_requirement_met` only requires a clock family when (a) the user's selection includes a protocol that uses it AND (b) at least one stream of that family has been observed (`state.streams.values().any(...)` or `!state.avtp_streams.is_empty()`). Without the "observed" gate, picking "All" on a pure-AES67 network warned about missing gPTP just because AVB was in the expanded set. Apply the same gate to any future requirement that depends on protocol selection
- Adding a new protocol = one new variant in `protocols::AvProtocol` + one new `handle_*` method + one new arm in `dispatch()`. No edits to `main.rs`

### Protocol Dispatch
- Detection order (first match wins):
  `LLDP → MSRP → MVRP → AVTP/AVB → gPTP → IGMP → SAP → mDNS → Dante control → UDP PTP → RTP gate → **Dante audio** → AES67 → ST2110`
- **Dante audio runs before AES67/ST2110 IP checks** — Dante multicast (239.255.x.x) would otherwise match `is_st2110_multicast`
- **Always processed regardless of user selection**: only LLDP/EEE (`AvProtocol::is_selected()` returns `true` unconditionally only for `LldpEee`)
- **Gated on protocol selection** via `is_selected()`:
  - PTP → AES67, ST2110, Dante, or AVB selected
  - IGMP → AES67, ST2110, or Dante selected (IP multicast protocols)
  - SAP → AES67 or ST2110 selected
  - All other protocols → gated by their own `ProtocolChoice` variant
- Protocol selection pre-expanded once: `expanded_protocols: Vec<ProtocolChoice>` computed before the loop
- The `should_process` guard is simply `proto.is_selected(&expanded_protocols)` — no hardcoded overrides remain
- BPF always includes `(ether proto 0x88cc)` (LLDP) and `(ether proto 0x88f7)` (gPTP); `tcp` added for NDI; `all_protocols_filter` includes all EtherTypes + tcp
- Multicast IP association: 239.69.*=AES67, all other 239.x.x.x=ST2110
- UDP PTP `protocol_kind` labels: version-based not application-based — PTPv1 → `"PTPv1"`, PTPv2 → `"PTPv2"`, L2 gPTP → `"AVB"`

### Capture Loop & Stream Lifecycle
- **Report block is at the TOP of the loop**, before `cap.next_packet()` — so it fires even when pcap times out on quiet L2-only networks (e.g. AVB-only; `Err(_) => continue` would otherwise skip it)
- `streams` and `tcp_streams` pruned after each 5s report: silent >20s removed; TCP `Terminated` removed immediately
- `ptp_domains` and `sdp_cache` never pruned (bounded by design)
- Per-window counters reset after each 5s report: `gap_events`, `max_iat_ms`, `pt_mismatches`, `dscp_violations`, `ssrc_changes` — alerts and score penalties reflect the current window, not the stream's lifetime
- All protocol arms set `last_packet_time = Some(now)` so pruning applies uniformly
- IGMP Join deduplication: `igmp_joins_seen: HashMap<(Ipv4Addr, Ipv4Addr), Instant>` — cleared on Leave; entries older than 5 minutes pruned each report cycle (handles hosts that disappear without sending Leave); Queries/Unknowns always print
- **VLAN-tagged frames**: `unwrap_vlan()` in `parser.rs` peels 802.1Q / 802.1ad / QinQ tags before dispatch — L2 AVB protocols work on tagged networks. No VLAN-ID filtering is implemented; the app processes whatever VLANs the capture interface receives. Operator-facing guidance (trunk vs access vs SPAN, macOS tag-stripping, QinQ caveat) lives in README.md under "Capture Setup — Monitoring One or Multiple VLANs"

### Interface Listing
- Filtered: `lo`/`lo0`, `utun*`, `awdl*`, `llw*`, `bridge*`, `vpn*`, `docker*`, `veth*`, `virbr*`, `ap1`, `anpi*` (iPhone USB), `gif*` (IPv6 tunnel), `stf*` (6to4 tunnel)
- `lo`/`lo0` excluded: macOS loopback uses DLT_NULL (4-byte BSD null header, no Ethernet frame) — incompatible with Ethernet parser; mDNS multicast also does not flow over loopback
- macOS port names via `macos_port_names()` → `networksetup -listallhardwareports`; IPv4 address shown; Enter selects interface 0 by default
- Startup banner via `cli::selected_protocol_display()` — e.g. `📡 Listening on en0  for AES67, Dante  (+ PTP, IGMP)  streams`; the `(+ PTP, IGMP)` suffix is shown only when those protocols are relevant to the selection

---

## Protocol Reference

### AES67
- **Transport**: UDP multicast 239.69.*
- **Detection**: `is_aes67_multicast(dst_ip)` after RTP version check
- **Clock**: PTPv2 via UDP ports 319/320; ts-refclk cross-check validates SDP-claimed grandmaster against wire
- **Health metrics**: loss (RFC 3550 seq, signed-delta — backward/reorder ignored), jitter (RFC 3550 EWMA, sign-preserving), SSRC changes, TS discontinuities, signal gaps, payload type validation, DSCP EF(46) per-stream
- `clock_hz_confirmed` gates TS discontinuity detection — set at stream creation if SDP found, or retroactively when SAP arrives
- `expected_pt` from SDP `a=rtpmap`; `pt_mismatches` counts mismatches per packet within the 5s window
- Signal gap: `gap_events` fires when IAT > 50ms; alert requires **≥2 events per 5s window** (single spike = pcap scheduling noise); `max_iat_ms` tracks worst case; both reset per 5s window
- PTP correction field stored as `last_offset_ns` (nanoseconds, after ÷65536); alert if abs > 1µs
- Alert `⚠ Stream not announced (no SAP)` when >10 packets with no SDP enrichment (AES67/Dante/ST2110 only — AVB/NDI never have SDP)

### Dante
- **Transport**: UDP unicast or multicast (239.255.x.x); discovery via mDNS `_netaudio._udp`
- **Detection**: `is_likely_dante_audio()` requires BOTH src AND dst ports in 5000–6000 (even) — prevents false positives from ephemeral source ports
- **Clock**: PTPv1 via UDP ports 319/320; grandmaster from Sync body (bytes 50–55 UUID, byte 61 stratum, bytes 62–65 ident); PTPv1 layout auto-detected by **`payload[0]`**: `0x11` → nibble-packed (hdr_shift=2), else separate-byte (hdr_shift=0); subdomain → domain: _DFLT=0, _ALT1=1, _ALT2=2, _ALT3=3
- **Device names**: extracted from mDNS DNS labels via `extract_dante_name()` (needle `\x09_netaudio`); stored in `dante_names: HashMap<Ipv4Addr, String>`; `DanteKind::Discovery { device_name }` carries name to dispatch
- **Health metrics**: all RTP metrics (same as AES67), DSCP EF(46) checked per packet
- `requires_valid_ptp_clock()` returns `true` for Dante — "no clock source" warning fires if PTPv1 disappears
- Default `ptime_ms = 1.0` (48 samples at 48kHz) for TS discontinuity tolerance
- Alert `⚠ Dante clock or subscription issue` for loss > **0.1%** or jitter > 15ms (0% threshold caused false positives from pcap scheduling noise)

### NDI
- **Transport**: TCP (dynamic ports 5960–5980); discovery via mDNS `_ndi._tcp`
- **Detection**: IP-based — `ndi_sources: HashSet<Ipv4Addr>` populated from mDNS; any TCP to/from a known IP counted; port-range matching removed (caused double-counting)
- **Source names**: `extract_ndi_name()` (needle `\x04_ndi`); stored in `ndi_names: HashMap<Ipv4Addr, String>`; `NdiKind::Discovery { source_name }` carries name
- **Health metrics**: packet count, dead stream, bitrate (aggregated from `tcp_streams` by IP match every 5s), TCP quality (Healthy/Degrading/Critical/Terminated), retransmissions, RST/FIN
- NDI stream `dst_ip` is set so bitrate aggregation loop can match it
- NDI TCP detection gated on `ndi_selected`; loopback unsupported (DLT_NULL + no mDNS multicast)
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
- **Transport**: L2 Ethernet — AVTP (0x22F0), MSRP (0x22EA), MVRP (0x88F5), gPTP (0x88F7)
- **AVTP**: `avtp_streams: HashMap<[u8;8], AvtpStreamStats>` per stream_id (sv=1, bytes 4–11); subtype decoded via `avtp_subtype_name()` (0x00=IEC 61883, 0x02=CRF, 0x7E=MAAP…); sequence loss via `AvtpStreamStats::update_seq()` on byte 2 counter (8-bit wrap-safe, signed-i8 reorder filter mirrors the RTP fix); bitrate from Ethernet frame sizes
- **MSRP**: `parse_msrp()` extracts TalkerAdvertise (bandwidth, VLAN, priority), TalkerFailed (failure code), Listener state; `msrp_state: HashMap<[u8;8], MsrpDeclaration>`; TalkerFailed alert immediate with code (1=bandwidth, 2=bridge resources, 3=traffic class)
- **MVRP**: `parse_mvrp()` extracts VLAN IDs; `mvrp_vlans: HashSet<u16>` — presence confirms L2 VLAN QoS; alert if AVTP active but no MVRP
- `avtp_streams` pruned per cycle; `msrp_state` and `mvrp_vlans` not pruned

### mDNS name extraction (shared)
- `extract_mdns_instance_name(payload, needle)` in `parser.rs`: finds DNS-label-encoded service, extracts preceding instance name (1–63 bytes, printable ASCII, longest match)
- Used by `extract_dante_name()` (needle `\x09_netaudio`) and `extract_ndi_name()` (needle `\x04_ndi`)

---

## Shared Infrastructure

### PTP / Clock Sources
- Domains keyed by `(domain, version)` — separates Dante PTPv1 from AES67/ST2110 PTPv2 on same domain number
- PTPv2 minimum: 34 bytes (common header) — allows Sync (44b) and P_Delay (54b) to create domain entries, not just Announce (64b)
- Grandmaster detected from Announce (PTPv2 ≥64b) or Sync body (PTPv1); alerts: DETECTED / CHANGED / LOST
- Clock loss via `PtpStats::check_timeout()` in the 5s report loop — **not in `update()`** which only runs on packet arrival
- gPTP display: ✓ grandmaster from Announce, ○ clock source EUI-64 from Sync (`last_clock_id`), ❌ no traffic
- Clock quality formatted at parse time: PTPv2 class → `ptp_class_str()` (6=locked, 7=free-running, 135=holdover, 165=default, 187/255=slave-only) + `ptp_accuracy_str()` (e.g. 0x20=< 100ns); PTPv1 stratum + ident (GPS, ATOM…)
- Correction field stored as nanoseconds (`÷ 65536`); shown in Clock Sources if non-zero; alert if abs > 1µs
- `ts-refclk` cross-check: every 5s, `parse_ts_refclk()` extracts claimed grandmaster EUI-64+domain from SDP and compares against active `ptp_domains`

### SAP / SDP
- SAP processed only when AES67 or ST2110 is selected — no other protocol uses SDP announcements
- SAP silent — no console/log output; enriches stream stats: `clock_hz`, `ptime_ms`, `channels`, `sdp_name`, `expected_pt`, sets `clock_hz_confirmed = true`
- Enrichment is **retroactive**: runs on existing stream entries, so a stream seen before SAP arrives is fully updated on next announcement
- `sdp_cache: HashMap<session_id, SdpSession>` never pruned; needed for ts-refclk cross-check
- `parse_ts_refclk(s)` normalizes `ptp=IEEE1588-2008:<eui64>:<domain>` / `ptp=IEEE1588-2002:<uuid>:<domain>` to lowercase colon-separated bytes matching `PtpStats::last_grandmaster`

### IGMP
- Processed only when AES67, ST2110, or Dante is selected (IP multicast protocols); suppressed for NDI-only and AVB-only
- `igmp_joins_seen` deduplicates Join prints per (src, group); Queries always printed
- Querier absence penalizes health score only when active multicast streams exist (>130s silence = −10 pts)
- `igmp_query_interval_secs` tracks detected interval between consecutive queries — shown in footer as `(interval Xs)`

### LLDP / EEE
- LLDP (0x88CC) always in BPF filter regardless of protocol selection
- `parse_lldp_eee()` returns `AvProtocol::LldpEee` only when EEE TLV (OUI 00-12-0F, subtype 0x05) present AND wake-up time > 0
- `eee_ports: HashMap<(chassis_id, port_id), (tx_wake_us, rx_wake_us)>` — alert on first detection per port
- Limitation: absence of detection does NOT confirm EEE is disabled (switch may not send LLDP)

---

## Report Design
- **Audience**: AV engineers, not network admins — plain English alerts, no raw hex or packet counts
- **Report header**: cyan rule line + `AVStreamLens  ·  <timestamp>` + rule line — separates successive 5-second reports
- **Four sections** (all use cyan `\x1b[36m` header + emoji); log file output matches console exactly:
  1. Overview — bandwidth + stream count summary + `✓/⚠/–` status line
  2. `📡 Streams:` — unified list of all active streams (AES67, Dante, ST2110, NDI, AVB), no blank lines between entries
  3. `🕐 Clock Sources:` — PTP domains (conditional)
  4. `🔬 Network Health — X%:` — health score + QoS/DSCP + IGMP querier + EEE
- Stream entry format: `  ▸ Protocol  "Name"  [codec]  —  IP:port` / `    metrics line` / `    ⚠  alerts`
  - RTP streams (AES67/Dante/ST2110): metrics = `loss: X%  |  jitter: X ms  |  X Mbps`
  - NDI: metrics = `quality  |  X Mbps  |  retrans: N` (TCP quality, no RTP metrics)
  - AVB: metrics = `loss: X%  |  X Mbps` + MSRP/VLAN reservation state inline
- DSCP: validated **per stream** against protocol-appropriate expected values; alert inline in Streams section when wrong; footer shows summary across all streams
  - AES67 / Dante / ST2110-30 audio / ST2110-40 anc: EF (46) required
  - ST2110-20 video: EF (46), CS5 (40), or AF41 (34) accepted
  - NDI / AVB: no DSCP check (TCP / Layer 2)
- ECN congestion marks: penalise score (−2 each, capped −20) **and** shown as `⚠  ECN: N congestion mark(s)` in Network Health section
- EEE: shown only when detected — absence is NOT reported (switch may not send LLDP, so absence ≠ disabled)
- Clock Sources: protocol label prominent; domain number only when multiple domains

---

## Network Health

`calculate_score(&mut self, streams, tcp_streams, ptp_domains, msrp_state, eee_ports)`

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
| PTP clock confirmed lost | −25/domain |
| PTP traffic seen, no grandmaster | −15/domain |
| PTP grandmaster changed | −10/domain × changes, capped at 3 |
| MSRP TalkerFailed (AVB) | −20/failed reservation |
| EEE active on switch port | −15/port, capped at −30 |
