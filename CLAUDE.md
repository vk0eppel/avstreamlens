# CLAUDE.md

## Conventions
- Langage : Rust
- Framework : CLI
- Style : Default Rust Style

AVStreamLens processes audio/visual streaming over network protocols. Key components:
- `src/main.rs`: Entry point, capture loop, protocol dispatcher
- `src/cli.rs`: Interactive prompts — interface selection, protocol selection, BPF filter building
- `src/parser.rs`: Protocol detection and packet parsing (SDP, RTP, PTP, TCP)
- `src/protocols.rs`: Protocol enums, constants, and type definitions
- `src/stats.rs`: Stream statistics — RTP, TCP, PTP, network health
- `src/report.rs`: Terminal reporting and log file output
- `Cargo.toml`: Dependencies and build configuration

## Common Commands

Build: `cargo build --release`
Format: `cargo fmt`
Lint: `cargo clippy -- -D warnings`

## Development Notes

- Protocol implementations reside under `src/protocols.rs` (centralized)
- All modules follow the same pattern: parsing, analysis, reporting
- Use `cargo doc --open` to generate and view API documentation
- Check `src/main.rs` for CLI argument parsing and feature flags
- There is no test harness. Any new functionality added must be verified manually or by adding tests.
- Loopback and virtual interfaces (utun, awdl, docker, etc.) are filtered out of the interface list.
- Logging: timestamped `.log` files written on every run
- BPF filter is built dynamically from selected protocols
- RTP analysis: RFC 3550 jitter, sequence loss (16-bit wrapping), SSRC change detection, timestamp discontinuity detection
- PTP grandmaster detection tracks clock presence per protocol
- AES67/ST2110: Monitors PTPv2 (IEEE 1588-2008) grandmaster via UDP ports 319/320, multicast 224.0.1.129–132
- Dante: Monitors PTPv1 (IEEE 1588-2002) grandmaster via UDP ports 319/320; grandmaster detected from Sync body (bytes 50–55 grandmasterClockUuid, byte 61 stratum, bytes 62–65 identifier); PTPv1 layout auto-detected: if payload[4]=='_' → nibble-packed (hdr_shift=2), else separate-byte (hdr_shift=0)
- AVB (gPTP): Monitors gPTP grandmaster via EtherType 0x88F7 (L2, no IP layer); also captures MSRP (0x22EA) stream reservations and MVRP (0x88F5) VLAN registrations
- AVB BPF filter includes all three EtherTypes: 0x22F0 (AVTP), 0x22EA (MSRP), 0x88F5 (MVRP), 0x88F7 (gPTP)
- PTPv2 minimum payload lowered to 34 bytes (common header) — allows Sync (44b) and P_Delay (54b) to populate `ptp_domains`, not just Announce (64b)
- gPTP clock source display: ✓ grandmaster from Announce, ○ source EUI-64 from Sync when no Announce seen yet (`PtpStats::last_clock_id`), ❌ no traffic
- Clock quality is formatted as human-readable strings at parse time (`parser.rs`):
  - PTPv2: `ptp_class_str()` translates clock_class (e.g. class=6 → "Primary reference — locked"); `ptp_accuracy_str()` translates accuracy byte (e.g. 0x20 → "< 100 ns"); combined: `"Primary reference — locked  < 1 µs"`
  - PTPv1: stratum 1 → "Primary reference", 2 → "Secondary reference", N → "Stratum N"; 4-char ident appended (e.g. "GPS", "ATOM")
  - Key PTPv2 class values: 6=locked, 7=free-running, 135=holdover, 165=default, 187/255=slave-only
- PTPv1 subdomain mapped to domain number: _DFLT→0, _ALT1→1, _ALT2→2, _ALT3→3
- PTP domains tracked per (domain, version) tuple — separates Dante PTPv1 from AES67/ST2110 PTPv2 on the same domain number
- Grandmaster detection fires on any PtpInfo with grandmaster_id set (PTPv2: Announce ≥64b, PTPv1: Sync)
- Alerts show: GRANDMASTER DETECTED/CHANGED/LOST per protocol
- Clock loss detected via `PtpStats::check_timeout()` called from the 5-second report loop — NOT inside `update()`, which only runs on packet arrival and cannot detect silence
- Detection order: LLDP → MSRP → MVRP → AVTP/AVB → gPTP → IGMP → SAP → mDNS → Dante control → UDP PTP → RTP gate → **Dante audio** → AES67 → ST2110; Dante port check is before AES67/ST2110 so that multicast Dante streams (239.255.x.x) are not misclassified as ST2110
- Protocol association via multicast IP (239.69.*=AES67, other 239.x.x.x=ST2110)
- PTP, IGMP, SAP, and LLDP are always processed regardless of user protocol selection; all other protocols are gated by `AvProtocol::is_selected()` in `protocols.rs`
- BPF filter always includes `(ether proto 0x88cc)` (LLDP) for EEE detection, regardless of protocol selection
- BPF filter includes `tcp` for NDI (only protocol using TCP); `all_protocols_filter` also includes `tcp`
- Protocol selection is pre-expanded once before the capture loop (`expanded_protocols: Vec<ProtocolChoice>`) and passed to `is_selected()` on each detected packet
- Startup banner: `📡 Listening on en0  for AES67, Dante  (+ PTP, IGMP)  streams` — formatted by `cli::selected_protocol_display()`; for "all" selection shows `📡 Listening on en0  —  all protocols`; "Audio"/"Video" group choices show the group name, not the expanded sub-protocols; the redundant "Selected protocols:" line was removed
- UDP PTP protocol_kind labels: PTPv1 (Dante/IEEE 1588-2002) → `"PTPv1"`, PTPv2 (AES67/ST2110/IEEE 1588-2008) → `"PTPv2"`, L2 gPTP → `"AVB"` — version-based labels, not application-layer names
- SAP produces no console or log output — it enriches stream stats (clock_hz, ptime_ms, channels, sdp_name, expected_pt) and sets `clock_hz_confirmed = true` on existing entries; also populates `sdp_cache` for the ts-refclk cross-check
- SAP enrichment runs on existing stream entries (not just at creation): a stream detected before SAP arrives will be fully enriched when the announcement arrives — `clock_hz_confirmed`, `expected_pt`, `ptime_ms` are all updated retroactively
- ts-refclk cross-check: every 5s, for each active SDP session, `parse_ts_refclk()` (parser.rs) extracts the claimed PTP grandmaster EUI-64 and domain, then compares against `ptp_domains`; alerts on missing PTP traffic or grandmaster mismatch
- `parse_ts_refclk(s)` handles `ptp=IEEE1588-2008:<eui64>:<domain>` (PTPv2) and `ptp=IEEE1588-2002:<uuid>:<domain>` (PTPv1); normalizes to lowercase colon-separated bytes matching `PtpStats::last_grandmaster`
- Loopback (`lo`/`lo0`) is filtered from the interface list — macOS loopback uses DLT_NULL link-layer (4-byte BSD null header, no Ethernet frame), which is incompatible with the Ethernet-based packet parser; mDNS multicast also does not flow over loopback, so NDI discovery would never fire

## NDI Detection
- NDI uses dynamically assigned TCP ports — port-range matching is unreliable
- `ndi_sources: HashSet<Ipv4Addr>` in `main.rs` is populated from mDNS `_ndi._tcp` discovery packets
- `ndi_names: HashMap<Ipv4Addr, String>` stores source names extracted from mDNS DNS labels via `extract_ndi_name()` in `parser.rs`; source name shown in discovery alert and as stream label
- IP-based stream tracking: any TCP packet from/to a known NDI source IP is counted as NDI; `dst_ip` is set on stream entry so bitrate aggregation works
- NDI bitrate aggregated from all matching `tcp_streams` entries every 5s (summed by src/dst IP match)
- NDI TCP detection block is gated on `ndi_selected` (computed from `expanded_protocols`) — skipped entirely if NDI not in selection
- `detect_protocol` does NOT contain NDI TCP port-range detection — that path caused double-counting
- NDI on loopback does not work: DLT_NULL parser incompatibility + no mDNS multicast on lo0

## Protocol-Specific Health Monitoring

### AES67
- All RTP metrics: loss, jitter (RFC 3550), SSRC changes, timestamp discontinuities, bitrate, dead stream
- `clock_hz_confirmed` set at creation if SDP available, or retroactively when SAP arrives — gates TS discontinuity detection
- `expected_pt` from SDP `a=rtpmap` payload type; mismatches counted as `pt_mismatches`
- Signal gap detection (`gap_events`, `max_iat_ms`): fires when IAT > 50ms; both counters reset each 5s report cycle so count reflects the current window; alert says "Signal gap detected (N in last 5s, worst Xms)"
- PTP correction field (Sync/Follow_Up) stored in `PtpStats::last_offset_ns` (nanoseconds); alert if abs > 1µs
- DSCP EF=46 checked on every packet via `network_health.track_dscp()`
- Alert `⚑ Stream not announced (no SAP)` shown when stream active > 10 packets without SDP enrichment

### Dante
- All RTP metrics (same as AES67)
- Device name extracted from mDNS `_netaudio._udp` DNS labels via `extract_dante_name()` in `parser.rs`; stored in `dante_names: HashMap<Ipv4Addr, String>`
- `DanteKind::Discovery { device_name }` carries name through to main.rs dispatch
- Default `ptime_ms = 1.0` (Dante standard 48 samples at 48kHz) — not needed for gap detection (50ms threshold is fixed) but kept for timestamp discontinuity tolerance
- DSCP checked on every audio stream packet
- PTPv1 clock monitored (grandmaster via Sync body)
- Alert `⚠ Dante clock or subscription issue` for loss > 0% or jitter > 15ms

### NDI
- Packet count, dead stream, bitrate (aggregated from tcp_streams)
- TCP quality per flow (Healthy/Degrading/Critical/Terminated), retransmissions, RST/FIN
- Source name from mDNS `_ndi._tcp` DNS labels via `extract_ndi_name()` in `parser.rs`

### ST2110
- All RTP metrics (same as AES67)
- ST2110-20 video: `clock_hz_confirmed = true` immediately (90kHz is always correct per spec)
- ST2110-30 audio: default `ptime_ms = 1.0` enables burst detection without SDP
- Alert `⚠ Stream type unknown` when stream is classified as 2110-??

### mDNS name extraction (shared helper)
- `extract_mdns_instance_name(payload, service_needle)` in `parser.rs` finds the DNS-encoded service label and extracts the preceding instance name label (1–63 bytes, printable ASCII, longest match)
- Used by both `extract_dante_name()` (needle `\x09_netaudio`) and `extract_ndi_name()` (needle `\x04_ndi`)

## False Positive Prevention
- **Dante audio**: `is_likely_dante_audio` requires BOTH src AND dst ports in 5000–6000 (even); OR logic caused false positives when any app used a Dante-range source port with a high ephemeral destination
- **Multicast Dante**: Dante port check (`is_likely_dante_audio`) runs before the AES67/ST2110 multicast IP checks — Dante multicast uses 239.255.x.x which would otherwise match `is_st2110_multicast`

## EEE Detection (Energy Efficient Ethernet — IEEE 802.3az)
- EEE causes micro-bursting (switch holds packets during sleep, releases on wake-up ~4–16µs) — a common cause of unexplained jitter on AV networks
- Detected via LLDP (EtherType 0x88CC): the IEEE 802.3az EEE TLV (OUI 00-12-0F, subtype 0x05) advertises Tx/Rx wake-up times per port
- `parse_lldp_eee()` in `parser.rs` walks the LLDP TLV list; returns `AvProtocol::LldpEee` only when EEE TLV is present AND at least one wake-up time is non-zero
- `eee_ports: HashMap<(chassis_id, port_id), (tx_wake_us, rx_wake_us)>` in `main.rs` — alert printed on first detection per port
- Shown in health breakdown with per-port wake-up times; −15 pts/port in health score (capped at −30)
- Limitation: only detected if the switch sends LLDP and includes the EEE TLV; absence of detection does NOT confirm EEE is disabled

## AVB Extended Monitoring
- AVTP stream_id tracking: `avtp_streams: HashMap<[u8;8], AvtpStreamStats>` in `main.rs` — only populated when sv (stream_valid) bit is set in the AVTP header; stream_id = bytes 4–11 (6-byte source MAC + 2-byte unique ID)
- AVTP subtype decoded to human-readable name via `avtp_subtype_name()` in `protocols.rs`: 0x00=IEC 61883, 0x02=CRF, 0x03=CVF, 0x7E=MAAP, etc.; used in stream key ("AVB IEC 61883" not "AVB subtype=0x00")
- AVTP sequence loss: `AvtpStreamStats.last_seq` and `lost_frames` track byte 2 (8-bit wrapping counter) per stream_id; loss% shown per stream, alert on any drops
- AVTP bitrate: tracked per stream_id (`AvtpStreamStats.bitrate_bps`) and per subtype aggregate (`StreamStats.bytes_total`) from Ethernet frame sizes
- MSRP parsing (`parse_msrp` in parser.rs): walks MRP message list, extracts TalkerAdvertise (stream reserved, bandwidth, VLAN, priority), TalkerFailed (failure code), Listener (ready/failed state); `msrp_state: HashMap<[u8;8], MsrpDeclaration>` keyed by stream_id
- MVRP parsing (`parse_mvrp` in parser.rs): extracts VLAN IDs; `mvrp_vlans: HashSet<u16>` — presence confirms L2 VLAN QoS is active
- `avtp_streams` pruned after each report (2×timeout); `msrp_state` and `mvrp_vlans` not pruned (declarations persist until superseded)
- MSRP TalkerFailed alerts: printed immediately on detection with failure code (1=insufficient bandwidth, 2=insufficient bridge resources, 3=insufficient bandwidth for Traffic Class)

## Report Design (AV team audience)
- Target audience: AV engineers and technicians, not network admins — language and metrics are chosen accordingly
- Stream label format: `Protocol  "Name"  [codec]  —  IP:port` — protocol type always first, SAP name when available, IP:port as secondary reference
- Top-level status: `✓ All streams healthy` / `⚠ N issue(s)` shown after bandwidth line
- Alert language is plain English: "Audio glitch risk", "No signal for Xs", "check PTP lock", etc.
- Clock Sources section replaces technical "PTP Domains" — shows protocol association prominently, domain number only when multiple domains exist
- Health footer shows QoS/DSCP and IGMP querier only — ECN marks removed (sysadmin territory, not actionable for AV teams)
- Packet count removed from per-stream status line; loss %, jitter, and bitrate kept

## Capture Loop
- 5-second report block is at the TOP of the loop, before `cap.next_packet()` — ensures report fires even when pcap times out (no packets); `Err(_) => continue` on the read would otherwise skip the report entirely on quiet L2-only networks (e.g. AVB-only selection)

## Stream Lifecycle
- `streams` and `tcp_streams` are pruned after each 5s report: entries silent for >2×`STREAM_TIMEOUT_SECS` (20s) are removed; TCP flows with `StreamQuality::Terminated` are also removed immediately
- The 2× multiplier ensures a dead stream appears in at least one report with the "💀 No signal for Xs" alert before being dropped
- All protocol arms (including AVB) set `last_packet_time = Some(now)` on every packet so pruning applies uniformly
- `ptp_domains` and `sdp_cache` are never pruned: PTP domains are bounded by (domain, version) combinations; SDP cache is needed for ts-refclk cross-checks
- IGMP Join deduplication: `igmp_joins_seen: HashSet<(Ipv4Addr, Ipv4Addr)>` in `main.rs` suppresses repeated Join prints for the same (src, group); cleared on Leave so re-joins print again; Queries and Unknowns always print

## Network Health
- `calculate_score()` signature: `(&mut self, streams, tcp_streams, ptp_domains, msrp_state, eee_ports)` — all five are required
- `calculate_score()` also populates `packet_loss_streams`, `high_jitter_streams`, `aes67_discontinuities`
- IGMP querier absence penalizes score only when active multicast streams exist
- Bitrate (`bitrate_bps`) is computed by dividing byte delta by actual elapsed seconds — not assumed 1s — applies to both `StreamStats` and `TcpStreamStats`

### Health score penalty table

| Factor | Penalty |
|---|---|
| Packet loss per stream | −loss% capped at −10 |
| Jitter > 20 ms | −5/stream |
| Jitter 10–20 ms | −2/stream |
| Timestamp discontinuities | −3 × count, capped at 5/stream |
| SSRC change (source interrupted) | −10/stream × changes, capped at 3 |
| Dead stream (no signal) | −30/stream |
| TCP Degrading | −5/stream |
| TCP Critical | −15/stream |
| TCP Terminated | −25/stream |
| TCP retransmissions | −0.5 each, capped at −10 |
| QoS >50% untagged | −20 |
| QoS 10–50% untagged | −10 |
| QoS any untagged | −3 |
| ECN congestion marks | −2 each, capped at −20 |
| IGMP querier absent (multicast active) | −10 |
| PTP clock confirmed lost | −25/domain |
| PTP traffic seen, no grandmaster | −15/domain |
| PTP grandmaster changed | −10/domain × changes, capped at 3 |
| MSRP TalkerFailed (AVB) | −20/failed reservation |
| EEE active on switch port | −15/port, capped at −30 |

