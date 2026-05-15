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
- PTPv1 subdomain mapped to domain number: _DFLT→0, _ALT1→1, _ALT2→2, _ALT3→3
- PTP domains tracked per (domain, version) tuple — separates Dante PTPv1 from AES67/ST2110 PTPv2 on the same domain number
- Grandmaster detection fires on any PtpInfo with grandmaster_id set (PTPv2: Announce ≥64b, PTPv1: Sync)
- Alerts show: GRANDMASTER DETECTED/CHANGED/LOST per protocol
- Clock loss detected via `PtpStats::check_timeout()` called from the 5-second report loop — NOT inside `update()`, which only runs on packet arrival and cannot detect silence
- Detection order: MSRP → MVRP → AVTP/AVB → gPTP → IGMP → SAP → mDNS → Dante control → UDP PTP → SRT → RIST → RTP gate → AES67 → ST2110 → Dante audio; UDP PTP must precede the RTP gate
- Protocol association via multicast IP (239.69.*=AES67, other 239.x.x.x=ST2110)
- PTP, IGMP, and SAP are always processed regardless of user protocol selection; all other protocols are gated by `AvProtocol::is_selected()` in `protocols.rs`
- BPF filter includes `tcp` for NDI (only protocol using TCP); `all_protocols_filter` also includes `tcp`
- Protocol selection is pre-expanded once before the capture loop (`expanded_protocols: Vec<ProtocolChoice>`) and passed to `is_selected()` on each detected packet
- Startup banner: `📡 Listening on en0  for AES67, Dante  (+ PTP, IGMP)  streams` — formatted by `cli::selected_protocol_display()`; for "all" selection shows `📡 Listening on en0  —  all protocols`; "Audio"/"Video" group choices show the group name, not the expanded sub-protocols; the redundant "Selected protocols:" line was removed
- UDP PTP protocol_kind labels: PTPv1 (Dante/IEEE 1588-2002) → `"PTPv1"`, PTPv2 (AES67/ST2110/IEEE 1588-2008) → `"PTPv2"`, L2 gPTP → `"AVB"` — version-based labels, not application-layer names
- SAP produces no console or log output — it silently enriches stream stats (clock_hz, ptime_ms, channels, sdp_name) and populates `sdp_cache` for the ts-refclk cross-check
- ts-refclk cross-check: every 5s, for each active SDP session, `parse_ts_refclk()` (parser.rs) extracts the claimed PTP grandmaster EUI-64 and domain, then compares against `ptp_domains`; alerts on missing PTP traffic or grandmaster mismatch
- `parse_ts_refclk(s)` handles `ptp=IEEE1588-2008:<eui64>:<domain>` (PTPv2) and `ptp=IEEE1588-2002:<uuid>:<domain>` (PTPv1); normalizes to lowercase colon-separated bytes matching `PtpStats::last_grandmaster`
- Loopback (`lo`/`lo0`) is filtered from the interface list — macOS loopback uses DLT_NULL link-layer (4-byte BSD null header, no Ethernet frame), which is incompatible with the Ethernet-based packet parser; mDNS multicast also does not flow over loopback, so NDI discovery would never fire

## NDI Detection
- NDI uses dynamically assigned TCP ports — port-range matching is unreliable
- `ndi_sources: HashSet<Ipv4Addr>` in `main.rs` is populated from mDNS `_ndi._tcp` discovery packets
- IP-based stream tracking: any TCP packet from/to a known NDI source IP is counted as NDI
- NDI TCP detection block is gated on `ndi_selected` (computed from `expanded_protocols`) — skipped entirely if NDI not in selection
- SRT and RIST match arms guard against both src AND dst being in `ndi_sources` — prevents NDI receiver→sender traffic from being misclassified (check both directions, not just src)
- `detect_protocol` does NOT contain NDI TCP port-range detection — that path caused double-counting
- NDI on loopback does not work: DLT_NULL parser incompatibility + no mDNS multicast on lo0

## False Positive Prevention
- **Dante audio**: `is_likely_dante_audio` requires BOTH src AND dst ports in 5000–6000 (even); OR logic caused false positives when any app used a Dante-range source port with a high ephemeral destination
- **RIST**: payload type must be exactly 33 (MPEG-TS); `pt >= 33` was too broad and matched NDI auxiliary traffic
- **SRT/RIST**: match arms in `main.rs` check `!ndi_sources.contains(&src) && !ndi_sources.contains(&dst)` — NDI receiver→sender UDP packets can accidentally match SRT (control bit pattern) or RIST (port + PT check)

## AVB Extended Monitoring
- AVTP stream_id tracking: `avtp_streams: HashMap<[u8;8], AvtpStreamStats>` in `main.rs` — only populated when sv (stream_valid) bit is set in the AVTP header; stream_id = bytes 4–11 (6-byte source MAC + 2-byte unique ID)
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
- `calculate_score()` signature: `(&mut self, streams, tcp_streams, ptp_domains, msrp_state)` — all four are required
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

