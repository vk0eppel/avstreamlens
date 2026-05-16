# CLAUDE.md

## Conventions
- Language: Rust  |  Framework: CLI  |  Style: Default Rust Style

## Key Components

| File | Purpose |
|---|---|
| `src/main.rs` | Entry point, capture loop, protocol dispatcher |
| `src/cli.rs` | Interface selection, protocol selection, BPF filter building |
| `src/parser.rs` | Protocol detection and packet parsing (SDP, RTP, PTP, AVTP, LLDP…) |
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
- No test harness — new functionality must be verified manually or by adding tests
- Logging: timestamped `.log` files written on every run in the working directory
- Bitrate computed as `byte_delta / elapsed_secs` — never assumed 1s exactly
- All modules follow the same pattern: parse → stats → report

### Protocol Dispatch
- Detection order (first match wins):
  `LLDP → MSRP → MVRP → AVTP/AVB → gPTP → IGMP → SAP → mDNS → Dante control → UDP PTP → RTP gate → **Dante audio** → AES67 → ST2110`
- **Dante audio runs before AES67/ST2110 IP checks** — Dante multicast (239.255.x.x) would otherwise match `is_st2110_multicast`
- **Always processed regardless of user selection**: PTP, IGMP, SAP, LLDP (`AvProtocol::is_selected()` returns true unconditionally for these)
- Protocol selection pre-expanded once: `expanded_protocols: Vec<ProtocolChoice>` computed before the loop
- BPF always includes `(ether proto 0x88cc)` (LLDP); `tcp` added for NDI; `all_protocols_filter` includes all EtherTypes + tcp
- Multicast IP association: 239.69.*=AES67, all other 239.x.x.x=ST2110
- UDP PTP `protocol_kind` labels: version-based not application-based — PTPv1 → `"PTPv1"`, PTPv2 → `"PTPv2"`, L2 gPTP → `"AVB"`

### Capture Loop & Stream Lifecycle
- **Report block is at the TOP of the loop**, before `cap.next_packet()` — so it fires even when pcap times out on quiet L2-only networks (e.g. AVB-only; `Err(_) => continue` would otherwise skip it)
- `streams` and `tcp_streams` pruned after each 5s report: silent >20s removed; TCP `Terminated` removed immediately
- `ptp_domains` and `sdp_cache` never pruned (bounded by design)
- `gap_events` and `max_iat_ms` reset after each report (per-window counters)
- All protocol arms set `last_packet_time = Some(now)` so pruning applies uniformly
- IGMP Join deduplication: `igmp_joins_seen: HashSet<(Ipv4Addr, Ipv4Addr)>` — cleared on Leave; Queries/Unknowns always print

### Interface Listing
- Filtered: `lo`/`lo0`, `utun*`, `awdl*`, `llw*`, `bridge*`, `vpn*`, `docker*`, `veth*`, `virbr*`, `ap1`, `anpi*` (iPhone USB), `gif*` (IPv6 tunnel), `stf*` (6to4 tunnel)
- `lo`/`lo0` excluded: macOS loopback uses DLT_NULL (4-byte BSD null header, no Ethernet frame) — incompatible with Ethernet parser; mDNS multicast also does not flow over loopback
- macOS port names via `macos_port_names()` → `networksetup -listallhardwareports`; IPv4 address shown; Enter selects interface 0 by default
- Startup banner: `📡 Listening on en0  for AES67, Dante  (+ PTP, IGMP)  streams` via `cli::selected_protocol_display()`

---

## Protocol Reference

### AES67
- **Transport**: UDP multicast 239.69.*
- **Detection**: `is_aes67_multicast(dst_ip)` after RTP version check
- **Clock**: PTPv2 via UDP ports 319/320; ts-refclk cross-check validates SDP-claimed grandmaster against wire
- **Health metrics**: loss (RFC 3550 seq), jitter (RFC 3550 EWMA), SSRC changes, TS discontinuities, signal gaps, payload type validation, DSCP EF=46
- `clock_hz_confirmed` gates TS discontinuity detection — set at stream creation if SDP found, or retroactively when SAP arrives
- `expected_pt` from SDP `a=rtpmap`; `pt_mismatches` counts mismatches per packet
- Signal gap: `gap_events` fires when IAT > 50ms; `max_iat_ms` tracks worst case; both reset per 5s window
- PTP correction field stored as `last_offset_ns` (nanoseconds, after ÷65536); alert if abs > 1µs
- Alert `⚑ Stream not announced (no SAP)` when >10 packets with no SDP enrichment

### Dante
- **Transport**: UDP unicast or multicast (239.255.x.x); discovery via mDNS `_netaudio._udp`
- **Detection**: `is_likely_dante_audio()` requires BOTH src AND dst ports in 5000–6000 (even) — prevents false positives from ephemeral source ports
- **Clock**: PTPv1 via UDP ports 319/320; grandmaster from Sync body (bytes 50–55 UUID, byte 61 stratum, bytes 62–65 ident); PTPv1 layout auto-detected: `payload[4]=='_'` → nibble-packed (hdr_shift=2), else separate-byte (hdr_shift=0); subdomain → domain: _DFLT=0, _ALT1=1, _ALT2=2, _ALT3=3
- **Device names**: extracted from mDNS DNS labels via `extract_dante_name()` (needle `\x09_netaudio`); stored in `dante_names: HashMap<Ipv4Addr, String>`; `DanteKind::Discovery { device_name }` carries name to dispatch
- **Health metrics**: all RTP metrics (same as AES67), DSCP checked on every audio packet
- Default `ptime_ms = 1.0` (48 samples at 48kHz) for TS discontinuity tolerance
- Alert `⚠ Dante clock or subscription issue` for loss > 0% or jitter > 15ms

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
- **Health metrics**: all RTP metrics (same as AES67), DSCP checked
- 2110-20 video: `clock_hz_confirmed = true` immediately (90kHz is always correct per spec, no SDP needed)
- 2110-30 audio: default `ptime_ms = 1.0` for TS discontinuity tolerance
- Alert `⚠ Stream type unknown` when classified as 2110-??

### AVB
- **Transport**: L2 Ethernet — AVTP (0x22F0), MSRP (0x22EA), MVRP (0x88F5), gPTP (0x88F7)
- **AVTP**: `avtp_streams: HashMap<[u8;8], AvtpStreamStats>` per stream_id (sv=1, bytes 4–11); subtype decoded via `avtp_subtype_name()` (0x00=IEC 61883, 0x02=CRF, 0x7E=MAAP…); sequence loss via byte 2 counter; bitrate from Ethernet frame sizes
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
- SAP silent — no console/log output; enriches stream stats: `clock_hz`, `ptime_ms`, `channels`, `sdp_name`, `expected_pt`, sets `clock_hz_confirmed = true`
- Enrichment is **retroactive**: runs on existing stream entries, so a stream seen before SAP arrives is fully updated on next announcement
- `sdp_cache: HashMap<session_id, SdpSession>` never pruned; needed for ts-refclk cross-check
- `parse_ts_refclk(s)` normalizes `ptp=IEEE1588-2008:<eui64>:<domain>` / `ptp=IEEE1588-2002:<uuid>:<domain>` to lowercase colon-separated bytes matching `PtpStats::last_grandmaster`

### IGMP
- Always monitored; `igmp_joins_seen` deduplicates Join prints per (src, group); Queries always printed
- Querier absence penalizes health score only when active multicast streams exist (>130s silence = −10 pts)

### LLDP / EEE
- LLDP (0x88CC) always in BPF filter regardless of protocol selection
- `parse_lldp_eee()` returns `AvProtocol::LldpEee` only when EEE TLV (OUI 00-12-0F, subtype 0x05) present AND wake-up time > 0
- `eee_ports: HashMap<(chassis_id, port_id), (tx_wake_us, rx_wake_us)>` — alert on first detection per port
- Limitation: absence of detection does NOT confirm EEE is disabled (switch may not send LLDP)

---

## Report Design
- **Audience**: AV engineers, not network admins — plain English alerts, no raw hex or packet counts
- Stream label: `Protocol  "Name"  [codec]  —  IP:port` (name from SAP/mDNS when available)
- Top-level status: `✓ All streams healthy` / `⚠ N issue(s)` / `– No streams detected`
- Per-stream: loss %, jitter ms, bitrate Mbps — no packet count
- Clock Sources section: protocol label prominent; domain number only when multiple domains
- Health footer: QoS/DSCP + IGMP querier — ECN removed from display (sysadmin metric; still penalizes score silently)

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
| Signal gap > 50ms (per 5s window) | −10/stream |
| TCP Degrading | −5/stream |
| TCP Critical | −15/stream |
| TCP Terminated | −25/stream |
| TCP retransmissions | −0.5 each, capped at −10 |
| QoS >50% untagged | −20 |
| QoS 10–50% untagged | −10 |
| QoS any untagged | −3 |
| ECN congestion marks | −2 each, capped at −20 *(score only, not shown)* |
| IGMP querier absent (multicast active) | −10 |
| PTP clock confirmed lost | −25/domain |
| PTP traffic seen, no grandmaster | −15/domain |
| PTP grandmaster changed | −10/domain × changes, capped at 3 |
| MSRP TalkerFailed (AVB) | −20/failed reservation |
| EEE active on switch port | −15/port, capped at −30 |
