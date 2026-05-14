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
- AVB (gPTP): Monitors gPTP grandmaster via EtherType 0x88F7 (L2, no IP layer)
- PTPv1 subdomain mapped to domain number: _DFLT→0, _ALT1→1, _ALT2→2, _ALT3→3
- PTP domains tracked per (domain, version) tuple — separates Dante PTPv1 from AES67/ST2110 PTPv2 on the same domain number
- Grandmaster detection fires on any PtpInfo with grandmaster_id set (PTPv2: Announce, PTPv1: Sync)
- Alerts show: GRANDMASTER DETECTED/CHANGED/LOST per protocol
- Clock loss detected via `PtpStats::check_timeout()` called from the 5-second report loop — NOT inside `update()`, which only runs on packet arrival and cannot detect silence
- Detection order: L2 AVB/gPTP → IGMP → SAP → mDNS → Dante control → NDI → UDP PTP → SRT → RIST → RTP gate → AES67 → ST2110 → Dante audio; UDP PTP must precede the RTP gate
- Protocol association via multicast IP (239.69.*=AES67, other 239.x.x.x=ST2110)
- PTP and IGMP are always monitored regardless of user protocol selection

