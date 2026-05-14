# CLAUDE.md

## Conventions
- Langage : Rust
- Framework : CLI
- Style : Default Rust Style

AVStreamLens processes audio/visual streaming over network protocols. Key components:
- `src/main.rs`: Entry point, CLI handling, protocol dispatcher
- `src/parser.rs`: Data parsing and deserialization for protocol-specific formats
- `src/protocols.rs`: Protocol interface and abstraction layer
- `src/stats.rs`: Stream statistics collection and reporting
- `src/report.rs`: Report generation and output formatting
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
- AES67/ST2110: Monitors PTPv2 (RFC 6188) grandmaster
- Dante: Monitors PTPv1 grandmaster
- AVB (gPTP): Monitors gPTP grandmaster via EtherType 0x88F7 (L2, no IP layer)
- PTP domains tracked per (domain, version) tuple — separates Dante PTPv1 from AES67/ST2110 PTPv2 on the same domain number
- Alerts show: GRANDMASTER DETECTED/CHANGED/LOST per protocol
- Protocol association via multicast IP (239.69.*=AES67, other 239.x.x.x=ST2110)
- PTP and IGMP are always monitored regardless of user protocol selection

