# AGENTS.md — AVStreamLens

## Project Overview
Single-binary Rust CLI tool for live network capture and analysis of AV streaming protocols (AES67, ST2110, Dante, NDI, AVB, SRT, RIST, IGMP, PTP).

- **Edition**: Rust 2024
- **Structure**: `src/main.rs` is the only source file. No tests, no lib crate.
- **Dependencies**: `pcap`, `pnet_packet`, `chrono`

## Developer Commands
```bash
cargo build          # build
cargo run            # run (requires sudo for packet capture)
sudo cargo run       # actual usage — pcap needs root
cargo check          # fast compile-check
```
No test suite, linter, formatter, or CI config exists.

## Key Architecture Notes
- **Interactive CLI**: prompts user for network interface index, then protocol selection at startup.
- **PTP + IGMP are always monitored** regardless of user protocol selection.
- **BPF filter** is built dynamically from selected protocols; includes UDP, TCP (for NDI/SRT), AVB L2, PTP L2/UDP, and IGMP.
- **SAP/SDP parser** (RFC 2974/4566) enriches stream stats with session metadata (clock rate, ptime, channels).
- **RTP analysis**: RFC 3550 jitter, sequence loss (16-bit wrapping), SSRC change detection, timestamp discontinuity detection.
- **Logging**: timestamped `.log` files written to repo root on every run. `.gitignore` excludes `*.log`, `/target`, `Cargo.lock`.

## Gotchas
- **pcap requires root**: `cargo run` will fail at BPF filter application without sudo.
- **Loopback excluded**: `lo`/`lo0` and virtual interfaces (utun, awdl, docker, etc.) are filtered out of the interface list.
- **No tests**: there is no test harness. Any new functionality added must be verified manually or by adding tests.
