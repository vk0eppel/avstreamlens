# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Code Architecture

AVStreamLens is structured around protocol-specific modules (AES67, AVB, Dante, NDI, ST2110) with a central stream processing engine. Key components:
- `src/main.rs`: Entry point and protocol integration
- `src/protocols/`: Implementation for each supported AV protocol
- `src/analytics/`: Stream analysis algorithms
- `src/debug/`: Diagnostic tools and visualization
- `Cargo.toml`: Configuration for build and dependencies

## Common Commands

Build: `cargo build --release`
Test: `cargo test -- --test-threads=1`
Format: `cargo fmt`
Lint: `cargo clippy -- -D warnings`

## Development Notes

- Protocol implementations live in `src/protocols/protocol_name.rs`
- Add new analyzers in `src/analytics/` with corresponding unit tests
- Use `cargo doc` to generate API documentation
- The AGENTS.md file contains integration instructions for external systems