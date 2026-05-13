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
- Logging : timestamped `.log` files written on every run.

