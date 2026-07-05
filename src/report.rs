// AVStreamLens — src/report.rs
// Reporting and output formatting for stream monitoring results.

use chrono::{Datelike, Timelike, Local};

/// Wrap `text` in an ANSI colour escape when colour output is enabled.
/// `code` is the SGR code string, e.g. `"36"` for cyan, `"33"` for yellow.
/// When colour is disabled the text is returned unchanged.
#[inline]
fn ansi(code: &str, text: &str) -> String {
    if crate::color_enabled() {
        format!("\x1b[{}m{}\x1b[0m", code, text)
    } else {
        text.to_string()
    }
}

// Whether report-body lines are written to stdout. Always true except during a
// quiet-mode healthy cycle, when `print_report` sets it false so the report goes
// to the log file only (the documented `--quiet` contract). Thread-local, mirror
// of the `COLOR` global — set once at the top of `print_report`, restored at the
// end. The log file always receives every line regardless of this flag.
thread_local! {
    static STDOUT_ENABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}
fn stdout_enabled() -> bool { STDOUT_ENABLED.with(|c| c.get()) }
fn set_stdout_enabled(v: bool) { STDOUT_ENABLED.with(|c| c.set(v)); }

/// Log `text` to the file and print it coloured to stdout. The single place
/// `report.rs` pairs file and console output — every report section used to
/// repeat this same `logger.log(&x); println!("{}", ansi(c, &x));` pair at
/// each call site.
#[inline]
fn emit_line(logger: &mut Logger, color: &str, text: &str) {
    logger.log(text);
    if stdout_enabled() { println!("{}", ansi(color, text)); }
}

/// Log + print an uncoloured line (the no-colour sibling of `emit_line`).
#[inline]
fn plain_line(logger: &mut Logger, text: &str) {
    logger.log(text);
    if stdout_enabled() { println!("{}", text); }
}

/// Leading indent for a section's top-level entries (`▸ Name`, `Bandwidth: ...`).
/// Shared across Discovered, Clock Sources, Streams, and Network Status so the
/// left margin doesn't shift when scanning a report top to bottom.
const ENTRY_INDENT: &str = "  ";

/// Leading indent for a sub-line under an entry (metrics, alerts, detail rows).
const DETAIL_INDENT: &str = "    ";

/// Wrap a section's top-level entry line in `ENTRY_INDENT`.
fn status_entry(text: &str) -> String {
    format!("{}{}", ENTRY_INDENT, text)
}

/// Wrap a section's sub-line (metrics, alerts, detail rows) in `DETAIL_INDENT`.
fn status_detail(text: &str) -> String {
    format!("{}{}", DETAIL_INDENT, text)
}

/// One line of report body content, decoupled from the act of writing it.
/// Lets a report section be a pure `(data slice) -> Vec<RenderedLine>` function
/// that a test can call directly and assert on, with no stdout/log capture.
/// `color` is `None` for an uncoloured line (the `plain_line` case), `Some(code)`
/// for a coloured one (the `emit_line` case) — log text and display text are
/// always identical for body content (verified true for every line in Clock
/// Sources/Streams/Network Status; only section *headers* and the two lines
/// documented in CLAUDE.md diverge, and those stay outside this mechanism).
#[derive(Debug, PartialEq, Eq, Clone)]
struct RenderedLine {
    text: String,
    color: Option<&'static str>,
}

impl RenderedLine {
    fn plain(text: String) -> Self {
        Self { text, color: None }
    }

    fn colored(color: &'static str, text: String) -> Self {
        Self { text, color: Some(color) }
    }
}

/// Write every line to the log file and console — the one emit step every
/// deepened report section funnels through, sibling to `emit_line`/`plain_line`.
fn emit_lines(lines: &[RenderedLine], logger: &mut Logger) {
    for line in lines {
        match line.color {
            Some(c) => emit_line(logger, c, &line.text),
            None    => plain_line(logger, &line.text),
        }
    }
}

/// Write a section header: plain text to the log, emoji + cyan to the console.
/// The one place the documented header log≠print divergence is handled, shared
/// across Discovered/AVDECC/Clock Sources/Streams/Network Status.
fn section_header(logger: &mut Logger, plain_label: &str, decorated_label: &str) {
    logger.log(&format!("\n{}", plain_label));
    if stdout_enabled() { println!("{}", ansi("36", &format!("\n{}", decorated_label))); }
}
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::stats::{AvdeccEntity, ConmonDevice, StreamDiagnostic, StreamStats, TcpStreamStats, PtpStats, NetworkHealth, StreamQuality, AvtpStreamStats};
use crate::parser::{fmt_eui64, media_type_summary, sr_class_str};
use crate::protocols::{STREAM_TIMEOUT_SECS, MsrpDeclaration, MsrpDeclType, PTP_VERSION_V1, TransmitterConfidence, TransmitterVerdict, avtp_subtype_name, msrp_failure_reason};
use crate::capture::{Alert, emit as emit_alerts, MissingClock, MissingClockKind};

/// Everything one report cycle (one Window) needs to render, gathered behind a
/// single borrow. Built by `do_report` via `from_state`-style assembly and
/// consumed by `print_report`. All fields are borrows from the live
/// `CaptureState` plus the locally-computed section diagnostics — zero copies,
/// valid only for the stack frame that builds it.
///
/// This is also the natural unit to serialize for JSON output (see TODO): a
/// `#[derive(Serialize)]` here would not couple the serializer to the live
/// capture state.
///
/// `Copy`: every field is a shared borrow or a scalar, so the snapshot is
/// trivially copyable — `print_report` destructures it in place.
#[derive(Clone, Copy)]
pub struct ReportSnapshot<'a> {
    pub streams:        &'a HashMap<String, StreamStats>,
    pub tcp_streams:    &'a HashMap<String, TcpStreamStats>,
    pub ptp_domains:    &'a HashMap<(u8, u8), PtpStats>,
    pub missing_ptp:    &'a [MissingClock],
    pub health:         &'a NetworkHealth,
    pub bytes_this_window: u64,
    pub eee_ports:      &'a HashMap<(String, String), (u16, u16)>,
    pub dante:          DanteSnapshot<'a>,
    pub avb:            AvbSnapshot<'a>,
    pub ndi_sources:    &'a HashSet<Ipv4Addr>,
    pub ndi_names:      &'a HashMap<Ipv4Addr, String>,
    pub pause_frames:   u64,
    pub pfc_frames:     u64,
    pub pcap_stats:     Option<(u32, u32, u32)>,
    pub packets_dispatched: u64,
    pub periodic_alerts: PeriodicAlerts<'a>,
    // Set when PTP clock loss and stream packet loss are correlated in the same
    // window. Suppresses the individual "no clock" and per-stream loss alerts
    // so the combined dropout alert (already emitted by emit_periodic_alerts)
    // dominates.
    pub clock_dropout_correlated: bool,
}

impl<'a> ReportSnapshot<'a> {
    /// Assemble the snapshot from `&CaptureState` plus the `WindowChecks` bundle
    /// `CaptureState::end_of_window` returns and the one value neither can supply
    /// (`pcap_stats`, read from `cap.stats()` by the caller). Previously `do_report`
    /// hand-built the ~35-line struct literal itself, which had to be kept in sync
    /// with this struct's field list by hand — this constructor is the one place
    /// that assembly logic lives now.
    pub fn from_state(
        state: &'a crate::capture::CaptureState,
        checks: &'a crate::capture::WindowChecks,
        pcap_stats: Option<(u32, u32, u32)>,
    ) -> Self {
        ReportSnapshot {
            streams: &state.streams,
            tcp_streams: &state.tcp_streams,
            ptp_domains: &state.ptp.domains,
            missing_ptp: &checks.missing_ptp,
            health: &state.network_health,
            bytes_this_window: state.bytes_this_window,
            eee_ports: &state.eee_ports,
            dante: DanteSnapshot {
                sources: &state.dante.sources,
                names: &state.dante.names,
                conmon: &state.dante.conmon,
                unverified: &checks.dante_unverified,
            },
            avb: AvbSnapshot {
                avtp_streams: &state.avb.avtp_streams,
                msrp_state: &state.avb.msrp_state,
                mvrp_vlans: &state.avb.mvrp_vlans,
                avdecc_entities: &state.avb.avdecc_entities,
            },
            ndi_sources: &state.ndi.sources,
            ndi_names: &state.ndi.names,
            pause_frames: state.pause_frames_this_window,
            pfc_frames: state.pfc_frames_this_window,
            pcap_stats,
            packets_dispatched: state.packets_dispatched,
            periodic_alerts: PeriodicAlerts {
                ip_config: &checks.ip_config_alerts,
                conmon_bridge: &checks.conmon_bridge_alerts,
                follower_census: &checks.follower_census_alerts,
                ptp_sync: &checks.ptp_sync_alerts,
            },
            clock_dropout_correlated: state.clock_dropout_correlated,
        }
    }
}

/// Dante-only fields, mirroring `CaptureState`'s `dante: DanteState` substate
/// (see CLAUDE.md Capture Module section) — the report-side view of the same
/// grouping, rather than 4 fields flattened into `ReportSnapshot` alongside
/// everything else.
#[derive(Clone, Copy)]
pub struct DanteSnapshot<'a> {
    pub sources:    &'a HashSet<Ipv4Addr>,
    pub names:      &'a HashMap<Ipv4Addr, String>,
    pub conmon:     &'a HashMap<Ipv4Addr, ConmonDevice>,
    pub unverified: &'a HashSet<Ipv4Addr>,
}

/// AVB-only fields, mirroring `CaptureState`'s `avb: AvbState` substate.
#[derive(Clone, Copy)]
pub struct AvbSnapshot<'a> {
    pub avtp_streams:    &'a HashMap<[u8; 8], AvtpStreamStats>,
    pub msrp_state:      &'a HashMap<[u8; 8], MsrpDeclaration>,
    pub mvrp_vlans:      &'a HashSet<u16>,
    pub avdecc_entities: &'a HashMap<[u8; 8], AvdeccEntity>,
}

/// Section-level diagnostics computed once per cycle in `do_report` and
/// rendered inline in their target sections (Discovered / Clock Sources).
#[derive(Clone, Copy)]
pub struct PeriodicAlerts<'a> {
    pub ip_config:       &'a [Alert],
    pub conmon_bridge:   &'a [Alert],
    pub follower_census: &'a [Alert],
    pub ptp_sync:        &'a [Alert],
}

/// Session-lifetime report config — distinct from the per-Window `ReportSnapshot`.
/// `quiet` is a CLI flag fixed for the Session; `no_flows_diagnostic_shown` is a
/// latch set the first time the no-active-flows diagnostic fires so it does not
/// repeat. Owned by `run_loop`, mutably threaded into `print_report`.
pub struct ReportSession {
    pub quiet: bool,
    pub no_flows_diagnostic_shown: bool,
}

/// Logger for writing timestamped messages to both file and console.
#[derive(Debug)]
pub struct Logger {
    file: std::fs::File,
}

/// Create a file at `path`, failing (rather than following or truncating) if
/// anything already exists there. `create_new` maps to `O_CREAT | O_EXCL`, which
/// refuses an existing path including a symlink; on Unix `O_NOFOLLOW` is added as
/// belt-and-suspenders. This matters because live capture runs as root and the log
/// is created in the current working directory, which may be attacker-writable — a
/// plain `File::create` would follow a planted symlink and truncate its target.
fn open_exclusive(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

impl Logger {
    /// Create a new logger with a filename based on protocol prefix and timestamp.
    /// The file is opened exclusively (never following a symlink or truncating an
    /// existing file — see `open_exclusive`); on the rare name collision a few
    /// randomized suffixes are tried before giving up.
    pub fn new(prefix: &str) -> std::io::Result<Self> {
        let now = Local::now();
        let base = format!(
            "avstreamlens_{}-{:02}-{:02}_{:02}-{:02}-{:02}_{}",
            now.year(), now.month(), now.day(), now.hour(), now.minute(), now.second(), prefix
        );
        for attempt in 0..8u32 {
            let filename = if attempt == 0 {
                format!("{base}.log")
            } else {
                let salt = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(attempt) ^ attempt;
                format!("{base}_{:05x}.log", salt & 0xF_FFFF)
            };
            match open_exclusive(std::path::Path::new(&filename)) {
                Ok(file) => return Ok(Logger { file }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not create a unique log file",
        ))
    }

    /// A throwaway `Logger` backed by a temp file, for tests elsewhere in the
    /// crate that need a `&mut Logger` but don't care about its contents (e.g.
    /// `main.rs`'s `process_packet` tests, which exercise `dispatch()`).
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        let path = std::env::temp_dir().join(format!(
            "avsl_test_logger_{}_{}.log",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        ));
        Logger { file: std::fs::File::options().read(true).write(true).create(true).truncate(true).open(&path).unwrap() }
    }

    /// Log a message to the file. Flushes immediately so the last lines
    /// survive a crash or SIGINT.
    pub fn log(&mut self, message: &str) {
        use std::io::Write;
        let _ = writeln!(self.file, "{}", message);
        let _ = self.file.flush();
    }

}

/// Create a new logger
pub fn create_logger(prefix: &str) -> std::io::Result<Logger> {
    Logger::new(prefix)
}

/// Count active Dante transmit flows sourced by `device_ip`: every entry in the
/// stream map whose src_ip matches and whose protocol is Dante — unicast and
/// multicast, RTP- and ATP-framed. Map pruning (silent > 20s) is the liveness
/// filter, so streams already pruned are not counted. A passive approximation of
/// Dante Controller's "Transmit Flows" — understated when unicast flows are not
/// visible (no Mirror Port).
pub fn dante_tx_flow_count(
    streams: &HashMap<String, StreamStats>,
    device_ip: std::net::Ipv4Addr,
) -> usize {
    streams.values()
        .filter(|s| s.protocol == "Dante" && s.src_ip == Some(device_ip))
        .count()
}

/// `  (N tx flows)` suffix for a device line, empty when the device sources none.
fn tx_flow_suffix(streams: &HashMap<String, StreamStats>, device_ip: std::net::Ipv4Addr) -> String {
    match dante_tx_flow_count(streams, device_ip) {
        0 => String::new(),
        n => format!("  ({} tx flows)", n),
    }
}

/// Inline Transmitter Class tag for a Dante stream line, e.g. `  ·  DVS (confirmed)`.
/// A confirmed verdict (control-plane fingerprint) reads differently from an
/// inferred one; a DSCP-only hint reads weakest. Multi-signal inferred verdicts
/// surface the supporting signal count. Empty when there is no verdict.
fn transmitter_tag(verdict: Option<TransmitterVerdict>) -> String {
    let Some(v) = verdict else { return String::new() };
    let conf = match v.confidence {
        TransmitterConfidence::Confirmed => "confirmed".to_string(),
        TransmitterConfidence::Inferred if v.signals > 1 => format!("likely, {} signals", v.signals),
        TransmitterConfidence::Inferred => "likely".to_string(),
        TransmitterConfidence::Hint => "possible — no QoS marking".to_string(),
    };
    format!("  ·  {} ({})", v.class.label(), conf)
}

struct DiscoveryInputs<'a> {
    dante_sources: &'a HashSet<std::net::Ipv4Addr>,
    dante_names:   &'a HashMap<std::net::Ipv4Addr, String>,
    dante_conmon:  &'a HashMap<std::net::Ipv4Addr, ConmonDevice>,
    dante_unverified: &'a HashSet<std::net::Ipv4Addr>,
    ndi_sources:   &'a HashSet<std::net::Ipv4Addr>,
    ndi_names:     &'a HashMap<std::net::Ipv4Addr, String>,
    dante_active: usize,
    ndi_active: usize,
    streams: &'a HashMap<String, StreamStats>,
}

/// Render the `📇 Discovered` section: devices learned from multicast mDNS and
/// Dante ConMon. One line per device; unverified devices shown inline with ⚠
/// prefix. Returns `None` when there is nothing to show — mirrors
/// `render_clock_sources`'s "no header when empty" rule. The no-active-flows
/// diagnostic is session state (must show at most once per run), so it's
/// threaded in as `&mut bool` rather than folded into the immutable inputs.
fn render_discovery(inputs: &DiscoveryInputs, no_flows_diagnostic_shown: &mut bool) -> Option<Vec<RenderedLine>> {
    let DiscoveryInputs {
        dante_sources, dante_names, dante_conmon, dante_unverified,
        ndi_sources, ndi_names, dante_active, ndi_active, streams,
    } = *inputs;

    let flagged = dante_unverified;
    let verified_count = dante_sources.len() - flagged.len();
    let ndi_count = ndi_sources.len();
    if verified_count == 0 && flagged.is_empty() && ndi_count == 0 {
        return None;
    }

    let mut lines = Vec::new();

    if verified_count > 0 || !flagged.is_empty() {
        let live_count = dante_conmon.len();
        let live_suffix = if live_count == 0 {
            String::new()
        } else if live_count == verified_count {
            "  · all live".to_string()
        } else {
            format!("  · {} live", live_count)
        };
        lines.push(RenderedLine::plain(status_entry(&format!("Dante ({}){}", verified_count, live_suffix))));

        // Verified devices sorted by IP — named first, then pending
        let mut verified: Vec<std::net::Ipv4Addr> = dante_sources.iter()
            .filter(|ip| !flagged.contains(ip))
            .copied()
            .collect();
        verified.sort();
        for ip in &verified {
            let suffix = tx_flow_suffix(streams, *ip);
            let line = if let Some(name) = dante_names.get(ip) {
                status_entry(&format!("▸ \"{}\"   {}{}", name, ip, suffix))
            } else {
                status_entry(&format!("▸ {}   (name pending){}", ip, suffix))
            };
            lines.push(RenderedLine::plain(line));
        }

        // Unverified devices inline (mDNS-only ≥ threshold windows)
        let mut flagged_sorted: Vec<std::net::Ipv4Addr> = flagged.iter().copied().collect();
        flagged_sorted.sort();
        for ip in &flagged_sorted {
            let suffix = tx_flow_suffix(streams, *ip);
            let line = if let Some(name) = dante_names.get(ip) {
                status_entry(&format!("⚠  \"{}\"   {}   (mDNS only, no ConMon){}", name, ip, suffix))
            } else {
                status_entry(&format!("⚠  {}   (mDNS only, no ConMon){}", ip, suffix))
            };
            lines.push(RenderedLine::colored("33", line));
        }
    }

    if ndi_count > 0 {
        lines.push(RenderedLine::plain(status_entry(&format!("NDI ({})", ndi_count))));

        let mut ndi_sorted: Vec<std::net::Ipv4Addr> = ndi_sources.iter().copied().collect();
        ndi_sorted.sort();
        for ip in &ndi_sorted {
            let line = if let Some(name) = ndi_names.get(ip) {
                status_entry(&format!("▸ \"{}\"   {}", name, ip))
            } else {
                status_entry(&format!("▸ {}   (name pending)", ip))
            };
            lines.push(RenderedLine::plain(line));
        }
    }

    // No-active-flows diagnostic — shown at most once per session
    let no_flows = (verified_count > 0 && dante_active == 0) || (ndi_count > 0 && ndi_active == 0);
    if no_flows && !*no_flows_diagnostic_shown {
        lines.push(RenderedLine::colored("33", status_entry("⚠  Devices announced but no active flows — mirror port may be needed")));
        *no_flows_diagnostic_shown = true;
    }

    Some(lines)
}

/// Render the "Discovered (AVDECC)" entity list: entity_id, role (talker/
/// listener), SR class, AEM flag, and the gPTP grandmaster currently in use.
fn render_avdecc_entities(entities: &HashMap<[u8; 8], AvdeccEntity>) -> Vec<RenderedLine> {
    let mut lines = Vec::new();
    let mut sorted: Vec<_> = entities.values().collect();
    sorted.sort_by_key(|e| e.entity_id);

    for e in sorted {
        let eui = fmt_eui64(&e.entity_id);
        let model = fmt_eui64(&e.entity_model_id);

        // Talker / listener role summary
        let mut parts: Vec<String> = Vec::new();
        if e.talker_stream_sources > 0 {
            parts.push(format!("T:{} ({})",
                e.talker_stream_sources, media_type_summary(e.talker_capabilities)));
        }
        if e.listener_stream_sinks > 0 {
            parts.push(format!("L:{} ({})",
                e.listener_stream_sinks, media_type_summary(e.listener_capabilities)));
        }
        if parts.is_empty() { parts.push("controller".into()); }
        let role = parts.join("  ");

        // Capability flags
        let class = sr_class_str(e.entity_capabilities);
        let aem   = if e.entity_capabilities & 0x08 != 0 { "  AEM" } else { "" };
        let not_ready = if e.entity_capabilities & 0x0002_0000 != 0 { "  ⚠ not ready" } else { "" };

        lines.push(RenderedLine::plain(status_entry(&format!("▸ {}  {}  {}{}{}", eui, role, class, aem, not_ready))));

        let gm = fmt_eui64(&e.gptp_grandmaster_id);
        let all_zero = e.gptp_grandmaster_id == [0u8; 8];
        let gm_str = if all_zero { "no grandmaster".to_string() }
                     else { format!("GM: {}  domain {}", gm, e.gptp_domain_number) };
        lines.push(RenderedLine::plain(status_detail(&format!("model {}  {}", model, gm_str))));
    }

    lines
}

/// Render the Clock Sources section: one block per PTP domain (grandmaster
/// status, clock quality, correction field, path delay) plus missing-clock
/// alerts. Returns `None` when there is nothing to show — the section header
/// itself is skipped in that case, unlike Streams/Network Status which always
/// print. Follower-census and sync-conflict `Alert`s are emitted by the caller
/// via `capture::emit` — they're a different domain concept (Alert, not a
/// rendered report line) and already follow their own return-data-emit-later
/// pattern, so this function doesn't fold them into `RenderedLine`.
fn render_clock_sources(
    ptp_domains: &HashMap<(u8, u8), PtpStats>,
    missing_ptp: &[MissingClock],
    dante_names: &HashMap<Ipv4Addr, String>,
    clock_dropout_correlated: bool,
) -> Option<Vec<RenderedLine>> {
    if ptp_domains.is_empty() && missing_ptp.is_empty() {
        return None;
    }

    let mut lines = Vec::new();
    let multi_domain = ptp_domains.len() > 1;

    for ((domain, _version), stats) in ptp_domains.iter() {
        let gm_icon = if stats.clock_valid { "✓" } else if stats.last_grandmaster.is_some() { "⚠" } else { "❌" };

        let proto_label = stats.protocol_kind.as_deref().unwrap_or("PTP");
        let domain_suffix = if multi_domain || *domain > 0 {
            format!("  (domain {})", domain)
        } else {
            String::new()
        };

        let clock_line = match (&stats.last_grandmaster, stats.clock_valid) {
            (Some(gm), true) => {
                let gm_ip = stats.grandmaster_src_ip.or(stats.last_src_ip);
                let ip_str = gm_ip.map(|ip| format!("  ({})", ip)).unwrap_or_default();
                let name = gm_ip.and_then(|ip| dante_names.get(&ip));
                let id_part = match (name, stats.version) {
                    (Some(n), _)           => format!("  grandmaster \"{}\"", n),
                    (None, PTP_VERSION_V1) => "  grandmaster".to_string(),
                    (None, _)              => format!("  grandmaster {}", gm),
                };
                status_entry(&format!("{}  {}{}  —{}{}", gm_icon, proto_label, domain_suffix, id_part, ip_str))
            }
            (Some(_), false) => {
                status_entry(&format!("{}  {}{}  —  clock lost", gm_icon, proto_label, domain_suffix))
            }
            (None, _) => {
                match &stats.last_clock_id {
                    Some(id) if stats.seen_sync =>
                        status_entry(&format!("○  {}{}  —  clock source: {}  (Sync seen, no Announce — no grandmaster elected)", proto_label, domain_suffix, id)),
                    Some(id) =>
                        status_entry(&format!("○  {}{}  —  clock source: {}  (peer-delay requests only — no Sync/grandmaster; link partner may not be gPTP-capable)", proto_label, domain_suffix, id)),
                    None =>
                        status_entry(&format!("{}  {}{}  —  no clock detected", gm_icon, proto_label, domain_suffix)),
                }
            }
        };
        lines.push(RenderedLine::plain(clock_line));

        if stats.protocol_kind.as_deref() == Some("AVB")
            && stats.last_grandmaster.is_none()
            && !stats.seen_sync
            && stats.last_clock_id.is_some()
        {
            lines.push(RenderedLine::plain(status_detail("ℹ  gPTP is link-local — the grandmaster is only visible on a time-aware (AVB-enabled) port")));
        }

        if let Some(ref q) = stats.last_quality {
            lines.push(RenderedLine::plain(status_detail(&format!("clock quality: {}", q))));
        }

        if let Some(offset_ns) = stats.last_offset_ns
            && offset_ns != 0
        {
            let offset_line = if offset_ns.unsigned_abs() >= 1_000 {
                status_detail(&format!("correction: {:.1} µs", offset_ns as f64 / 1_000.0))
            } else {
                status_detail(&format!("correction: {} ns", offset_ns))
            };
            lines.push(RenderedLine::plain(offset_line));
            if offset_ns.unsigned_abs() > 1_000 {
                lines.push(RenderedLine::colored("33", status_detail("⚠  Large PTP correction field — transparent clock or path issue")));
            }
        }

        if let (Some(min), Some(max)) = (stats.min_path_delay_ns, stats.max_path_delay_ns) {
            let spread_ns = max - min;
            let fmt = |ns: i64| if ns.unsigned_abs() >= 1_000 {
                format!("{:.1}µs", ns as f64 / 1_000.0)
            } else {
                format!("{}ns", ns)
            };
            let hops = crate::stats::path_delay_hop_estimate(min);
            let hops_str = if hops > 0 { format!("  ~{} hop{}", hops, if hops == 1 { "" } else { "s" }) } else { String::new() };
            let line = if min == max {
                status_detail(&format!("path delay: {}{}", fmt(max), hops_str))
            } else {
                status_detail(&format!("path delay: {} – {}  (spread {}){}", fmt(min), fmt(max), fmt(spread_ns), hops_str))
            };
            lines.push(RenderedLine::plain(line));
            if crate::stats::path_delay_spread_unstable(min, max) {
                lines.push(RenderedLine::colored("33", status_detail("⚠  PTP path-delay variance > 10µs — unstable link (EEE, half-duplex, or cable)")));
            }
            if crate::stats::path_delay_too_many_hops(max) {
                lines.push(RenderedLine::colored("33", status_detail("⚠  PTP path delay > 1ms — too many hops between this node and grandmaster")));
            }
        }

        if stats.protocol_clock_lost {
            lines.push(RenderedLine::colored("33", status_detail("⚠  Clock lost — grandmaster disappeared")));
        }

        if stats.protocol_changes_count > 0 {
            lines.push(RenderedLine::colored("33", status_detail(&format!("⚠  Clock source changed {} time(s)", stats.protocol_changes_count))));
        }
    }

    // Missing clock alerts — suppressed when the combined clock-dropout alert dominates
    if !clock_dropout_correlated {
        for mc in missing_ptp {
            lines.push(RenderedLine::colored("31", format_missing_clock(mc)));
        }
    }

    Some(lines)
}

/// Render the Streams section: the unified RTP/Dante/NDI list plus the AVB
/// per-stream entries (AVTP stream IDs with MSRP/VLAN reservation state inline).
/// Always has content (the header is shown unconditionally, same as today).
#[allow(clippy::too_many_arguments)]
fn render_streams(
    streams: &HashMap<String, StreamStats>,
    tcp_streams: &HashMap<String, TcpStreamStats>,
    dante_sources: &HashSet<Ipv4Addr>,
    dante_names: &HashMap<Ipv4Addr, String>,
    avtp_streams: &HashMap<[u8; 8], AvtpStreamStats>,
    msrp_state: &HashMap<[u8; 8], MsrpDeclaration>,
    mvrp_vlans: &HashSet<u16>,
    clock_dropout_correlated: bool,
) -> Vec<RenderedLine> {
    let mut lines = Vec::new();

    let group_order = ["AES67", "Dante", "NDI", "ST", "AVB"];
    let mut keys: Vec<&String> = streams.keys().collect();
    keys.sort_by(|a, b| {
        let a_group = group_order
            .iter()
            .position(|g| a.starts_with(g))
            .unwrap_or(group_order.len());
        let b_group = group_order
            .iter()
            .position(|g| b.starts_with(g))
            .unwrap_or(group_order.len());
        a_group.cmp(&b_group).then(a.cmp(b))
    });

    for key in keys {
        let s = &streams[key];

        if s.protocol == "AVB" || s.protocol.starts_with("AVB ") { continue; }

        let proto_label = if s.protocol.starts_with("2110-") {
            format!("ST{}", s.protocol)
        } else if s.protocol == "AES67"
            && s.src_ip.map(|ip| dante_sources.contains(&ip)).unwrap_or(false)
        {
            s.src_ip
                .and_then(|ip| dante_names.get(&ip))
                .map(|n| format!("AES67 (Dante: \"{}\")", n))
                .unwrap_or_else(|| "AES67 (Dante)".to_string())
        } else {
            s.protocol.clone()
        };

        let name_str = s.sdp_name.as_deref()
            .map(|n| format!("  \"{}\"", n))
            .unwrap_or_default();

        let codec_str = s.sdp_rtpmap.as_deref()
            .map(|r| format!("  [{}]", r))
            .unwrap_or_default();

        let addr_str = match s.dst_ip {
            Some(ip) if s.dst_port > 0 => format!("  —  {}:{}", ip, s.dst_port),
            Some(ip)                   => format!("  —  {}", ip),
            None                       => String::new(),
        };

        let multicast_tag = if s.protocol == "Dante" {
            if s.is_multicast { "  [multicast]" } else { "  [unicast]" }
        } else { "" };

        let tx_tag = transmitter_tag(s.transmitter);
        lines.push(RenderedLine::plain(status_entry(&format!("▸ {}{}{}{}{}{}", proto_label, multicast_tag, name_str, codec_str, addr_str, tx_tag))));

        if s.protocol == "NDI" {
            let tcp = s.dst_ip.and_then(|ip| {
                tcp_streams.values().find(|t| t.src_ip == ip || t.dst_ip == ip)
            });
            let metrics = if let Some(t) = tcp {
                let quality_str = match t.stream_quality {
                    StreamQuality::Healthy    => "healthy",
                    StreamQuality::Degrading  => "degrading",
                    StreamQuality::Critical   => "critical",
                    StreamQuality::Terminated => "terminated",
                };
                status_detail(&format!("{}  |  {:.1} Mbps  |  retrans: {}",
                    quality_str, t.bitrate_bps as f64 / 1_000_000.0, t.retransmissions))
            } else {
                status_detail(&format!("{:.1} Mbps", s.bitrate_bps as f64 / 1_000_000.0))
            };
            lines.push(RenderedLine::plain(metrics));
        } else if s.protocol == "Dante" && !s.rtp_seen {
            lines.push(RenderedLine::plain(status_detail(&format!(
                "{} pkts  |  {:.1} Mbps  (ATP framing — loss/jitter unavailable)",
                s.packets, s.bitrate_bps as f64 / 1_000_000.0
            ))));
        } else {
            lines.push(RenderedLine::plain(status_detail(&format!(
                "loss: {:.1}%  |  jitter: {:.2} ms  |  {:.1} Mbps",
                s.loss_pct(), s.jitter_ms(), s.bitrate_bps as f64 / 1_000_000.0
            ))));
        }

        for diag in s.diagnostics() {
            // Suppress PacketLoss for clock-dependent protocols when the combined
            // clock-dropout alert already fired — avoids double-reporting.
            let clock_proto = crate::capture::stream_clock_kind(&s.protocol).is_some();
            if clock_dropout_correlated
                && clock_proto
                && matches!(diag, StreamDiagnostic::PacketLoss { .. })
            {
                continue;
            }
            let Some(line) = diag.message() else { continue };
            let color = if diag.is_critical() { "31" } else { "33" };
            lines.push(RenderedLine::colored(color, line));
        }
    }

    // AVB per-stream entries (AVTP stream IDs with MSRP/VLAN inline)
    if !avtp_streams.is_empty() {
        let mut sorted: Vec<&AvtpStreamStats> = avtp_streams.values().collect();
        sorted.sort_by_key(|s| s.stream_id);
        for avtp in sorted {
            let dead = avtp.last_seen.elapsed() > Duration::from_secs(STREAM_TIMEOUT_SECS);
            lines.push(RenderedLine::plain(status_entry(&format!("▸ AVB  {}  —  {}",
                avtp_subtype_name(avtp.subtype), avtp.stream_id_str()))));

            lines.push(RenderedLine::plain(status_detail(&format!(
                "loss: {:.1}%  |  {:.1} Mbps",
                avtp.loss_pct(), avtp.bitrate_bps as f64 / 1_000_000.0
            ))));

            if let Some(talker) = msrp_state.get(&avtp.stream_id) {
                match talker.decl_type {
                    MsrpDeclType::TalkerAdvertise => {
                        let vlan = talker.vlan_id.map(|v| format!("  VLAN {}", v)).unwrap_or_default();
                        let prio = talker.priority.map(|p| format!("  prio {}", p)).unwrap_or_default();
                        let listener_str = msrp_state.values()
                            .find(|d| d.stream_id == avtp.stream_id
                                && matches!(d.decl_type, MsrpDeclType::Listener))
                            .map(|l| match l.listener_state {
                                Some(2) => "  ✓  Listener Ready",
                                Some(1) => "  ⚠  Listener AskingFailed",
                                Some(3) => "  ⚠  Listener ReadyFailed",
                                _       => "  Listener Unknown",
                            })
                            .unwrap_or("");
                        lines.push(RenderedLine::plain(status_detail(&format!("✓  Reserved{}{}{}", vlan, prio, listener_str))));
                    }
                    MsrpDeclType::TalkerFailed => {
                        let code_str = match talker.failure_code {
                            Some(code) => format!("code {}: {}", code, msrp_failure_reason(code)),
                            None       => "failed".to_string(),
                        };
                        lines.push(RenderedLine::colored("33", status_detail(&format!("⚠  Reservation failed — {}", code_str))));
                    }
                    MsrpDeclType::Listener => {}
                }
            } else if mvrp_vlans.is_empty() {
                lines.push(RenderedLine::colored("33", status_detail("⚠  No VLAN registration — L2 QoS may not be configured")));
            }

            if avtp.pcp_violations > 0 {
                lines.push(RenderedLine::colored("33", status_detail(&format!(
                    "⚠  AVTP stream using PCP {}, MSRP reservation declared PCP {} — frame lands in wrong CBS queue",
                    avtp.observed_pcp.unwrap_or(0), avtp.msrp_declared_pcp.unwrap_or(3)
                ))));
            }

            if dead {
                lines.push(RenderedLine::colored("31", status_detail(&format!("💀 No signal for {:.0}s", avtp.last_seen.elapsed().as_secs_f64()))));
            }
        }
    }

    lines
}

/// Render the Network Status section: bandwidth, QoS, IGMP querier, ECN,
/// PAUSE/PFC, EEE, and pcap capture stats. Always has content (unlike
/// Discovered/Clock Sources), so always returns a non-empty `Vec`.
struct NetworkStatusInputs<'a> {
    mbps: f64,
    streams: &'a HashMap<String, StreamStats>,
    health: &'a NetworkHealth,
    pause_frames: u64,
    pfc_frames: u64,
    eee_ports: &'a HashMap<(String, String), (u16, u16)>,
    pcap_stats: Option<(u32, u32, u32)>,
    packets_dispatched: u64,
}

fn render_network_status(inputs: &NetworkStatusInputs) -> Vec<RenderedLine> {
    let NetworkStatusInputs {
        mbps, streams, health, pause_frames, pfc_frames, eee_ports, pcap_stats, packets_dispatched,
    } = *inputs;
    let mut lines = Vec::new();

    // One metric per line for at-a-glance scanning.
    lines.push(RenderedLine::plain(status_entry(&format!("Bandwidth: {:.1} Mbps (last 5s)", mbps))));

    let dscp_bad = streams.values().filter(|s| s.dscp_violations > 0).count();
    let qos_str = if streams.values().all(|s| s.protocol == "NDI" || s.protocol == "AVB" || s.protocol.starts_with("AVB ")) {
        "QoS: – (no IP streams)".to_string()
    } else if dscp_bad == 0 {
        "QoS: ✓ all streams correctly marked".to_string()
    } else {
        format!("QoS: ⚠ {} stream(s) with incorrect DSCP", dscp_bad)
    };
    lines.push(RenderedLine::plain(status_entry(&qos_str)));

    let querier_str = match health.last_igmp_query {
        None => "IGMP: – (no querier seen)".to_string(),
        Some(t) => {
            let secs = t.elapsed().as_secs();
            if secs > health.querier_silent_after_secs() {
                format!("IGMP: ⚠ querier silent {}s", secs)
            } else {
                let interval_str = health.igmp_query_interval_secs
                    .map(|i| format!("  (interval {}s)", i))
                    .unwrap_or_default();
                let ip_str = health.igmp_querier_ip
                    .map(|ip| format!(" {}", ip))
                    .unwrap_or_default();
                let mac_str = health.igmp_querier_mac
                    .map(|m| format!(" [{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}]",
                        m[0], m[1], m[2], m[3], m[4], m[5]))
                    .unwrap_or_default();
                format!("IGMP: ✓ querier{}{} {}s ago{}", ip_str, mac_str, secs, interval_str)
            }
        }
    };
    lines.push(RenderedLine::plain(status_entry(&querier_str)));

    if health.ecn_congestion_marks > 0 {
        lines.push(RenderedLine::colored("33", status_entry(&format!(
            "⚠  ECN: {} congestion mark(s) — router congestion detected on the path",
            health.ecn_congestion_marks
        ))));
    }

    if pause_frames > 0 {
        lines.push(RenderedLine::colored("33", status_entry(&format!(
            "⚠  PAUSE frames: {} in last 5s — upstream link congestion causing tx-side freezes",
            pause_frames
        ))));
    }
    if pfc_frames > 0 {
        lines.push(RenderedLine::colored("33", status_entry(&format!(
            "⚠  PFC frames: {} in last 5s — priority flow control engaged on upstream link",
            pfc_frames
        ))));
    }

    if !eee_ports.is_empty() {
        lines.push(RenderedLine::colored("33", status_entry(&format!(
            "⚠  EEE active on {} switch port(s) — may cause audio/video glitches  (disable EEE on all AV switch ports)",
            eee_ports.len()
        ))));
        for ((chassis, port), (tx, rx)) in eee_ports.iter() {
            lines.push(RenderedLine::plain(status_detail(&format!("port \"{}\"  chassis {}  Tx wake: {}µs  Rx wake: {}µs", port, chassis, tx, rx))));
        }
    }

    // Capture statistics — 📦 marks the group, one counter per line. Drop counters
    // turn red when non-zero so the offending counter is obvious at a glance.
    if let Some((received, dropped, if_dropped)) = pcap_stats {
        lines.push(RenderedLine::plain(status_entry(&format!("📦 {} pkts received", received))));
        let drop_line = |n: u32, label: &str| status_detail(&format!("{} {}", n, label));
        if dropped > 0 {
            lines.push(RenderedLine::colored("31", drop_line(dropped, "kernel drop(s)")));
        } else {
            lines.push(RenderedLine::plain(drop_line(dropped, "kernel drop(s)")));
        }
        if if_dropped > 0 {
            lines.push(RenderedLine::colored("31", drop_line(if_dropped, "interface drop(s)")));
        } else {
            lines.push(RenderedLine::plain(drop_line(if_dropped, "interface drop(s)")));
        }
        lines.push(RenderedLine::plain(status_detail(&format!("{} parsed", packets_dispatched))));
        if dropped > 0 || if_dropped > 0 {
            lines.push(RenderedLine::colored("31", status_entry("❌ Capture drops detected — loss/jitter figures may be understated. \
                        Reduce load or increase pcap buffer size.")));
        }
    } else {
        lines.push(RenderedLine::plain(status_entry(&format!("📦 {} parsed", packets_dispatched))));
    }

    lines
}

/// Print one 5-second report cycle to stdout and the log file.
///
/// Sections printed in order:
/// 1. 🔬 Network Health — X% | stream counts  (timestamp is in the header rule line)
/// 2. ✓ / ⚠ status line
/// 3. `📇 Discovered` — mDNS/ConMon devices, per-device layout
/// 4. `📡 Discovered (AVDECC)` — ADP-discovered entities
/// 5. `🕐 Clock Sources` — PTP domains + follower census + sync conflict
/// 6. `📡 Streams` — AES67, Dante, ST2110, NDI, AVB entries with per-stream alerts
/// 7. `📊 Network Status` — QoS, IGMP, EEE, PAUSE/PFC, pcap stats, bandwidth
pub fn print_report(snap: &ReportSnapshot, session: &mut ReportSession, logger: &mut Logger) {
    // Destructure the snapshot into the local names the body below uses. Every
    // field is Copy (a borrow or scalar), so this is zero-cost.
    let ReportSnapshot {
        streams, tcp_streams, ptp_domains, missing_ptp, health, bytes_this_window,
        eee_ports, dante, avb, ndi_sources, ndi_names,
        pause_frames, pfc_frames, pcap_stats, packets_dispatched,
        periodic_alerts, clock_dropout_correlated,
    } = *snap;
    let DanteSnapshot { sources: dante_sources, names: dante_names, conmon: dante_conmon, unverified: dante_unverified } = dante;
    let AvbSnapshot { avtp_streams, msrp_state, mvrp_vlans, avdecc_entities } = avb;
    let PeriodicAlerts { ip_config: ip_config_alerts, conmon_bridge: conmon_bridge_alerts, follower_census: follower_census_alerts, ptp_sync: ptp_sync_alerts } = periodic_alerts;
    let quiet = session.quiet;
    let no_flows_diagnostic_shown = &mut session.no_flows_diagnostic_shown;

    let now = Local::now();
    let full_timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_header = format!("{} | AVStreamLens report", full_timestamp);
    logger.log(&log_header);

    let mbps = bytes_this_window as f64 * 8.0 / 5_000_000.0;

    type ProtocolGroup = (&'static str, fn(&str) -> bool);
    let protocol_groups: &[ProtocolGroup] = &[
        ("AES67",  |p| p == "AES67"),
        ("ST2110", |p| p.starts_with("2110-")),
        ("Dante",  |p| p == "Dante"),
        ("NDI",    |p| p == "NDI"),
    ];

    let mut proto_parts: Vec<String> = protocol_groups.iter()
        .filter_map(|(label, matches)| {
            let n = streams.values().filter(|s| matches(&s.protocol)).count();
            if n > 0 { Some(format!("{}: {}", label, n)) } else { None }
        })
        .collect();

    if !avtp_streams.is_empty() {
        proto_parts.push(format!("AVB: {}", avtp_streams.len()));
    }

    let tcp_count = tcp_streams.len();
    if tcp_count > 0 {
        proto_parts.push(format!("TCP: {}", tcp_count));
    }

    let streams_str = if proto_parts.is_empty() {
        "no streams".to_string()
    } else {
        proto_parts.join("  |  ")
    };

    // ── Health Summary ──────────────────────────────────────────────────────
    // One bullet per factor deducting from the Health Score this Window. Mirrors
    // the scoring table exactly (NetworkHealth::build_health_summary). Empty when
    // the score is 100%.
    let health_summary =
        health.build_health_summary(streams, tcp_streams, ptp_domains, msrp_state, eee_ports, avtp_streams);

    // ── Quiet mode: suppress stdout only, never the log ─────────────────────
    // A quiet cycle prints nothing to stdout when the report is fully healthy —
    // no summary bullets, no pcap drops, no missing required clock, and no
    // section-level diagnostic alert (the latter two carry no Health-Score penalty
    // so the summary can't see them; see `quiet_suppressible`). The log file always
    // receives the full report, so `--quiet` never loses a record of the cycle.
    let section_alerts: [&[Alert]; 4] =
        [ip_config_alerts, conmon_bridge_alerts, follower_census_alerts, ptp_sync_alerts];
    let suppress_stdout =
        quiet && quiet_suppressible(&health_summary, pcap_stats, missing_ptp, &section_alerts);
    set_stdout_enabled(!suppress_stdout);

    // ── 1. Report header block + Health Score ──────────────────────────────
    let score = format!("{:.0}%", health.network_score);
    let rule = "─".repeat(66);
    logger.log(&format!("\n{}", rule));
    logger.log(&format!("  AVStreamLens  ·  {}", full_timestamp));
    logger.log(&rule);
    if stdout_enabled() {
        println!("\n{}", ansi("36", &rule));
        println!("{}", ansi("36", &format!("  AVStreamLens  ·  {}", full_timestamp)));
        println!("{}", ansi("36", &rule));
    }

    // Time is already in the header rule line above (full date + time) — don't repeat it here.
    let header = if proto_parts.is_empty() {
        format!("\n🔬 Network Health — {}", score)
    } else {
        format!("\n🔬 Network Health — {}  |  {}", score, streams_str)
    };
    logger.log(&format!("Network Health — {}  |  {}", score, streams_str));
    if stdout_enabled() { println!("{}", ansi("36", &header)); }

    // ── 2. Health Summary ───────────────────────────────────────────────────
    // Rendered only when the Health Score is below 100% (non-empty summary). A
    // fully healthy report shows no status line at all — the score line says 100%.
    for bullet in &health_summary {
        emit_line(logger, "33", bullet);
    }

    // ── 3. Discovered (mDNS/ConMon) ────────────────────────────────────────
    let dante_active = streams.values().filter(|s| s.protocol == "Dante").count();
    let ndi_active   = streams.values().filter(|s| s.protocol == "NDI").count();
    let discovery_inputs = DiscoveryInputs {
        dante_sources, dante_names, dante_conmon, dante_unverified,
        ndi_sources, ndi_names, dante_active, ndi_active, streams,
    };
    if let Some(discovery_lines) = render_discovery(&discovery_inputs, no_flows_diagnostic_shown) {
        section_header(logger, "Discovered:", "📇 Discovered:");
        emit_lines(&discovery_lines, logger);
        emit_alerts(ip_config_alerts, logger);
        emit_alerts(conmon_bridge_alerts, logger);
    }

    // ── 4. Discovered (AVDECC) ──────────────────────────────────────────────
    if !avdecc_entities.is_empty() {
        let noun = if avdecc_entities.len() == 1 { "entity" } else { "entities" };
        let plain = format!("Discovered (AVDECC — {} {}):", avdecc_entities.len(), noun);
        let decorated = format!("📡 {}", plain);
        section_header(logger, &plain, &decorated);
        emit_lines(&render_avdecc_entities(avdecc_entities), logger);
    }

    // ── 5. Clock Sources ────────────────────────────────────────────────────
    let has_clock_content = !ptp_domains.is_empty()
        || !missing_ptp.is_empty()
        || !follower_census_alerts.is_empty()
        || !ptp_sync_alerts.is_empty();

    if has_clock_content {
        section_header(logger, "Clock Sources:", "🕐 Clock Sources:");
        if let Some(clock_lines) = render_clock_sources(ptp_domains, missing_ptp, dante_names, clock_dropout_correlated) {
            emit_lines(&clock_lines, logger);
        }

        // Follower census and sync conflict belong inside Clock Sources
        emit_alerts(follower_census_alerts, logger);
        emit_alerts(ptp_sync_alerts, logger);
    }

    // ── 6. Streams (all protocols unified) ─────────────────────────────────
    section_header(logger, "Streams:", "📡 Streams:");
    let stream_lines = render_streams(
        streams, tcp_streams, dante_sources, dante_names, avtp_streams, msrp_state, mvrp_vlans,
        clock_dropout_correlated,
    );
    emit_lines(&stream_lines, logger);

    // ── 7. Network Status ───────────────────────────────────────────────────
    section_header(logger, "Network Status:", "📊 Network Status:");
    let network_status_lines = render_network_status(&NetworkStatusInputs {
        mbps, streams, health, pause_frames, pfc_frames, eee_ports, pcap_stats, packets_dispatched,
    });
    emit_lines(&network_status_lines, logger);

    logger.log("");
    // Restore stdout for any output that follows this report (e.g. next cycle's
    // alerts emitted via capture::emit, which does not consult this gate).
    set_stdout_enabled(true);
}

/// Whether a quiet-mode cycle may suppress stdout. Only when the report is fully
/// healthy: no Health Summary bullets, no pcap kernel/interface drops, no missing
/// required clock, and none of the section-level diagnostic alerts (Dante
/// IP-config, ConMon bridge, follower census, PTP sync conflict). Missing clocks
/// and section alerts carry no Health-Score penalty, so they are invisible to the
/// summary and must be checked explicitly — otherwise `--quiet` would hide a
/// "no clock" or "redundancy bridged" warning entirely. The log file always
/// receives the full report regardless of this decision.
fn quiet_suppressible(
    health_summary: &[String],
    pcap_stats: Option<(u32, u32, u32)>,
    missing_ptp: &[MissingClock],
    section_alerts: &[&[Alert]],
) -> bool {
    let pcap_drops_ok = pcap_stats.is_none_or(|(_, d, id)| d == 0 && id == 0);
    health_summary.is_empty()
        && pcap_drops_ok
        && missing_ptp.is_empty()
        && section_alerts.iter().all(|a| a.is_empty())
}

/// Render a `MissingClock` as the user-facing red alert line.
fn format_missing_clock(mc: &MissingClock) -> String {
    let clock = match mc.kind {
        MissingClockKind::Ptpv2 => "PTPv2",
        MissingClockKind::Ptp   => "PTPv1 or PTPv2",
        MissingClockKind::Gptp  => "L2 gPTP",
    };
    let protos = match mc.affected.len() {
        0 => "(none)".to_string(),
        1 => mc.affected[0].to_string(),
        2 => format!("{} and {}", mc.affected[0], mc.affected[1]),
        _ => {
            let (last, rest) = mc.affected.split_last().unwrap();
            format!("{}, and {}", rest.join(", "), last)
        }
    };
    format!("⚠  No {} clock — {} streams may lose sync", clock, protos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::StreamStats;
    use std::net::Ipv4Addr;

    fn dante_stream(src: Ipv4Addr, multicast: bool, atp: bool) -> StreamStats {
        let mut s = StreamStats::new("Dante", 48_000.0);
        s.src_ip = Some(src);
        s.is_multicast = multicast;
        s.rtp_seen = !atp; // ATP flows never set rtp_seen
        s
    }

    #[test]
    fn tx_flow_count_zero_when_no_streams() {
        let streams = HashMap::new();
        let ip = Ipv4Addr::new(192, 168, 1, 45);
        assert_eq!(dante_tx_flow_count(&streams, ip), 0);
        assert_eq!(tx_flow_suffix(&streams, ip), "");
    }

    #[test]
    fn tx_flow_count_single_unicast() {
        let ip = Ipv4Addr::new(192, 168, 1, 45);
        let mut streams = HashMap::new();
        streams.insert("Dante a".into(), dante_stream(ip, false, false));
        assert_eq!(dante_tx_flow_count(&streams, ip), 1);
        assert_eq!(tx_flow_suffix(&streams, ip), "  (1 tx flows)");
    }

    #[test]
    fn tx_flow_count_combines_unicast_and_multicast() {
        let ip = Ipv4Addr::new(192, 168, 1, 45);
        let mut streams = HashMap::new();
        streams.insert("Dante a".into(), dante_stream(ip, false, false)); // unicast
        streams.insert("Dante b".into(), dante_stream(ip, true, false));  // multicast
        streams.insert("Dante c".into(), dante_stream(ip, true, true));   // multicast ATP
        assert_eq!(dante_tx_flow_count(&streams, ip), 3);
    }

    #[test]
    fn tx_flow_count_includes_atp_framed() {
        let ip = Ipv4Addr::new(192, 168, 1, 45);
        let mut streams = HashMap::new();
        streams.insert("Dante atp".into(), dante_stream(ip, true, true));
        assert_eq!(dante_tx_flow_count(&streams, ip), 1, "ATP flow (rtp_seen=false) must count");
    }

    #[test]
    fn tx_flow_count_ignores_other_source_ips() {
        let ip = Ipv4Addr::new(192, 168, 1, 45);
        let other = Ipv4Addr::new(192, 168, 1, 99);
        let mut streams = HashMap::new();
        streams.insert("Dante a".into(), dante_stream(ip, false, false));
        streams.insert("Dante b".into(), dante_stream(other, false, false));
        assert_eq!(dante_tx_flow_count(&streams, ip), 1);
    }

    #[test]
    fn tx_flow_count_ignores_non_dante_protocols() {
        let ip = Ipv4Addr::new(192, 168, 1, 45);
        let mut streams = HashMap::new();
        let mut aes = StreamStats::new("AES67", 48_000.0);
        aes.src_ip = Some(ip);
        streams.insert("AES67 x".into(), aes);
        assert_eq!(dante_tx_flow_count(&streams, ip), 0, "only Dante flows count toward Dante budget");
    }

    // ── transmitter_tag (confidence verdict display) ─────────────────────────
    use crate::protocols::TransmitterClass;

    #[test]
    fn tag_empty_without_verdict() {
        assert_eq!(transmitter_tag(None), "");
    }

    #[test]
    fn tag_confirmed_reads_confirmed() {
        let v = TransmitterVerdict { class: TransmitterClass::Dvs, confidence: TransmitterConfidence::Confirmed, signals: 3 };
        assert_eq!(transmitter_tag(Some(v)), "  ·  DVS (confirmed)");
    }

    #[test]
    fn tag_inferred_multi_signal_shows_count() {
        let v = TransmitterVerdict { class: TransmitterClass::Dvs, confidence: TransmitterConfidence::Inferred, signals: 2 };
        assert_eq!(transmitter_tag(Some(v)), "  ·  DVS (likely, 2 signals)");
    }

    #[test]
    fn tag_hint_reads_low_confidence() {
        let v = TransmitterVerdict { class: TransmitterClass::Dvs, confidence: TransmitterConfidence::Hint, signals: 1 };
        assert_eq!(transmitter_tag(Some(v)), "  ·  DVS (possible — no QoS marking)");
    }

    #[test]
    fn tag_inferred_hardware_single_signal() {
        let v = TransmitterVerdict { class: TransmitterClass::Hardware, confidence: TransmitterConfidence::Inferred, signals: 1 };
        assert_eq!(transmitter_tag(Some(v)), "  ·  Hardware (likely)");
    }

    // ── quiet-mode suppression decision ─────────────────────────────────────

    #[test]
    fn quiet_suppressible_false_when_required_clock_missing() {
        // A missing required clock carries no Health-Score penalty when there is no
        // PTP traffic at all (ptp_domains empty), so the summary is empty — but
        // quiet must NOT suppress a "no clock" warning.
        let missing = [MissingClock { kind: MissingClockKind::Ptp, affected: vec!["Dante"] }];
        assert!(!quiet_suppressible(&[], None, &missing, &[]));
    }

    #[test]
    fn quiet_suppressible_false_when_section_alert_present() {
        // Section-level diagnostics (Dante IP-config, ConMon bridge, follower
        // census, PTP sync conflict) are not Health-Summary bullets, so quiet must
        // check them explicitly.
        let alerts = [Alert::error("Dante redundancy bridged")];
        let slices: [&[Alert]; 1] = [&alerts];
        assert!(!quiet_suppressible(&[], None, &[], &slices));
    }

    #[test]
    fn quiet_suppressible_true_when_fully_healthy() {
        assert!(quiet_suppressible(&[], None, &[], &[]));
        assert!(quiet_suppressible(&[], Some((100, 0, 0)), &[], &[]), "zero drops is healthy");
    }

    #[test]
    fn quiet_suppressible_false_on_pcap_drops_or_summary() {
        assert!(!quiet_suppressible(&[], Some((100, 5, 0)), &[], &[]), "kernel drops force output");
        assert!(!quiet_suppressible(&["⚠ loss".to_string()], None, &[], &[]), "summary forces output");
    }

    #[cfg(unix)]
    #[test]
    fn log_open_refuses_to_follow_symlink() {
        // Live capture runs as root and the log is created in CWD, which may be
        // attacker-writable (/tmp, a shared dir). A pre-planted symlink at the log
        // path must NOT be followed and its target must NOT be truncated.
        let dir = std::env::temp_dir().join(format!("avsl_symlink_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, b"important").unwrap();
        let link = dir.join("planted.log");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let res = open_exclusive(&link);
        assert!(res.is_err(), "must refuse to open through an existing symlink path");
        assert_eq!(std::fs::read(&victim).unwrap(), b"important",
            "the symlink target must not be truncated");

        // A fresh, unplanted path still succeeds.
        assert!(open_exclusive(&dir.join("fresh.log")).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn quiet_healthy_cycle_still_writes_full_report_to_log() {
        use std::io::Read;
        // The documented --quiet contract: a fully healthy cycle prints nothing to
        // stdout but MUST still write the complete report to the log file.
        let streams = HashMap::new(); let tcp = HashMap::new(); let ptp = HashMap::new();
        let avtp = HashMap::new(); let msrp = HashMap::new(); let mvrp = HashSet::new();
        let eee = HashMap::new(); let dsrc = HashSet::new(); let dnames = HashMap::new();
        let dconmon = HashMap::new(); let dunver = HashSet::new(); let nsrc = HashSet::new();
        let nnames = HashMap::new(); let avdecc = HashMap::new();
        let health = NetworkHealth::new();
        let snap = ReportSnapshot {
            streams: &streams, tcp_streams: &tcp, ptp_domains: &ptp, missing_ptp: &[],
            health: &health, bytes_this_window: 0, eee_ports: &eee,
            dante: DanteSnapshot { sources: &dsrc, names: &dnames, conmon: &dconmon, unverified: &dunver },
            avb: AvbSnapshot { avtp_streams: &avtp, msrp_state: &msrp, mvrp_vlans: &mvrp, avdecc_entities: &avdecc },
            ndi_sources: &nsrc, ndi_names: &nnames,
            pause_frames: 0, pfc_frames: 0, pcap_stats: None,
            packets_dispatched: 0,
            periodic_alerts: PeriodicAlerts { ip_config: &[], conmon_bridge: &[], follower_census: &[], ptp_sync: &[] },
            clock_dropout_correlated: false,
        };
        let tmp = std::env::temp_dir().join(format!("avsl_quiet_{}.log", std::process::id()));
        let file = std::fs::File::options().read(true).write(true).create(true).truncate(true)
            .open(&tmp).unwrap();
        let mut logger = Logger { file };
        let mut session = ReportSession { quiet: true, no_flows_diagnostic_shown: false };
        print_report(&snap, &mut session, &mut logger);

        let mut contents = String::new();
        std::fs::File::open(&tmp).unwrap().read_to_string(&mut contents).unwrap();
        std::fs::remove_file(&tmp).ok();
        assert!(contents.contains("Network Health"),
            "log must contain the full report even when quiet suppresses stdout");
        assert!(contents.contains("Network Status:"), "log must include all sections");
    }

    // ── Clock Sources: PTPv1 hops advisory removed ──────────────────────────

    #[test]
    fn ptpv1_domain_does_not_render_hops_latency_advisory() {
        // PTPv1 path delay is never measured (parse_ptp_v1 returns None for
        // path_delay_ns), so the old "N hops: Dante latency should be ≥ X" line was
        // unreachable. Even when the path-delay fields are populated, a v1 domain
        // must not render it — v1 path delay is not a real measurement.
        let mut domains = HashMap::new();
        let mut ptp = PtpStats::new(0, PTP_VERSION_V1);
        ptp.min_path_delay_ns = Some(20_000); // 4 "hops" by the 5µs heuristic
        ptp.max_path_delay_ns = Some(20_000);
        domains.insert((0, PTP_VERSION_V1), ptp);

        let lines = render_clock_sources(&domains, &[], &HashMap::new(), false).unwrap();
        assert!(!lines.iter().any(|l| l.text.contains("Dante latency should be")),
            "PTPv1 must not render the hops latency advisory");
    }

    // ── shared indent constants (Network Status alignment) ───────────────────

    #[test]
    fn entry_indent_is_two_spaces() {
        assert_eq!(ENTRY_INDENT, "  ");
    }

    #[test]
    fn detail_indent_is_four_spaces() {
        assert_eq!(DETAIL_INDENT, "    ");
    }

    #[test]
    fn network_status_entry_matches_other_sections_indent() {
        // Streams/Discovered/Clock Sources entries start with ENTRY_INDENT before
        // their glyph; Network Status metric lines must match so the left margin
        // doesn't shift when scanning a report top to bottom.
        assert_eq!(status_entry("Bandwidth: 1.0 Mbps"), format!("{}Bandwidth: 1.0 Mbps", ENTRY_INDENT));
    }

    #[test]
    fn network_status_detail_matches_other_sections_indent() {
        assert_eq!(status_detail("port detail"), format!("{}port detail", DETAIL_INDENT));
    }

    // ── AVB PCP mismatch rendering (per stream_id, via AvtpStreamStats) ──────

    #[test]
    fn avb_stream_renders_pcp_mismatch_line() {
        use crate::stats::AvtpStreamStats;
        let sid = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut avtp = AvtpStreamStats::new(sid, 0x00);
        avtp.pcp_violations = 1;
        avtp.observed_pcp = Some(2);
        avtp.msrp_declared_pcp = Some(3);
        let mut avtp_streams = HashMap::new();
        avtp_streams.insert(sid, avtp);

        let lines = render_streams(
            &HashMap::new(), &HashMap::new(), &HashSet::new(), &HashMap::new(),
            &avtp_streams, &HashMap::new(), &HashSet::new(), false,
        );

        assert!(
            lines.iter().any(|l| l.text.contains("PCP") && l.text.contains("2") && l.text.contains("3")),
            "expected a PCP mismatch line mentioning observed(2) vs. expected(3), got: {:#?}",
            lines.iter().map(|l| &l.text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn avb_stream_no_pcp_line_when_no_violation() {
        use crate::stats::AvtpStreamStats;
        let sid = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let avtp = AvtpStreamStats::new(sid, 0x00);
        let mut avtp_streams = HashMap::new();
        avtp_streams.insert(sid, avtp);

        let lines = render_streams(
            &HashMap::new(), &HashMap::new(), &HashSet::new(), &HashMap::new(),
            &avtp_streams, &HashMap::new(), &HashSet::new(), false,
        );

        assert!(!lines.iter().any(|l| l.text.contains("PCP")));
    }

    // ── render_network_status — QoS / IGMP querier status strings ────────────

    fn network_status_inputs<'a>(
        streams: &'a HashMap<String, StreamStats>,
        health: &'a NetworkHealth,
        eee_ports: &'a HashMap<(String, String), (u16, u16)>,
    ) -> NetworkStatusInputs<'a> {
        NetworkStatusInputs {
            mbps: 0.0,
            streams,
            health,
            pause_frames: 0,
            pfc_frames: 0,
            eee_ports,
            pcap_stats: None,
            packets_dispatched: 0,
        }
    }

    #[test]
    fn qos_status_reads_no_ip_streams_when_all_ndi_or_avb() {
        let mut streams = HashMap::new();
        streams.insert("NDI a".into(), StreamStats::new("NDI", 0.0));
        streams.insert("AVB a".into(), StreamStats::new("AVB", 0.0));
        let health = NetworkHealth::new();

        let lines = render_network_status(&network_status_inputs(&streams, &health, &HashMap::new()));

        assert!(lines.iter().any(|l| l.text.contains("QoS: – (no IP streams)")),
            "got {:?}", lines.iter().map(|l| &l.text).collect::<Vec<_>>());
    }

    #[test]
    fn qos_status_reads_all_correct_when_no_dscp_violations() {
        let mut streams = HashMap::new();
        streams.insert("AES67 a".into(), StreamStats::new("AES67", 48_000.0));
        let health = NetworkHealth::new();

        let lines = render_network_status(&network_status_inputs(&streams, &health, &HashMap::new()));

        assert!(lines.iter().any(|l| l.text.contains("QoS: ✓ all streams correctly marked")),
            "got {:?}", lines.iter().map(|l| &l.text).collect::<Vec<_>>());
    }

    #[test]
    fn qos_status_reports_violation_count() {
        let mut streams = HashMap::new();
        let mut bad = StreamStats::new("AES67", 48_000.0);
        bad.dscp_violations = 3;
        streams.insert("AES67 a".into(), bad);
        let health = NetworkHealth::new();

        let lines = render_network_status(&network_status_inputs(&streams, &health, &HashMap::new()));

        assert!(lines.iter().any(|l| l.text.contains("QoS: ⚠ 1 stream(s) with incorrect DSCP")),
            "got {:?}", lines.iter().map(|l| &l.text).collect::<Vec<_>>());
    }

    #[test]
    fn igmp_status_reads_no_querier_seen() {
        let streams: HashMap<String, StreamStats> = HashMap::new();
        let health = NetworkHealth::new();

        let lines = render_network_status(&network_status_inputs(&streams, &health, &HashMap::new()));

        assert!(lines.iter().any(|l| l.text.contains("IGMP: – (no querier seen)")),
            "got {:?}", lines.iter().map(|l| &l.text).collect::<Vec<_>>());
    }

    #[test]
    fn igmp_status_reads_querier_silent_past_threshold() {
        let streams: HashMap<String, StreamStats> = HashMap::new();
        let mut health = NetworkHealth::new();
        // Default querier_silent_after_secs() is 260s with no interval established.
        health.last_igmp_query = Some(std::time::Instant::now() - Duration::from_secs(300));

        let lines = render_network_status(&network_status_inputs(&streams, &health, &HashMap::new()));

        assert!(lines.iter().any(|l| l.text.contains("IGMP: ⚠ querier silent")),
            "got {:?}", lines.iter().map(|l| &l.text).collect::<Vec<_>>());
    }

    #[test]
    fn igmp_status_reads_active_querier_with_interval_ip_and_mac() {
        let streams: HashMap<String, StreamStats> = HashMap::new();
        let mut health = NetworkHealth::new();
        health.last_igmp_query = Some(std::time::Instant::now());
        health.igmp_query_interval_secs = Some(125);
        health.igmp_querier_ip = Some(Ipv4Addr::new(192, 168, 1, 1));
        health.igmp_querier_mac = Some([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);

        let lines = render_network_status(&network_status_inputs(&streams, &health, &HashMap::new()));

        let line = lines.iter().find(|l| l.text.contains("IGMP: ✓")).expect("querier line");
        assert!(line.text.contains("192.168.1.1"), "got {}", line.text);
        assert!(line.text.contains("00:1a:2b:3c:4d:5e"), "got {}", line.text);
        assert!(line.text.contains("interval 125s"), "got {}", line.text);
    }

    // ── ReportSnapshot::from_state — self-assembling constructor ─────────────

    #[test]
    fn from_state_assembles_snapshot_from_capture_state_and_window_checks() {
        use crate::capture::CaptureState;

        let mut state = CaptureState::new();
        state.streams.insert("s1".into(), StreamStats::new("AES67", 48_000.0));
        state.dante.sources.insert(Ipv4Addr::new(169, 254, 1, 1));

        let checks = state.end_of_window(&[], false);
        let snap = ReportSnapshot::from_state(&state, &checks, Some((100, 2, 0)));

        assert_eq!(snap.streams.len(), 1, "streams must come from state.streams");
        assert_eq!(snap.dante.sources.len(), 1, "dante.sources must come from state.dante.sources");
        assert_eq!(snap.pcap_stats, Some((100, 2, 0)), "pcap_stats is the caller-supplied value");
        assert_eq!(snap.missing_ptp.len(), checks.missing_ptp.len(),
            "missing_ptp must come from the WindowChecks bundle, not be recomputed");
    }
}
