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
use std::collections::HashMap;
use std::time::Duration;

use crate::stats::{AvdeccEntity, ConmonDevice, StreamStats, TcpStreamStats, PtpStats, NetworkHealth, StreamQuality, AvtpStreamStats};
use crate::parser::{fmt_eui64, media_type_summary, sr_class_str};
use crate::protocols::{STREAM_TIMEOUT_SECS, MsrpDeclaration, MsrpDeclType, PTP_VERSION_V1, TransmitterConfidence, TransmitterVerdict, avtp_subtype_name, msrp_failure_reason};
use crate::capture::{Alert, emit as emit_alerts, MissingClock, MissingClockKind};

/// Logger for writing timestamped messages to both file and console.
#[derive(Debug)]
pub struct Logger {
    file: std::fs::File,
}

impl Logger {
    /// Create a new logger with a filename based on protocol prefix and timestamp.
    pub fn new(prefix: &str) -> std::io::Result<Self> {
        let now = Local::now();
        let filename = format!(
            "avstreamlens_{}-{:02}-{:02}_{:02}-{:02}-{:02}_{}.log",
            now.year(), now.month(), now.day(), now.hour(), now.minute(), now.second(), prefix
        );
        let file = std::fs::File::create(filename)?;
        Ok(Logger { file })
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

/// Print the `📇 Discovered` section: devices learned from multicast mDNS and
/// Dante ConMon, plus periodic diagnostics for the Discovered section.
/// One line per device; unverified devices shown inline with ⚠ prefix.
/// The no-active-flows diagnostic appears at most once per session (flag lives at call site).
#[allow(clippy::too_many_arguments)]
fn print_discovery(
    dante_sources: &std::collections::HashSet<std::net::Ipv4Addr>,
    dante_names:   &HashMap<std::net::Ipv4Addr, String>,
    dante_conmon:  &HashMap<std::net::Ipv4Addr, ConmonDevice>,
    dante_unverified_windows: &HashMap<std::net::Ipv4Addr, u32>,
    ndi_sources:   &std::collections::HashSet<std::net::Ipv4Addr>,
    ndi_names:     &HashMap<std::net::Ipv4Addr, String>,
    dante_active: usize,
    ndi_active: usize,
    streams: &HashMap<String, StreamStats>,
    ip_config_alerts: &[Alert],
    conmon_bridge_alerts: &[Alert],
    no_flows_diagnostic_shown: &mut bool,
    logger: &mut Logger,
) {
    const UNVERIFIED_THRESHOLD: u32 = 3;

    let flagged: std::collections::HashSet<std::net::Ipv4Addr> = dante_sources
        .iter()
        .filter(|ip| dante_unverified_windows.get(ip).copied().unwrap_or(0) >= UNVERIFIED_THRESHOLD)
        .copied()
        .collect();
    let verified_count = dante_sources.len() - flagged.len();

    let ndi_count = ndi_sources.len();
    if verified_count == 0 && flagged.is_empty() && ndi_count == 0 { return; }

    logger.log("\nDiscovered:");
    println!("\n{}", ansi("36", "📇 Discovered:"));

    if verified_count > 0 || !flagged.is_empty() {
        let live_count = dante_conmon.len();
        let live_suffix = if live_count == 0 {
            String::new()
        } else if live_count == verified_count {
            "  · all live".to_string()
        } else {
            format!("  · {} live", live_count)
        };
        let subheader = format!("  Dante ({}){}", verified_count, live_suffix);
        logger.log(&subheader);
        println!("{}", subheader);

        // Verified devices sorted by IP — named first, then pending
        let mut verified: Vec<std::net::Ipv4Addr> = dante_sources.iter()
            .filter(|ip| !flagged.contains(ip))
            .copied()
            .collect();
        verified.sort();
        for ip in &verified {
            let suffix = tx_flow_suffix(streams, *ip);
            let line = if let Some(name) = dante_names.get(ip) {
                format!("  ▸ \"{}\"   {}{}", name, ip, suffix)
            } else {
                format!("  ▸ {}   (name pending){}", ip, suffix)
            };
            logger.log(&line);
            println!("{}", line);
        }

        // Unverified devices inline (mDNS-only ≥ threshold windows)
        let mut flagged_sorted: Vec<std::net::Ipv4Addr> = flagged.iter().copied().collect();
        flagged_sorted.sort();
        for ip in &flagged_sorted {
            let suffix = tx_flow_suffix(streams, *ip);
            let line = if let Some(name) = dante_names.get(ip) {
                format!("  ⚠  \"{}\"   {}   (mDNS only, no ConMon){}", name, ip, suffix)
            } else {
                format!("  ⚠  {}   (mDNS only, no ConMon){}", ip, suffix)
            };
            logger.log(&line);
            println!("{}", ansi("33", &line));
        }
    }

    if ndi_count > 0 {
        let subheader = format!("  NDI ({})", ndi_count);
        logger.log(&subheader);
        println!("{}", subheader);

        let mut ndi_sorted: Vec<std::net::Ipv4Addr> = ndi_sources.iter().copied().collect();
        ndi_sorted.sort();
        for ip in &ndi_sorted {
            let line = if let Some(name) = ndi_names.get(ip) {
                format!("  ▸ \"{}\"   {}", name, ip)
            } else {
                format!("  ▸ {}   (name pending)", ip)
            };
            logger.log(&line);
            println!("{}", line);
        }
    }

    // Periodic diagnostics: IP config and redundancy bridge
    emit_alerts(ip_config_alerts, logger);
    emit_alerts(conmon_bridge_alerts, logger);

    // No-active-flows diagnostic — shown at most once per session
    let no_flows = (verified_count > 0 && dante_active == 0) || (ndi_count > 0 && ndi_active == 0);
    if no_flows && !*no_flows_diagnostic_shown {
        let alert = "  ⚠  Devices announced but no active flows — mirror port may be needed";
        logger.log(alert);
        println!("{}", ansi("33", alert));
        *no_flows_diagnostic_shown = true;
    }
}

/// Print AVDECC entities discovered via ADP in a "📡 Discovered (AVDECC):" block.
/// Each entity shows its entity_id, role (talker/listener), SR class, AEM flag,
/// and the gPTP grandmaster it is currently using.
fn print_avdecc_entities(
    entities: &HashMap<[u8; 8], AvdeccEntity>,
    logger: &mut Logger,
) {
    if entities.is_empty() { return; }

    logger.log(&format!("\nDiscovered (AVDECC — {} {}):{}",
        entities.len(), if entities.len() == 1 { "entity" } else { "entities" }, ""));
    println!("\n{}", ansi("36", &format!("📡 Discovered (AVDECC — {} {}):",
        entities.len(), if entities.len() == 1 { "entity" } else { "entities" })));

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

        let line1 = format!("  ▸ {}  {}  {}{}{}", eui, role, class, aem, not_ready);
        logger.log(&line1);
        println!("{}", line1);

        let gm = fmt_eui64(&e.gptp_grandmaster_id);
        let all_zero = e.gptp_grandmaster_id == [0u8; 8];
        let gm_str = if all_zero { "no grandmaster".to_string() }
                     else { format!("GM: {}  domain {}", gm, e.gptp_domain_number) };
        let line2 = format!("    model {}  {}", model, gm_str);
        logger.log(&line2);
        println!("{}", line2);
    }
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
#[allow(clippy::too_many_arguments)]
pub fn print_report(
    streams: &HashMap<String, StreamStats>,
    tcp_streams: &HashMap<String, TcpStreamStats>,
    ptp_domains: &HashMap<(u8, u8), PtpStats>,
    missing_ptp: &[MissingClock],
    logger: &mut Logger,
    health: &NetworkHealth,
    bytes_this_window: u64,
    avtp_streams: &HashMap<[u8; 8], AvtpStreamStats>,
    msrp_state: &HashMap<[u8; 8], MsrpDeclaration>,
    mvrp_vlans: &std::collections::HashSet<u16>,
    eee_ports: &std::collections::HashMap<(String, String), (u16, u16)>,
    dante_sources: &std::collections::HashSet<std::net::Ipv4Addr>,
    dante_names: &HashMap<std::net::Ipv4Addr, String>,
    dante_conmon: &HashMap<std::net::Ipv4Addr, ConmonDevice>,
    dante_unverified_windows: &HashMap<std::net::Ipv4Addr, u32>,
    ndi_sources: &std::collections::HashSet<std::net::Ipv4Addr>,
    ndi_names: &HashMap<std::net::Ipv4Addr, String>,
    avdecc_entities: &HashMap<[u8; 8], AvdeccEntity>,
    pause_frames: u64,
    pfc_frames: u64,
    pcap_stats: Option<(u32, u32, u32)>,
    packets_dispatched: u64,
    ip_config_alerts: &[Alert],
    conmon_bridge_alerts: &[Alert],
    follower_census_alerts: &[Alert],
    ptp_sync_alerts: &[Alert],
    no_flows_diagnostic_shown: &mut bool,
    quiet: bool,
) {
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
        health.build_health_summary(streams, tcp_streams, ptp_domains, msrp_state, eee_ports);

    // ── Quiet-mode early exit ───────────────────────────────────────────────
    // Healthy = no Health Summary bullets AND no pcap drops. pcap drops are not a
    // score factor, but they still force output so the operator sees the
    // "measurements may be understated" warning in Network Status.
    let pcap_drops_ok = pcap_stats.is_none_or(|(_, d, id)| d == 0 && id == 0);
    if quiet && health_summary.is_empty() && pcap_drops_ok {
        logger.log("");
        return;
    }

    // ── 1. Report header block + Health Score ──────────────────────────────
    let score = format!("{:.0}%", health.network_score);
    let rule = "─".repeat(66);
    logger.log(&format!("\n{}", rule));
    logger.log(&format!("  AVStreamLens  ·  {}", full_timestamp));
    logger.log(&rule);
    println!("\n{}", ansi("36", &rule));
    println!("{}", ansi("36", &format!("  AVStreamLens  ·  {}", full_timestamp)));
    println!("{}", ansi("36", &rule));

    // Time is already in the header rule line above (full date + time) — don't repeat it here.
    let header = if proto_parts.is_empty() {
        format!("\n🔬 Network Health — {}", score)
    } else {
        format!("\n🔬 Network Health — {}  |  {}", score, streams_str)
    };
    logger.log(&format!("Network Health — {}  |  {}", score, streams_str));
    println!("{}", ansi("36", &header));

    // ── 2. Health Summary ───────────────────────────────────────────────────
    // Rendered only when the Health Score is below 100% (non-empty summary). A
    // fully healthy report shows no status line at all — the score line says 100%.
    for bullet in &health_summary {
        logger.log(bullet);
        println!("{}", ansi("33", bullet));
    }

    // ── 3. Discovered (mDNS/ConMon) ────────────────────────────────────────
    let dante_active = streams.values().filter(|s| s.protocol == "Dante").count();
    let ndi_active   = streams.values().filter(|s| s.protocol == "NDI").count();
    print_discovery(
        dante_sources, dante_names, dante_conmon, dante_unverified_windows,
        ndi_sources, ndi_names, dante_active, ndi_active, streams,
        ip_config_alerts, conmon_bridge_alerts, no_flows_diagnostic_shown, logger,
    );

    // ── 4. Discovered (AVDECC) ──────────────────────────────────────────────
    print_avdecc_entities(avdecc_entities, logger);

    // ── 5. Clock Sources ────────────────────────────────────────────────────
    let has_clock_content = !ptp_domains.is_empty()
        || !missing_ptp.is_empty()
        || !follower_census_alerts.is_empty()
        || !ptp_sync_alerts.is_empty();

    if has_clock_content {
        logger.log("\nClock Sources:");
        println!("\n{}", ansi("36", "🕐 Clock Sources:"));

        let multi_domain = ptp_domains.len() > 1;

        for ((domain, version), stats) in ptp_domains.iter() {
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
                    format!("  {}  {}{}  —{}{}", gm_icon, proto_label, domain_suffix, id_part, ip_str)
                }
                (Some(_), false) => {
                    format!("  {}  {}{}  —  clock lost", gm_icon, proto_label, domain_suffix)
                }
                (None, _) => {
                    match &stats.last_clock_id {
                        Some(id) if stats.seen_sync =>
                            format!("  ○  {}{}  —  clock source: {}  (Sync seen, no Announce — no grandmaster elected)", proto_label, domain_suffix, id),
                        Some(id) =>
                            format!("  ○  {}{}  —  clock source: {}  (peer-delay requests only — no Sync/grandmaster; link partner may not be gPTP-capable)", proto_label, domain_suffix, id),
                        None =>
                            format!("  {}  {}{}  —  no clock detected", gm_icon, proto_label, domain_suffix),
                    }
                }
            };
            logger.log(&clock_line);
            println!("{}", clock_line);

            if stats.protocol_kind.as_deref() == Some("AVB")
                && stats.last_grandmaster.is_none()
                && !stats.seen_sync
                && stats.last_clock_id.is_some()
            {
                let hint = "    ℹ  gPTP is link-local — the grandmaster is only visible on a time-aware (AVB-enabled) port";
                logger.log(hint);
                println!("{}", hint);
            }

            if let Some(ref q) = stats.last_quality {
                let quality_line = format!("    clock quality: {}", q);
                logger.log(&quality_line);
                println!("{}", quality_line);
            }

            if let Some(offset_ns) = stats.last_offset_ns
                && offset_ns != 0
            {
                let offset_line = if offset_ns.unsigned_abs() >= 1_000 {
                    format!("    correction: {:.1} µs", offset_ns as f64 / 1_000.0)
                } else {
                    format!("    correction: {} ns", offset_ns)
                };
                logger.log(&offset_line);
                println!("{}", offset_line);
                if offset_ns.unsigned_abs() > 1_000 {
                    let alert = "    ⚠  Large PTP correction field — transparent clock or path issue";
                    logger.log(alert);
                    println!("{}", ansi("33", alert));
                }
            }

            if let (Some(min), Some(max)) = (stats.min_path_delay_ns, stats.max_path_delay_ns) {
                let spread_ns = max - min;
                let fmt = |ns: i64| if ns.unsigned_abs() >= 1_000 {
                    format!("{:.1}µs", ns as f64 / 1_000.0)
                } else {
                    format!("{}ns", ns)
                };
                let hops = (min / 5_000).max(0) as u32;
                let hops_str = if hops > 0 { format!("  ~{} hop{}", hops, if hops == 1 { "" } else { "s" }) } else { String::new() };
                let line = if min == max {
                    format!("    path delay: {}{}", fmt(max), hops_str)
                } else {
                    format!("    path delay: {} – {}  (spread {}){}", fmt(min), fmt(max), fmt(spread_ns), hops_str)
                };
                logger.log(&line);
                println!("{}", line);
                if spread_ns > 10_000 {
                    let alert = "    ⚠  PTP path-delay variance > 10µs — unstable link (EEE, half-duplex, or cable)";
                    logger.log(alert);
                    println!("{}", ansi("33", alert));
                }
                if max > 1_000_000 {
                    let alert = "    ⚠  PTP path delay > 1ms — too many hops between this node and grandmaster";
                    logger.log(alert);
                    println!("{}", ansi("33", alert));
                }
                if *version == PTP_VERSION_V1 && hops >= 3 {
                    let min_latency = if hops >= 10 { "5ms" } else if hops >= 5 { "2ms" } else { "0.5ms" };
                    let advisory = format!("    ℹ  {} hops: Dante latency should be ≥ {}", hops, min_latency);
                    logger.log(&advisory);
                    println!("{}", advisory);
                }
            }

            if stats.protocol_clock_lost {
                let alert = "    ⚠  Clock lost — grandmaster disappeared";
                logger.log(alert);
                println!("{}", ansi("33", alert));
            }

            if stats.protocol_changes_count > 0 {
                let alert = format!("    ⚠  Clock source changed {} time(s)", stats.protocol_changes_count);
                logger.log(&alert);
                println!("{}", ansi("33", &alert));
            }
        }

        // Missing clock alerts
        for mc in missing_ptp {
            let alert = format_missing_clock(mc);
            logger.log(&alert);
            println!("{}", ansi("31", &alert));
        }

        // Follower census and sync conflict belong inside Clock Sources
        emit_alerts(follower_census_alerts, logger);
        emit_alerts(ptp_sync_alerts, logger);
    }

    // ── 6. Streams (all protocols unified) ─────────────────────────────────
    logger.log("\nStreams:");
    println!("\n{}", ansi("36", "📡 Streams:"));

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
        let stream_line = format!("  ▸ {}{}{}{}{}{}", proto_label, multicast_tag, name_str, codec_str, addr_str, tx_tag);
        logger.log(&stream_line);
        println!("{}", stream_line);

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
                format!("    {}  |  {:.1} Mbps  |  retrans: {}",
                    quality_str, t.bitrate_bps as f64 / 1_000_000.0, t.retransmissions)
            } else {
                format!("    {:.1} Mbps", s.bitrate_bps as f64 / 1_000_000.0)
            };
            logger.log(&metrics);
            println!("{}", metrics);
        } else if s.protocol == "Dante" && !s.rtp_seen {
            let metrics = format!(
                "    {} pkts  |  {:.1} Mbps  (ATP framing — loss/jitter unavailable)",
                s.packets, s.bitrate_bps as f64 / 1_000_000.0
            );
            logger.log(&metrics);
            println!("{}", metrics);
        } else {
            let metrics = format!(
                "    loss: {:.1}%  |  jitter: {:.2} ms  |  {:.1} Mbps",
                s.loss_pct(), s.jitter_ms(), s.bitrate_bps as f64 / 1_000_000.0
            );
            logger.log(&metrics);
            println!("{}", metrics);
        }

        if s.ts_discontinuities_this_window > 0 {
            let alert = format!(
                "    ⚠  Audio glitch risk — timing discontinuity detected ({} in last 5s)",
                s.ts_discontinuities_this_window
            );
            logger.log(&alert);
            println!("{}", ansi("33", &alert));
        }

        if s.lost_this_window > 0 {
            let alert = format!(
                "    ⚠  Packet loss detected ({} in last 5s, {:.2}% cumulative)",
                s.lost_this_window, s.loss_pct()
            );
            logger.log(&alert);
            println!("{}", ansi("33", &alert));
        }

        if s.reorders_this_window > 0 {
            let total = (s.packets + s.lost_packets).max(1);
            let pct = 100.0 * s.reorders_this_window as f64 / total as f64;
            if pct > 1.0 {
                let alert = format!(
                    "    ⚠  Packet reorder {:.1}% ({} in last 5s) — possible per-packet load-balancing",
                    pct, s.reorders_this_window
                );
                logger.log(&alert);
                println!("{}", ansi("33", &alert));
            }
        }

        if s.dscp_violations > 0 {
            let expected = if s.protocol == "2110-20" { "EF (46), AF41 (34), or CS5 (40)" } else { "EF (46)" };
            let alert = format!(
                "    ⚠  QoS: {} packet(s) not marked {} — may be deprioritised by switches",
                s.dscp_violations, expected
            );
            logger.log(&alert);
            println!("{}", ansi("33", &alert));
        }

        if s.protocol == "Dante" && s.min_ttl.is_some_and(|t| t < 64) {
            let alert = format!(
                "    ⚠  Dante traffic routed (TTL {}) — Dante is L2-only; a router is in the path",
                s.min_ttl.unwrap()
            );
            logger.log(&alert);
            println!("{}", ansi("33", &alert));
        }

        if s.jitter_ms() > 20.0 {
            let alert = "    ⚠  High jitter — stream quality at risk";
            logger.log(alert);
            println!("{}", ansi("33", alert));
        }

        if s.protocol == "AES67" && s.jitter_ms() > 10.0 {
            let alert = "    ⚠  AES67 timing issue — check PTP lock";
            logger.log(alert);
            println!("{}", ansi("33", alert));
        }

        if s.protocol == "Dante" && (s.loss_pct() > 0.1 || s.jitter_ms() > 15.0) {
            let alert = "    ⚠  Dante clock or subscription issue";
            logger.log(alert);
            println!("{}", ansi("33", alert));
        }

        if s.ssrc_changes > 0 {
            let alert = format!("    ⚠  Source interrupted and reconnected ({} time(s))", s.ssrc_changes);
            logger.log(&alert);
            println!("{}", ansi("33", &alert));
        }

        if s.pt_mismatches > 0 {
            let alert = format!("    ⚠  RTP payload type mismatch ({} packet(s)) — encoder/SDP misconfiguration", s.pt_mismatches);
            logger.log(&alert);
            println!("{}", ansi("33", &alert));
        }

        let expects_sdp = (s.protocol == "AES67"
            || s.protocol == "Dante"
            || s.protocol.starts_with("2110-"))
            && s.rtp_seen;
        if expects_sdp && !s.clock_hz_confirmed && s.packets > 10 {
            let alert = "    ⚠  Stream not announced (no SAP) — audio glitch detection unavailable";
            logger.log(alert);
            println!("{}", ansi("33", alert));
        }

        if s.protocol == "2110-??" {
            let alert = "    ⚠  Stream type unknown — SDP required to classify as video/audio/ancillary";
            logger.log(alert);
            println!("{}", ansi("33", alert));
        }

        if s.gap_events >= 2 {
            let alert = format!(
                "    ⚠  Signal gap detected ({} in last 5s, worst {:.1} ms) — stream interrupted",
                s.gap_events, s.max_iat_ms
            );
            logger.log(&alert);
            println!("{}", ansi("33", &alert));
        }

        if let Some(last_time) = s.last_packet_time
            && last_time.elapsed() > Duration::from_secs(STREAM_TIMEOUT_SECS)
        {
            let alert = format!("    💀 No signal for {:.0}s", last_time.elapsed().as_secs_f64());
            logger.log(&alert);
            println!("{}", ansi("31", &alert));
        }
    }

    // AVB per-stream entries (AVTP stream IDs with MSRP/VLAN inline)
    if !avtp_streams.is_empty() {
        let mut sorted: Vec<&AvtpStreamStats> = avtp_streams.values().collect();
        sorted.sort_by_key(|s| s.stream_id);
        for avtp in sorted {
            let dead = avtp.last_seen.elapsed() > Duration::from_secs(STREAM_TIMEOUT_SECS);
            let stream_line = format!("  ▸ AVB  {}  —  {}",
                avtp_subtype_name(avtp.subtype), avtp.stream_id_str());
            logger.log(&stream_line);
            println!("{}", stream_line);

            let metrics = format!(
                "    loss: {:.1}%  |  {:.1} Mbps",
                avtp.loss_pct(), avtp.bitrate_bps as f64 / 1_000_000.0
            );
            logger.log(&metrics);
            println!("{}", metrics);

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
                        let res_line = format!("    ✓  Reserved{}{}{}", vlan, prio, listener_str);
                        logger.log(&res_line);
                        println!("{}", res_line);
                    }
                    MsrpDeclType::TalkerFailed => {
                        let code_str = match talker.failure_code {
                            Some(code) => format!("code {}: {}", code, msrp_failure_reason(code)),
                            None       => "failed".to_string(),
                        };
                        let alert = format!("    ⚠  Reservation failed — {}", code_str);
                        logger.log(&alert);
                        println!("{}", ansi("33", &alert));
                    }
                    MsrpDeclType::Listener => {}
                }
            } else if mvrp_vlans.is_empty() {
                let alert = "    ⚠  No VLAN registration — L2 QoS may not be configured";
                logger.log(alert);
                println!("{}", ansi("33", alert));
            }

            if dead {
                let alert = format!("    💀 No signal for {:.0}s", avtp.last_seen.elapsed().as_secs_f64());
                logger.log(&alert);
                println!("{}", ansi("31", &alert));
            }
        }
    }

    // ── 7. Network Status ───────────────────────────────────────────────────
    logger.log("\nNetwork Status:");
    println!("\n{}", ansi("36", "📊 Network Status:"));

    // Bandwidth
    let bw_line = format!("   Bandwidth: {:.1} Mbps (last 5s)", mbps);
    logger.log(&bw_line);
    println!("{}", bw_line);

    let dscp_bad = streams.values().filter(|s| s.dscp_violations > 0).count();
    let qos_str = if streams.values().all(|s| s.protocol == "NDI" || s.protocol == "AVB" || s.protocol.starts_with("AVB ")) {
        "QoS: – (no IP streams)".to_string()
    } else if dscp_bad == 0 {
        "QoS: ✓ all streams correctly marked".to_string()
    } else {
        format!("QoS: ⚠ {} stream(s) with incorrect DSCP", dscp_bad)
    };

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

    let breakdown = format!("   {}  |  {}", qos_str, querier_str);
    logger.log(&breakdown);
    println!("{}", breakdown);

    if health.ecn_congestion_marks > 0 {
        let alert = format!(
            "   ⚠  ECN: {} congestion mark(s) — router congestion detected on the path",
            health.ecn_congestion_marks
        );
        logger.log(&alert);
        println!("{}", ansi("33", &alert));
    }

    if pause_frames > 0 {
        let alert = format!(
            "   ⚠  PAUSE frames: {} in last 5s — upstream link congestion causing tx-side freezes",
            pause_frames
        );
        logger.log(&alert);
        println!("{}", ansi("33", &alert));
    }
    if pfc_frames > 0 {
        let alert = format!(
            "   ⚠  PFC frames: {} in last 5s — priority flow control engaged on upstream link",
            pfc_frames
        );
        logger.log(&alert);
        println!("{}", ansi("33", &alert));
    }

    if !eee_ports.is_empty() {
        let eee_alert = format!(
            "   ⚠  EEE active on {} switch port(s) — may cause audio/video glitches  (disable EEE on all AV switch ports)",
            eee_ports.len()
        );
        logger.log(&eee_alert);
        println!("{}", ansi("33", &eee_alert));
        for ((chassis, port), (tx, rx)) in eee_ports.iter() {
            let detail = format!("      port \"{}\"  chassis {}  Tx wake: {}µs  Rx wake: {}µs", port, chassis, tx, rx);
            logger.log(&detail);
            println!("{}", detail);
        }
    }

    if let Some((received, dropped, if_dropped)) = pcap_stats {
        let stats_line = format!(
            "   📦 {:} pkts received  |  {} kernel drop(s)  |  {} interface drop(s)  |  {} parsed",
            received, dropped, if_dropped, packets_dispatched
        );
        logger.log(&stats_line);
        if dropped > 0 || if_dropped > 0 {
            println!("{}", ansi("31", &stats_line));
            let warn = "   ❌ Capture drops detected — loss/jitter figures may be understated. \
                        Reduce load or increase pcap buffer size.";
            logger.log(warn);
            println!("{}", ansi("31", warn));
        } else {
            println!("{}", stats_line);
        }
    } else {
        let line = format!("   📦 {} parsed", packets_dispatched);
        logger.log(&line);
        println!("{}", line);
    }

    logger.log("");
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
}
