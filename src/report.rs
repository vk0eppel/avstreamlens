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
use crate::protocols::{STREAM_TIMEOUT_SECS, MsrpDeclaration, MsrpDeclType, PTP_VERSION_V1, avtp_subtype_name, msrp_failure_reason};
use crate::capture::{MissingClock, MissingClockKind};

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

/// Render a single discovery line: `   Dante (5):  "A", "B", … `.
/// `total` is the authoritative device count; `names` may be shorter (some
/// sources announce before their instance name is resolved).
fn discovered_line(label: &str, total: usize, mut names: Vec<&str>) -> String {
    names.sort_unstable();
    names.dedup();
    if names.is_empty() {
        return format!("   {} ({}):  (names not yet resolved)", label, total);
    }
    const SHOWN: usize = 6;
    let mut listed = names.iter().take(SHOWN).map(|n| format!("\"{}\"", n))
        .collect::<Vec<_>>().join(", ");
    if names.len() > SHOWN { listed.push_str(", …"); }
    format!("   {} ({}):  {}", label, total, listed)
}

/// Print the `📇 Discovered` section: devices learned from multicast mDNS and
/// Dante ConMon, plus a no-SPAN diagnostic when devices are announced but no
/// flows of that type are active (the usual fingerprint of unicast flows on a
/// non-mirrored port).
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
    logger: &mut Logger,
) {
    const UNVERIFIED_THRESHOLD: u32 = 3;

    // Split dante_sources into verified (ConMon or active stream) and flagged
    // (mDNS-only for ≥ UNVERIFIED_THRESHOLD consecutive windows).
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
        if verified_count > 0 {
            // Merge mDNS discovery count with ConMon liveness into one line.
            // Suffix: "all live" when ConMon covers every verified device,
            // "N live" when only some have active ConMon traffic, nothing when
            // ConMon is absent (e.g. before the first metering frame arrives).
            let live_count = dante_conmon.len();
            let live_suffix = if live_count == 0 {
                String::new()
            } else if live_count == verified_count {
                "  · all live".to_string()
            } else {
                format!("  · {} live", live_count)
            };
            let verified_names: Vec<&str> = dante_sources
                .iter()
                .filter(|ip| !flagged.contains(ip))
                .filter_map(|ip| dante_names.get(ip).map(|s| s.as_str()))
                .collect();
            let base = discovered_line("Dante", verified_count, verified_names);
            let line = format!("{}{}", base, live_suffix);
            logger.log(&line);
            println!("{}", line);

            // List IPs for verified devices not yet name-resolved.
            let mut unnamed: Vec<String> = dante_sources
                .iter()
                .filter(|ip| !flagged.contains(ip) && !dante_names.contains_key(ip))
                .map(|ip| ip.to_string())
                .collect();
            if !unnamed.is_empty() {
                unnamed.sort_unstable();
                let unnamed_line = format!("   ({} unnamed: {})", unnamed.len(), unnamed.join(", "));
                logger.log(&unnamed_line);
                println!("{}", unnamed_line);
            }
        }

        // Flagged devices: mDNS-only for ≥ threshold windows — likely a
        // management NIC or non-Dante device responding to Dante mDNS queries.
        if !flagged.is_empty() {
            let mut flagged_strs: Vec<String> = flagged.iter().map(|ip| {
                if let Some(name) = dante_names.get(ip) {
                    format!("{} \"{}\"", ip, name)
                } else {
                    ip.to_string()
                }
            }).collect();
            flagged_strs.sort_unstable();
            let flag_line = format!("   ⚠  Unverified (mDNS only, no ConMon): {} — may be a management NIC or non-Dante device", flagged_strs.join(", "));
            logger.log(&flag_line);
            println!("{}", ansi("33", &flag_line));
        }
    }
    if ndi_count > 0 {
        let line = discovered_line("NDI  ", ndi_count, ndi_names.values().map(|s| s.as_str()).collect());
        logger.log(&line);
        println!("{}", line);
    }

    // No-SPAN / snooping diagnostic: devices announced via mDNS but no active flows.
    // Two causes: (1) unicast flows between other devices need a SPAN port;
    // (2) on IGMP-snooping switches, even multicast flows are pruned until we
    // join the group — AVStreamLens joins automatically from SAP and IGMPv3 reports.
    if (verified_count > 0 && dante_active == 0) || (ndi_count > 0 && ndi_active == 0) {
        let alert = "   ⚠  Devices announced but no active flows\
            \n      Multicast (Dante audio, AES67): joining stream groups automatically via IGMP\
            \n      Unicast (Dante subscriptions, NDI): requires a SPAN/mirror port";
        logger.log(alert);
        println!("{}", ansi("33", alert));
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
/// - Bandwidth + stream count overview + status line
/// - `📡 Streams:` — AES67, Dante, ST2110, NDI, AVB entries with per-stream alerts
/// - `🕐 Clock Sources:` — PTP domains (omitted when none observed)
/// - `🔬 Network Health — X%:` — QoS, IGMP querier, EEE, pcap capture stats
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
    quiet: bool,
) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let header_line = format!("{} | AVStreamLens report", timestamp);

    logger.log(&header_line);

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

    // AVB is counted from avtp_streams (per stream-id) so the overview count equals
    // the number of rendered AVB lines and matches the gPTP clock-requirement gate.
    // Counting streams["AVB …"] (per-subtype) instead let sv=0 control frames show
    // "AVB: 1" with an empty Streams list.
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

    let net_summary = format!(
        "\n📊 Bandwidth: {:.1} Mbps (last 5s)  |  {}",
        mbps, streams_str
    );
    logger.log(&net_summary);

    // ── Top-level status ────────────────────────────────────────────────────
    // Stream-issue count uses per-window deltas where applicable so the status
    // line accurately reflects current conditions instead of accumulating
    // every problem ever seen in this run.
    let stream_issues = streams.values().filter(|s| {
        s.lost_this_window > 0
            || s.jitter_ms() > 20.0
            || s.ts_discontinuities_this_window > 0
            || s.ssrc_changes > 0
            || s.last_packet_time.is_some_and(|t| t.elapsed() > Duration::from_secs(STREAM_TIMEOUT_SECS))
    }).count();
    let mut parts = Vec::new();
    if stream_issues > 0 { parts.push(format!("{} stream issue(s)", stream_issues)); }
    if !missing_ptp.is_empty() {
        // Status-line summary: list affected protocol names. The detailed
        // "no <clock-type> clock — <protocols> may lose sync" alert is printed
        // separately below.
        let affected: Vec<&str> = missing_ptp.iter()
            .flat_map(|mc| mc.affected.iter().copied())
            .collect();
        parts.push(format!("no clock for {}", affected.join(", ")));
    }
    let status_line = if !parts.is_empty() {
        format!("⚠  {}", parts.join("  |  "))
    } else if streams.is_empty() {
        "–  No streams detected".to_string()
    } else {
        "✓  All streams healthy".to_string()
    };
    logger.log(&status_line);

    // ── Quiet-mode early exit ───────────────────────────────────────────────
    // When --quiet is set and the cycle is fully healthy (no stream issues,
    // no missing clocks, no pcap drops), suppress all stdout output.
    // The log file always receives the full report regardless of this flag.
    let pcap_drops_ok = pcap_stats.is_none_or(|(_, d, id)| d == 0 && id == 0);
    // '✓' = all streams healthy, '–' = no streams but no issues either — both are healthy.
    let is_healthy = (status_line.starts_with('✓') || status_line.starts_with('–')) && pcap_drops_ok;
    if quiet && is_healthy {
        logger.log("");
        return;
    }

    // From here on, output goes to both stdout and the log file.
    let rule = "─".repeat(66);
    println!("\n{}", ansi("36", &rule));
    println!("{}", ansi("36", &format!("  AVStreamLens  ·  {}", timestamp)));
    println!("{}", ansi("36", &rule));

    println!("{}", net_summary);

    if status_line.starts_with('✓') {
        println!("{}", ansi("32", &status_line));
    } else if status_line.starts_with('⚠') {
        println!("{}", ansi("33", &status_line));
    } else {
        println!("{}", status_line);
    }

    // ── Streams (all protocols unified) ────────────────────────────────────
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

        // AVB aggregate entries are superseded by per-AVTP-stream rendering below
        if s.protocol == "AVB" || s.protocol.starts_with("AVB ") { continue; }

        // Protocol label: prefix ST2110 subtypes clearly; tag AES67 streams whose
        // source IP is a known Dante device (AES67-mode Dante).
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

        // Dante: show [unicast] or [multicast] so the engineer knows immediately
        // whether the stream requires IGMP/multicast switch configuration.
        let multicast_tag = if s.protocol == "Dante" {
            if s.is_multicast { "  [multicast]" } else { "  [unicast]" }
        } else { "" };

        let stream_line = format!("  ▸ {}{}{}{}{}", proto_label, multicast_tag, name_str, codec_str, addr_str);
        logger.log(&stream_line);
        println!("{}", stream_line);

        // NDI: show TCP connection quality instead of RTP loss/jitter (NDI uses TCP, not RTP)
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
            // ATP framing (official Dante ports 4321 / 14336–15359) is not RTP —
            // showing "loss: 0.0% | jitter: 0.00 ms" would present unmeasured
            // values as healthy. Presence and bitrate are real; say what isn't.
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

        // Per-window deltas — these alerts only fire when fresh activity
        // occurred in the last 5s, so a single old loss does not re-alert forever.
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

        // Reorder rate — distinct from loss. >1% suggests per-packet ECMP/LAG
        // load-balancing, which breaks ordered AV streams even without drops.
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

        // Routing check: Dante must stay on L2; a TTL < 64 means a router decremented
        // it (Linux/macOS sources start at 64; any router hop → ≤ 63). Windows sources
        // start at 128 so a routed Windows device would show 127 — not caught here.
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

        // 0.1% loss ≈ ~3 dropped packets per 5s window at 1ms ptime — below that is
        // usually capture jitter, not a real subscription/clock fault.
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

        // Gap 2: payload type mismatch
        if s.pt_mismatches > 0 {
            let alert = format!("    ⚠  RTP payload type mismatch ({} packet(s)) — encoder/SDP misconfiguration", s.pt_mismatches);
            logger.log(&alert);
            println!("{}", ansi("33", &alert));
        }

        // Gap 3: stream not yet announced via SAP
        // Only applies to RTP-based protocols that carry SDP (AES67, ST2110, Dante).
        // AVB and NDI never publish SDP — skip the warning. Dante ATP flows
        // (rtp_seen == false) are not RTP and never have SAP either.
        let expects_sdp = (s.protocol == "AES67"
            || s.protocol == "Dante"
            || s.protocol.starts_with("2110-"))
            && s.rtp_seen;
        if expects_sdp && !s.clock_hz_confirmed && s.packets > 10 {
            let alert = "    ⚠  Stream not announced (no SAP) — audio glitch detection unavailable";
            logger.log(alert);
            println!("{}", ansi("33", alert));
        }

        // ST2110 unclassified stream type
        if s.protocol == "2110-??" {
            let alert = "    ⚠  Stream type unknown — SDP required to classify as video/audio/ancillary";
            logger.log(alert);
            println!("{}", ansi("33", alert));
        }

        // Gap 4: signal gap events (IAT > 50ms).
        // Require at least 2 events per 5s window — a single spike is typically
        // a pcap scheduling artifact on the capture host, not a real interruption.
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

    // ── AVB per-stream entries (AVTP stream IDs with MSRP/VLAN inline) ────────
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

            // MSRP reservation state for this stream
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

    // ── Discovered devices (mDNS) ────────────────────────────────────────────
    // mDNS is multicast, so device announcements are visible even on a plain
    // (non-SPAN) switch port where the actual unicast audio/video never arrives.
    let dante_active = streams.values().filter(|s| s.protocol == "Dante").count();
    let ndi_active   = streams.values().filter(|s| s.protocol == "NDI").count();
    print_discovery(dante_sources, dante_names, dante_conmon, dante_unverified_windows, ndi_sources, ndi_names, dante_active, ndi_active, logger);
    print_avdecc_entities(avdecc_entities, logger);

    // ── PTP / Clock Sources ─────────────────────────────────────────────────
    if !ptp_domains.is_empty() {
        logger.log("\nClock Sources:");
        println!("\n{}", ansi("36", "🕐 Clock Sources:"));

        let multi_domain = ptp_domains.len() > 1;

        for ((domain, version), stats) in ptp_domains.iter() {
            let gm_icon = if stats.clock_valid { "✓" } else if stats.last_grandmaster.is_some() { "⚠" } else { "❌" };

            // Primary label: protocol association (Dante, AES67/ST2110, AVB, …)
            let proto_label = stats.protocol_kind.as_deref().unwrap_or("PTP");
            // Show domain number only when multiple domains exist (to distinguish them)
            let domain_suffix = if multi_domain || *domain > 0 {
                format!("  (domain {})", domain)
            } else {
                String::new()
            };

            let clock_line = match (&stats.last_grandmaster, stats.clock_valid) {
                (Some(gm), true) => {
                    // Use the grandmaster's own IP (not the last sender in the domain).
                    let gm_ip = stats.grandmaster_src_ip.or(stats.last_src_ip);
                    let ip_str = gm_ip.map(|ip| format!("  ({})", ip)).unwrap_or_default();
                    // Identify the grandmaster the way an operator thinks about it:
                    //  1. a discovered Dante device name (from mDNS) if we have one;
                    //  2. else for PTPv1 (Dante) drop the gmClockUuid — it is a firmware
                    //     constant (00:00:00:01:00:1d), identical on every device, so the
                    //     IP is the only real discriminator;
                    //  3. else (PTPv2 / gPTP) keep the EUI-64 — it really identifies the GM.
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
                    // No Announce/grandmaster. Distinguish a clock that is at least
                    // emitting Sync (no GM elected yet) from a node that only sends
                    // P_Delay_Req link-measurement traffic — the latter, with no
                    // Pdelay_Resp, signals the link partner isn't gPTP-capable.
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

            // gPTP is link-local (dest MAC 01:80:C2:00:00:0E) and never forwarded by
            // bridges — so the grandmaster's Announce is only visible on a time-aware
            // (AVB-enabled) port. When all we see on this port is P_Delay_Req from an
            // AVB node (no Sync, no grandmaster), tell the operator where to look
            // instead of leaving them to wonder why the configured GM is absent.
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

            // Path-delay tracking: report min..max spread and alert on instability
            // (>10µs spread = unstable link; >1ms absolute = too many hops).
            if let (Some(min), Some(max)) = (stats.min_path_delay_ns, stats.max_path_delay_ns) {
                let spread_ns = max - min;
                let fmt = |ns: i64| if ns.unsigned_abs() >= 1_000 {
                    format!("{:.1}µs", ns as f64 / 1_000.0)
                } else {
                    format!("{}ns", ns)
                };
                // Rough hop estimate: ~5µs per gigabit switch.
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
                // Dante-specific latency advisory: Audinate's recommended minimums by hop count.
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
    }

    // ── Clock source required but absent ───────────────────────────────────
    // One alert per missing-clock family so the user immediately knows which
    // clock type (PTPv2 / PTPv1-or-v2 / L2 gPTP) is needed and which protocol
    // family is at risk because of it.
    for mc in missing_ptp {
        let alert = format_missing_clock(mc);
        logger.log(&alert);
        println!("{}", ansi("31", &alert));
    }

    // ── Network health ──────────────────────────────────────────────────────
    let score = format!("{:.0}%", health.network_score);
    logger.log(&format!("\nNetwork Health — {}:", score));
    println!("\n{}", ansi("36", &format!("🔬 Network Health — {}:", score)));

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
                // Querier is silent — suppress the stale (interval) from previous queries.
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

    // Link-layer flow control (PAUSE / PFC). Most NICs strip these in hardware
    // and pcap never sees them; when they DO reach userspace, even one frame is
    // a strong signal of upstream congestion causing tx-side freezes.
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

    // ── pcap capture stats ──────────────────────────────────────────────────
    // Kernel drops mean the ring buffer overflowed — packets were received by
    // the NIC but discarded before pcap handed them to us. Even a small drop
    // count corrupts loss and jitter measurements for all streams.
    if let Some((received, dropped, if_dropped)) = pcap_stats {
        let stats_line = format!(
            "   📦 {:} pkts received  |  {} kernel drop(s)  |  {} interface drop(s)  |  {} parsed",
            received, dropped, if_dropped, packets_dispatched
        );
        logger.log(&stats_line);
        if dropped > 0 || if_dropped > 0 {
            // Red: drops actively corrupt loss/jitter numbers — engineer must act.
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
/// Names the clock type plainly and joins the affected protocols with commas
/// (and "and" before the last item).
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
