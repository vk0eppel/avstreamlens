// AVStreamLens — src/report.rs
// Reporting and output formatting for stream monitoring results.

use chrono::{Datelike, Timelike, Local};
use std::collections::HashMap;
use std::time::Duration;

use crate::stats::{StreamStats, TcpStreamStats, PtpStats, NetworkHealth, StreamQuality, AvtpStreamStats};
use crate::protocols::{STREAM_TIMEOUT_SECS, MsrpDeclaration, MsrpDeclType, avtp_subtype_name};

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

///
/// Displays:
/// - Network load summary
/// - RTP stream statistics (AES67, ST2110, Dante, NDI, SRT, RIST, AVB)
/// - TCP stream quality and diagnostics
/// - PTP domain synchronization status
/// - Protocol-specific warnings and alerts
#[allow(clippy::too_many_arguments)]
pub fn print_report(
    streams: &HashMap<String, StreamStats>,
    tcp_streams: &HashMap<String, TcpStreamStats>,
    ptp_domains: &HashMap<(u8, u8), PtpStats>,
    requires_valid_ptp: bool,
    logger: &mut Logger,
    health: &NetworkHealth,
    bytes_this_window: u64,
    avtp_streams: &HashMap<[u8; 8], AvtpStreamStats>,
    msrp_state: &HashMap<[u8; 8], MsrpDeclaration>,
    mvrp_vlans: &std::collections::HashSet<u16>,
    eee_ports: &std::collections::HashMap<(String, String), (u16, u16)>,
) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let score = format!("{:.0}%", health.network_score);
    
    let header_line = format!("{} | AVStreamLens report  |  Health: {}", timestamp, score);

    logger.log(&header_line);

    println!("\n\x1b[36m╔═════════════════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[36m║  {}\x1b[0m", header_line);
    println!("\x1b[36m╚═════════════════════════════════════════════════════════════════╝\x1b[0m");

    let mbps = bytes_this_window as f64 * 8.0 / 5_000_000.0;

    type ProtocolGroup = (&'static str, fn(&str) -> bool);
    let protocol_groups: &[ProtocolGroup] = &[
        ("AES67",  |p| p == "AES67"),
        ("ST2110", |p| p.starts_with("2110-")),
        ("Dante",  |p| p == "Dante"),
        ("NDI",    |p| p == "NDI"),
        ("AVB",    |p| p == "AVB" || p.starts_with("AVB ")),
    ];

    let mut proto_parts: Vec<String> = protocol_groups.iter()
        .filter_map(|(label, matches)| {
            let n = streams.values().filter(|s| matches(&s.protocol)).count();
            if n > 0 { Some(format!("{}: {}", label, n)) } else { None }
        })
        .collect();

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
    println!("{}", net_summary);

    // ── Top-level status ────────────────────────────────────────────────────
    let stream_issues = streams.values().filter(|s| {
        s.loss_pct() > 0.0
            || s.jitter_ms() > 20.0
            || s.ts_discontinuities > 0
            || s.ssrc_changes > 0
            || s.last_packet_time.is_some_and(|t| t.elapsed() > Duration::from_secs(STREAM_TIMEOUT_SECS))
    }).count();
    let ptp_issue = requires_valid_ptp && !ptp_domains.values().any(|s| s.clock_valid);
    let mut parts = Vec::new();
    if stream_issues > 0 { parts.push(format!("{} stream issue(s)", stream_issues)); }
    if ptp_issue { parts.push("no clock source".to_string()); }
    let status_line = if !parts.is_empty() {
        format!("⚠  {}", parts.join("  |  "))
    } else if streams.is_empty() {
        "–  No streams detected".to_string()
    } else {
        "✓  All streams healthy".to_string()
    };
    logger.log(&status_line);
    if status_line.starts_with('✓') {
        println!("\x1b[32m{}\x1b[0m", status_line);
    } else if status_line.starts_with('⚠') {
        println!("\x1b[33m{}\x1b[0m", status_line);
    } else {
        println!("{}", status_line);
    }

    // ── Streams (all protocols unified) ────────────────────────────────────
    logger.log("\nStreams:");
    println!("\n\x1b[36m📡 Streams:\x1b[0m");

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

        // Protocol label: prefix ST2110 subtypes clearly
        let proto_label = if s.protocol.starts_with("2110-") {
            format!("ST{}", s.protocol)
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

        let stream_line = format!("\n  ▸ {}{}{}{}", proto_label, name_str, codec_str, addr_str);
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
        } else {
            let metrics = format!(
                "    loss: {:.1}%  |  jitter: {:.2} ms  |  {:.1} Mbps",
                s.loss_pct(), s.jitter_ms(), s.bitrate_bps as f64 / 1_000_000.0
            );
            logger.log(&metrics);
            println!("{}", metrics);
        }

        if s.ts_discontinuities > 0 {
            let alert = "    ⚠  Audio glitch risk — timing discontinuity detected";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }

        if s.loss_pct() > 0.0 {
            let alert = "    ⚠  Packet loss detected";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }

        if s.jitter_ms() > 20.0 {
            let alert = "    ⚠  High jitter — stream quality at risk";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }

        if s.protocol == "AES67" && s.jitter_ms() > 10.0 {
            let alert = "    ⚠  AES67 timing issue — check PTP lock";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }

        // 0.1% loss ≈ ~3 dropped packets per 5s window at 1ms ptime — below that is
        // usually capture jitter, not a real subscription/clock fault.
        if s.protocol == "Dante" && (s.loss_pct() > 0.1 || s.jitter_ms() > 15.0) {
            let alert = "    ⚠  Dante clock or subscription issue";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }

        if s.ssrc_changes > 0 {
            let alert = format!("    ⚠  Source interrupted and reconnected ({} time(s))", s.ssrc_changes);
            logger.log(&alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }

        // Gap 2: payload type mismatch
        if s.pt_mismatches > 0 {
            let alert = format!("    ⚠  RTP payload type mismatch ({} packet(s)) — encoder/SDP misconfiguration", s.pt_mismatches);
            logger.log(&alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }

        // Gap 3: stream not yet announced via SAP
        // Only applies to RTP-based protocols that carry SDP (AES67, ST2110, Dante).
        // AVB and NDI never publish SDP — skip the warning.
        let expects_sdp = s.protocol == "AES67"
            || s.protocol == "Dante"
            || s.protocol.starts_with("2110-");
        if expects_sdp && !s.clock_hz_confirmed && s.packets > 10 {
            let alert = "    ⚠  Stream not announced (no SAP) — audio glitch detection unavailable";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }

        // ST2110 unclassified stream type
        if s.protocol == "2110-??" {
            let alert = "    ⚠  Stream type unknown — SDP required to classify as video/audio/ancillary";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
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
            println!("\x1b[33m{}\x1b[0m", alert);
        }

        if let Some(last_time) = s.last_packet_time
            && last_time.elapsed() > Duration::from_secs(STREAM_TIMEOUT_SECS)
        {
            let alert = format!("    💀 No signal for {:.0}s", last_time.elapsed().as_secs_f64());
            logger.log(&alert);
            println!("\x1b[31m{}\x1b[0m", alert);
        }
    }

    // ── AVB per-stream entries (AVTP stream IDs with MSRP/VLAN inline) ────────
    if !avtp_streams.is_empty() {
        let mut sorted: Vec<&AvtpStreamStats> = avtp_streams.values().collect();
        sorted.sort_by_key(|s| s.stream_id);
        for avtp in sorted {
            let dead = avtp.last_seen.elapsed() > Duration::from_secs(STREAM_TIMEOUT_SECS);
            let stream_line = format!("\n  ▸ AVB  {}  —  {}",
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
                            Some(1) => "insufficient bandwidth",
                            Some(2) => "insufficient bridge resources",
                            Some(3) => "insufficient bandwidth for Traffic Class",
                            Some(_) => "unknown failure",
                            None    => "failed",
                        };
                        let alert = format!("    ⚠  Reservation failed — {}", code_str);
                        logger.log(&alert);
                        println!("\x1b[33m{}\x1b[0m", alert);
                    }
                    MsrpDeclType::Listener => {}
                }
            } else if mvrp_vlans.is_empty() {
                let alert = "    ⚠  No VLAN registration — L2 QoS may not be configured";
                logger.log(alert);
                println!("\x1b[33m{}\x1b[0m", alert);
            }

            if dead {
                let alert = format!("    💀 No signal for {:.0}s", avtp.last_seen.elapsed().as_secs_f64());
                logger.log(&alert);
                println!("\x1b[31m{}\x1b[0m", alert);
            }
        }
    }

    // ── PTP / Clock Sources ─────────────────────────────────────────────────
    if !ptp_domains.is_empty() {
        logger.log("\nClock Sources:");
        println!("\n\x1b[36m🕐 Clock Sources:\x1b[0m");

        let multi_domain = ptp_domains.len() > 1;

        for ((domain, _version), stats) in ptp_domains.iter() {
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
                    let ip_str = stats.last_src_ip
                        .map(|ip| format!("  ({})", ip))
                        .unwrap_or_default();
                    format!("  {}  {}{}  —  grandmaster {}{}", gm_icon, proto_label, domain_suffix, gm, ip_str)
                }
                (Some(_), false) => {
                    format!("  {}  {}{}  —  clock lost", gm_icon, proto_label, domain_suffix)
                }
                (None, _) => {
                    // No Announce seen yet; use source clock ID from Sync as fallback
                    match &stats.last_clock_id {
                        Some(id) => format!("  ○  {}{}  —  clock source: {}  (sync only, no announce)", proto_label, domain_suffix, id),
                        None     => format!("  {}  {}{}  —  no clock detected", gm_icon, proto_label, domain_suffix),
                    }
                }
            };
            logger.log(&clock_line);
            println!("{}", clock_line);

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
                    println!("\x1b[33m{}\x1b[0m", alert);
                }
            }

            if stats.protocol_clock_lost {
                let alert = "    ⚠  Clock lost — grandmaster disappeared";
                logger.log(alert);
                println!("\x1b[33m{}\x1b[0m", alert);
            }

            if stats.protocol_changes_count > 0 {
                let alert = format!("    ⚠  Clock source changed {} time(s)", stats.protocol_changes_count);
                logger.log(&alert);
                println!("\x1b[33m{}\x1b[0m", alert);
            }
        }
    }

    // ── Clock source required but absent ───────────────────────────────────
    if requires_valid_ptp && !ptp_domains.values().any(|s| s.clock_valid) {
        let alert = "⚠  No clock source — streams requiring PTP may lose sync";
        logger.log(&format!("\n{}", alert));
        println!("\x1b[31m{}\x1b[0m", alert);
    }

    // ── Network health ──────────────────────────────────────────────────────
    logger.log("\nNetwork Health:");
    println!("\n\x1b[36m🔬 Network Health:\x1b[0m");

    let qos_str = if health.dscp_total == 0 {
        "QoS: – (no AV streams)".to_string()
    } else if health.dscp_violations == 0 {
        format!("QoS: ✓ DSCP marked ({} pkts)", health.dscp_total)
    } else {
        let pct = health.dscp_violations * 100 / health.dscp_total;
        let pct_str = if pct == 0 { "<1".to_string() } else { pct.to_string() };
        format!("QoS: ⚠ {}% untagged ({}/{})", pct_str, health.dscp_violations, health.dscp_total)
    };

    let querier_str = match health.last_igmp_query {
        None => "IGMP: – (no querier seen)".to_string(),
        Some(t) => {
            let secs = t.elapsed().as_secs();
            if secs > 130 {
                format!("IGMP: ⚠ querier silent {}s", secs)
            } else {
                format!("IGMP: ✓ querier {}s ago", secs)
            }
        }
    };

    let breakdown = format!("   {}  |  {}", qos_str, querier_str);
    logger.log(&breakdown);
    println!("{}", breakdown);

    if !eee_ports.is_empty() {
        let eee_alert = format!(
            "   ⚠  EEE active on {} switch port(s) — may cause audio/video glitches  (disable EEE on all AV switch ports)",
            eee_ports.len()
        );
        logger.log(&eee_alert);
        println!("\x1b[33m{}\x1b[0m", eee_alert);
        for ((chassis, port), (tx, rx)) in eee_ports.iter() {
            let detail = format!("      port \"{}\"  chassis {}  Tx wake: {}µs  Rx wake: {}µs", port, chassis, tx, rx);
            logger.log(&detail);
            println!("{}", detail);
        }
    }

    logger.log("");
}
