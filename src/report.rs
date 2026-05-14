// AVStreamLens — src/report.rs
// Reporting and output formatting for stream monitoring results.

use chrono::{Datelike, Timelike, Local};
use std::collections::HashMap;
use std::time::Duration;

use crate::stats::{StreamStats, TcpStreamStats, PtpStats, NetworkHealth, StreamQuality};
use crate::protocols::STREAM_TIMEOUT_SECS;

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

    /// Log a message to the file.
    pub fn log(&mut self, message: &str) {
        use std::io::Write;
        let _ = writeln!(self.file, "{}", message);
    }

    /// Log a formatted message to the file.
    #[allow(dead_code)]
    pub fn log_fmt(&mut self, args: std::fmt::Arguments) {
        use std::io::Write;
        let message = args.to_string();
        let _ = writeln!(self.file, "{}", message);
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
pub fn print_report(
    streams: &HashMap<String, StreamStats>,
    tcp_streams: &HashMap<String, TcpStreamStats>,
    ptp_domains: &HashMap<(u8, u8), PtpStats>,
    requires_valid_ptp: bool,
    logger: &mut Logger,
    health: &NetworkHealth,
) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let stream_count = streams.len();
    let tcp_count = tcp_streams.len();
    let score = format!("{:.0}%", health.network_score);
    
    let header_line = format!("{} | AVStreamLens report", timestamp);
    let details = format!("  ({} RTP, {} TCP streams) | Health: {}", stream_count, tcp_count, score);
    
    let full_header = format!("{}\n{}", header_line, details);
    
    logger.log(&full_header);
    
    println!("\n\x1b[36m╔══════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[36m║  {}\x1b[0m", header_line);
    println!("\x1b[36m║    {}\x1b[0m", details);
    println!("\x1b[36m╚══════════════════════════════════════════════════════╝\x1b[0m");

    let net_summary = format!(
        "\n📊 Network Load: {:.1} Mbps  |  Multicast: {} pkts  |  Unicast: {} pkts  |  Duplicates: {}",
        (health.total_bytes * 8) as f64 / 1_000_000.0,
        health.multicast_packets,
        health.unicast_packets,
        health.detected_duplicates
    );
    logger.log(&net_summary);
    println!("{}", net_summary);

    // ── Health breakdown ────────────────────────────────────────────────────
    let qos_str = if health.dscp_total == 0 {
        "QoS: – (no AV streams)".to_string()
    } else {
        let pct = health.dscp_violations * 100 / health.dscp_total;
        if health.dscp_violations == 0 {
            format!("QoS: ✓ DSCP EF ({} pkts)", health.dscp_total)
        } else {
            format!("QoS: ⚠ {}% untagged ({}/{})", pct, health.dscp_violations, health.dscp_total)
        }
    };

    let igmp_str = if health.ecn_congestion_marks == 0 {
        "Congestion: ✓ none".to_string()
    } else {
        format!("Congestion: ⚠ {} ECN marks", health.ecn_congestion_marks)
    };

    let querier_str = match health.last_igmp_query {
        None => "IGMP: – (no query seen)".to_string(),
        Some(t) => {
            let secs = t.elapsed().as_secs();
            if secs > 130 {
                format!("IGMP: ⚠ querier silent {}s", secs)
            } else {
                format!("IGMP: ✓ querier {}s ago", secs)
            }
        }
    };

    let breakdown = format!("   {}  |  {}  |  {}", qos_str, igmp_str, querier_str);
    logger.log(&breakdown);
    println!("{}", breakdown);

    // ── RTP Streams Report ──────────────────────────────────────────────────
    let group_order = vec!["AES67", "AVB", "Dante", "NDI", "ST"];
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
        let name_str = s
            .sdp_name
            .as_deref()
            .map(|n| format!("  \"{}\"", n))
            .unwrap_or_default();
        let codec_str = s
            .sdp_rtpmap
            .as_deref()
            .map(|c| format!("  [{}]", c))
            .unwrap_or_default();
        let mc_str = if s.is_multicast { " [MC]" } else { " [UC]" };
        let media_str = if s.media_type != "unknown" {
            format!("  ({})", s.media_type)
        } else {
            String::new()
        };
        let stream_line = format!(
            "\n  ▸ [{}] {}{}{}{}{}",
            s.protocol, key, name_str, codec_str, mc_str, media_str
        );
        logger.log(&stream_line);
        println!("{}", stream_line);

        let status_line = format!(
            "    packets: {}  |  losses: {} ({:.1}%)  |  jitter: {:.2} ms  |  rate: {:.1} Mbps",
            s.packets,
            s.lost_packets,
            s.loss_pct(),
            s.jitter_ms(),
            (s.bitrate_bps as f64) / 1_000_000.0
        );
        logger.log(&status_line);
        println!("{}", status_line);

        // Timestamp discontinuity warning
        if s.ts_discontinuities > 0 {
            let ts_alert = format!(
                "    ⚠  Timestamp discontinuities: {} detected",
                s.ts_discontinuities
            );
            logger.log(&ts_alert);
            println!("\x1b[33m{}\x1b[0m", ts_alert);
        }

        // Packet loss warning
        if s.loss_pct() > 0.0 {
            let alert = "    ⚠  Packet loss";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }

        // Jitter warning
        if s.jitter_ms() > 20.0 {
            let alert = "    ⚠  High jitter (> 20 ms)";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }

        // AES67-specific warnings
        if s.protocol == "AES67" && s.jitter_ms() > 10.0 {
            let alert = "    ⚠  AES67 compliance risk: RTP/PTP drift or strict timing issue";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }

        // Dante-specific warnings
        if s.protocol == "Dante" && (s.loss_pct() > 0.0 || s.jitter_ms() > 15.0) {
            let alert = "    ⚠  Dante subscription or clock mismatch detected";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }

        // SSRC change warning
        if s.ssrc_changes > 0 {
            let alert = format!(
                "    ⚠  SSRC changed {} time(s) — source interrupted and reconnected",
                s.ssrc_changes
            );
            logger.log(&alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }

        // Dead stream detection
        if let Some(last_time) = s.last_packet_time {
            if last_time.elapsed() > Duration::from_secs(STREAM_TIMEOUT_SECS) {
                let alert = format!(
                    "    💀 No packet since {:.0}s — stream may be dead",
                    last_time.elapsed().as_secs_f64()
                );
                logger.log(&alert);
                println!("\x1b[31m{}\x1b[0m", alert);
            }
        }
    }

    // ── TCP Streams Report ──────────────────────────────────────────────────
    if !tcp_streams.is_empty() {
        logger.log("\nTCP Streams:");
        println!("\n\x1b[34m🔌 TCP Streams:\x1b[0m");
        for tcp_stat in tcp_streams.values() {
            let quality_icon = match tcp_stat.stream_quality {
                StreamQuality::Healthy => "✓",
                StreamQuality::Degrading => "⚠",
                StreamQuality::Critical => "⚠⚠",
                StreamQuality::Terminated => "✗",
            };
            let tcp_line = format!(
                "  {} {}: {} packets, {} bytes, {} Mbps, retransmissions: {}",
                quality_icon,
                tcp_stat.key,
                tcp_stat.packets,
                tcp_stat.bytes,
                (tcp_stat.bitrate_bps as f64) / 1_000_000.0,
                tcp_stat.retransmissions
            );
            logger.log(&tcp_line);
            println!("{}", tcp_line);

            if tcp_stat.rst_packets > 0 {
                let alert = format!(
                    "    ⚠  RST flags: {} (connection reset)",
                    tcp_stat.rst_packets
                );
                logger.log(&alert);
                println!("\x1b[31m{}\x1b[0m", alert);
            }
            if tcp_stat.retransmissions > 5 {
                let alert = format!("    ⚠  High retransmission rate detected");
                logger.log(&alert);
                println!("\x1b[33m{}\x1b[0m", alert);
            }
        }
    }

    // ── PTP Domains Report ──────────────────────────────────────────────────
    if !ptp_domains.is_empty() {
        logger.log("\nPTP Domains:");
        println!("\n\x1b[35m📡 PTP Domains:\x1b[0m");

        for ((domain, _version), stats) in ptp_domains.iter() {
            let gm_icon = if stats.clock_valid { "✓" } else if stats.last_grandmaster.is_some() { "✓" } else { "❌" };

            let version_str = format!(" v{}", stats.version);
            let protocol_str = if let Some(ref pk) = stats.protocol_kind {
                format!(" [{}]", pk)
            } else {
                String::new()
            };

            let domain_line = format!(
                "  {}: Domain {}{}{}",
                gm_icon, domain, version_str, protocol_str
            );
            logger.log(&domain_line);
            println!("{}", domain_line);

            if let Some(ref gm) = stats.last_grandmaster {
                let ip_str = stats.last_src_ip
                    .map(|ip| format!("  ({})", ip))
                    .unwrap_or_default();
                let line = format!("    {} Grandmaster clock: {}{}", gm_icon, gm, ip_str);
                println!("{}", line);
                logger.log(&line);
            }

            if let Some(ref q) = stats.last_quality {
                println!("    {} Lock quality: {}", "✔", q);
                logger.log(&format!("    {} Lock quality: {}", "✔", q));
            }

            if stats.protocol_clock_lost {
                println!("    {} ⚠  Clock LOST (protocol grandmaster disappeared)", "✘");
                logger.log(&format!("    {} ⚠  Clock LOST (protocol grandmaster disappeared)", "✘"));
            }

            if stats.protocol_changes_count > 0 {
                println!(
                    "    {} ⚠  Grandmaster changed {} time(s) for {}",
                    "✙", stats.protocol_changes_count, stats.protocol_kind.as_ref().unwrap_or(&"unknown".to_string())
                );
                logger.log(&format!(
                    "    {} ⚠  Grandmaster changed {} time(s) for {}",
                    "✙", stats.protocol_changes_count, stats.protocol_kind.as_ref().unwrap_or(&"unknown".to_string())
                ));
            }
        }
    }

    // ── PTP Validation ──────────────────────────────────────────────────────
    if requires_valid_ptp {
        // Check if any domain has a currently valid clock
        let has_valid_clock = ptp_domains.values().any(|stats| stats.clock_valid);

        if !has_valid_clock {
            let alert = "⚠  No valid PTP clock detected for the selected protocols.";
            logger.log(&format!("\n{}", alert));
            println!("\x1b[31m{}\x1b[0m", alert);
        }
    }

    logger.log("");
}
