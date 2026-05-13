// AVStreamLens — src/report.rs
// Reporting and output formatting for stream monitoring results.

use chrono::{Datelike, Timelike, Local};
use std::collections::HashMap;
use std::time::Duration;
use std::io::{self, Write};

use crate::stats::{StreamStats, TcpStreamStats, PtpStats, NetworkHealth, StreamQuality};
use crate::protocols::{ProtocolChoice, STREAM_TIMEOUT_SECS};

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

/// Prompt user for protocol selection
pub fn prompt_protocol_selection(selected: &[ProtocolChoice]) -> Vec<ProtocolChoice> {
    println!("Choose the protocols to monitor:");
    println!("  0) All");
    for (i, choice) in ProtocolChoice::all_choices().iter().enumerate() {
        println!("  {}) {}", i + 1, choice.name());
    }
    println!("  [Separate by commas, e.g. '1,2,3' or enter for all]");
    print!("> ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    if input.trim().is_empty() {
        return vec![ProtocolChoice::All];
    }

    if input.trim() == "0" {
        return vec![ProtocolChoice::All];
    }

    let mut selected = Vec::new();
    for part in input.split(',') {
        if let Ok(idx) = part.trim().parse::<usize>() {
            if idx == 0 {
                return vec![ProtocolChoice::All];
            }
            if let Some(choice) = ProtocolChoice::all_choices().get(idx.saturating_sub(1)) {
                selected.push(choice.clone());
            }
        }
    }

    if selected.is_empty() {
        vec![ProtocolChoice::All]
    } else {
        selected
    }
}

/// Build BPF filter from selected protocols
pub fn build_bpf_filter(selected: &[ProtocolChoice]) -> String {
    // Expand Audio/Video choices
    let mut expanded = Vec::new();
    for choice in selected {
        expanded.extend(choice.includes());
    }

    if expanded.is_empty() || expanded.iter().any(|c| matches!(c, ProtocolChoice::All)) {
        return filter_with_igmp();
    }

    let needs_udp = expanded.iter().any(|c| c.needs_udp());
    let needs_avb = expanded.iter().any(|c| c.needs_avb());
    let needs_ptp = expanded.iter().any(|c| c.needs_ptp_filter()) || 
                    expanded.iter().any(|c| c.requires_valid_ptp_clock());

    let mut filters = Vec::new();
    
    if needs_udp {
        filters.push("udp".to_string());
    }
    if needs_avb {
        filters.push("(ether proto 0x22f0)".to_string());
    }
    if needs_ptp {
        filters.push("(ether proto 0x88f7)".to_string());
    }

    if filters.is_empty() {
        filter_with_igmp()
    } else {
        // Add IGMP filter for protocol 2 (no port concept)
        filters.insert(0, "igmp".to_string());
        filters.join(" or ")
    }
}

/// Helper function for default filter with IGMP
pub fn filter_with_igmp() -> String {
    "igmp or udp or (ether proto 0x22f0) or (ether proto 0x88f7)".to_string()
}

/// Format selected protocol names
pub fn selected_protocol_names(selected: &[ProtocolChoice]) -> String {
    if selected.iter().any(|c| matches!(c, ProtocolChoice::All)) {
        "all".to_string()
    } else {
        selected.iter()
            .map(|c| c.name().replace(" (", "_").replace(")", ""))
            .collect::<Vec<_>>()
            .join("_")
    }
}

/// Check if selected protocols require PTP
pub fn protocol_requires_ptp(selected: &[ProtocolChoice]) -> bool {
    // Expand Audio/Video
    let expanded: Vec<_> = selected.iter().flat_map(|c| c.includes()).collect();

    if expanded.is_empty() || expanded.iter().any(|c| matches!(c, ProtocolChoice::All)) {
        return true;
    }

    expanded.iter().any(|c| c.requires_valid_ptp_clock())
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
    ptp_domains: &HashMap<u8, PtpStats>,
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
        for (domain, stats) in ptp_domains {
            let domain_line = format!(
                "  Domain {} (v{}): {} packets, {} masters",
                domain, stats.version, stats.packets, stats.masters.len()
            );
            logger.log(&domain_line);
            println!("{}", domain_line);

            if let Some(gm) = &stats.last_grandmaster {
                let gm_line = format!("    Grandmaster: {}", gm);
                logger.log(&gm_line);
                println!("{}", gm_line);
            }
            if let Some(q) = &stats.last_quality {
                let qual_line = format!("    Lock quality: {}", q);
                logger.log(&qual_line);
                println!("{}", qual_line);
            }
            if let Some(offset) = stats.last_offset_ns {
                let off_line = format!("    Last offset correction: {} ns", offset);
                logger.log(&off_line);
                println!("{}", off_line);
            }
            if let Some(delay) = stats.last_path_delay_ns {
                let delay_line = format!("    Last path delay: {} ns", delay);
                logger.log(&delay_line);
                println!("{}", delay_line);
            }
            if stats.masters.len() > 1 {
                let alert = format!(
                    "    ⚠  Multiple masters detected in domain {}",
                    domain
                );
                logger.log(&alert);
                println!("\x1b[31m{}\x1b[0m", alert);
            }
            if stats.grandmaster_changes > 0 {
                let alert = format!(
                    "    ⚠  Grandmaster changed {} time(s)",
                    stats.grandmaster_changes
                );
                logger.log(&alert);
                println!("\x1b[33m{}\x1b[0m", alert);
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
