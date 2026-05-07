// AVStreamLens — main.rs (refactored)
//
// IP AV Monitoring: AES67, SMPTE ST 2110, Dante, NDI, AVB, SRT, RIST
// - Pcap capture with BPF filter
// - Protocol detection by network signature (Audio/Video presets)
// - SAP/SDP parser for stream metadata
// - RFC 3550 jitter, SSRC tracking, dead-stream detection
// - PTP (IEEE 1588) and IGMP always monitored
// - Terminal reporting every 5 seconds

mod parser;
mod protocols;
mod stats;

use pcap::{Capture, Device};
use pnet_packet::ethernet::EthernetPacket;
use pnet_packet::Packet;
use chrono::{Datelike, Local, Timelike};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

// Import types from modules
use protocols::{AvProtocol, ProtocolChoice, SdpSession, DanteKind, NdiKind, St2110Type, IgmpType};
use stats::{StreamStats, TcpStreamStats, NetworkHealth, PtpStats, StreamQuality};
use parser::{detect_protocol, parse_tcp_packet, parse_rtp, is_multicast, 
             is_aes67_multicast, is_st2110_multicast};

// Constants from protocols module
use protocols::{
    DEFAULT_CLOCK_HZ, STREAM_TIMEOUT_SECS,
};

// ═══════════════════════════════════════════════════════════
// Logger struct — main.rs-specific
// ═══════════════════════════════════════════════════════════

#[derive(Debug)]
struct Logger {
    file: File,
}

impl Logger {
    fn new(prefix: &str) -> io::Result<Self> {
        let now = Local::now();
        let filename = format!(
            "avstreamlens_{}-{:02}-{:02}_{:02}-{:02}-{:02}_{}.log",
            now.year(), now.month(), now.day(), now.hour(), now.minute(), now.second(), prefix
        );
        let file = File::create(filename)?;
        Ok(Logger { file })
    }

    fn log(&mut self, message: &str) {
        let _ = writeln!(self.file, "{}", message);
    }

    #[allow(dead_code)]
    fn log_fmt(&mut self, args: std::fmt::Arguments) {
        let message = args.to_string();
        let _ = writeln!(self.file, "{}", message);
    }
}

// ═══════════════════════════════════════════════════════════
// Utility Functions — main.rs-specific
// ═══════════════════════════════════════════════════════════

fn prompt_protocol_selection() -> Vec<ProtocolChoice> {
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

fn build_bpf_filter(selected: &[ProtocolChoice]) -> String {
    // Expand Audio/Video choices
    let mut expanded = Vec::new();
    for choice in selected {
        expanded.extend(choice.includes());
    }

    if expanded.is_empty() || expanded.iter().any(|c| matches!(c, ProtocolChoice::All)) {
        return "udp or (ether proto 0x22f0) or (ether proto 0x88f7)".to_string();
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
        "udp or (ether proto 0x22f0) or (ether proto 0x88f7)".to_string()
    } else {
        filters.join(" or ")
    }
}

fn selected_protocol_names(selected: &[ProtocolChoice]) -> String {
    if selected.iter().any(|c| matches!(c, ProtocolChoice::All)) {
        "all".to_string()
    } else {
        selected.iter()
            .map(|c| c.name().replace(" (", "_").replace(")", ""))
            .collect::<Vec<_>>()
            .join("_")
    }
}

fn protocol_requires_ptp(selected: &[ProtocolChoice]) -> bool {
    // Expand Audio/Video
    let mut expanded = Vec::new();
    for choice in selected {
        expanded.extend(choice.includes());
    }

    if expanded.is_empty() || expanded.iter().any(|c| matches!(c, ProtocolChoice::All)) {
        return true;
    }

    expanded.iter().any(|c| c.requires_valid_ptp_clock())
}

// ═══════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════

fn main() {
    // ── Interface listing ───────────────────────────
    let devices = Device::list().expect("Unable to list interfaces");
    let filtered: Vec<Device> = devices
        .into_iter()
        .filter(|d| {
            let n = d.name.as_str();
            if n == "lo" || n == "lo0" { return false; }
            let skip = ["utun", "awdl", "llw", "bridge", "vpn", "docker", "veth", "virbr"];
            !skip.iter().any(|k| n.contains(k))
        })
        .collect();

    if filtered.is_empty() {
        eprintln!("❌ No active network interfaces found."); return;
    }

    println!("📡 Available interfaces:\n");
    for (i, d) in filtered.iter().enumerate() {
        println!("  {}: {}", i, d.name);
    }

    println!("\n👉 Choose the interface index:");
    print!("> ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let index: usize = input.trim().parse().expect("Invalid number");

    let device = match filtered.get(index) {
        Some(d) => d.clone(),
        _    => { eprintln!("❌ Invalid selection."); return; }
    };

    let selected_protocols = prompt_protocol_selection();
    let protocol_names = selected_protocol_names(&selected_protocols);
    let mut logger = Logger::new(&protocol_names).expect("Unable to create log file");
    let bpf_filter = build_bpf_filter(&selected_protocols);

    println!("Selected protocols: {}", protocol_names);
    logger.log(&format!("Selected protocols: {}", protocol_names));
    println!("\n📡 Listening on {}  (BPF filter: \"{}\")\n", device.name, bpf_filter);
    logger.log(&format!("\n📡 Listening on {}  (BPF filter: \"{}\")\n", device.name, bpf_filter));

    // ── Opening capture with BPF filter ───────────────
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .immediate_mode(true)
        .open()
        .unwrap();

    cap.filter(&bpf_filter, true)
        .expect("BPF filter failure — run as root/sudo");

    // ── Global state ──────────────────────────────────────
    let mut streams:       HashMap<String, StreamStats> = HashMap::new();
    let mut tcp_streams:   HashMap<String, TcpStreamStats> = HashMap::new();
    let mut sdp_cache:     HashMap<String, SdpSession> = HashMap::new();
    let mut ptp_domains:   HashMap<u8, PtpStats> = HashMap::new();
    let mut network_health: NetworkHealth = NetworkHealth::new();
    let mut multicast_seen: HashMap<(Ipv4Addr, u16), u64> = HashMap::new();
    let mut last_report = Instant::now();

    // ── Capture loop ────────────────────────────────
    loop {
        let packet = match cap.next_packet() { Ok(p) => p, Err(_) => continue };
        let eth    = match EthernetPacket::new(packet.data) { Some(e) => e, _ => continue };

        match detect_protocol(&eth) {

            // ── SAP/SDP ──────────────────────────────────
            Some(AvProtocol::Sap { src, sdp }) => {
                println!("📋 SAP received from {}  session=\"{}\"  ({} media(s))",
                    src, sdp.session_name, sdp.media.len());
                logger.log(&format!("📋 SAP received from {}  session=\"{}\"  ({} media(s))",
                    src, sdp.session_name, sdp.media.len()));

                for m in &sdp.media {
                    logger.log(&format!("   {} port {}  {}  {:.0} Hz  {}ch  ptime {:.2} ms",
                        m.media_type, m.port, m.rtpmap,
                        m.clock_hz, m.channels, m.ptime_ms));
                    if !m.ts_refclk.is_empty() {
                        logger.log(&format!("   PTP refclk: {}", m.ts_refclk));
                    }
                    if !m.mediaclk.is_empty() {
                        logger.log(&format!("   mediaclk: {}", m.mediaclk));
                    }
                    // Enrich existing StreamStats if port matches
                    for stats in streams.values_mut() {
                        if stats.sdp_name.is_none() && m.port > 0 {
                            stats.sdp_name   = Some(sdp.session_name.clone());
                            stats.sdp_rtpmap = Some(m.rtpmap.clone());
                            if m.clock_hz > 0.0 { stats.clock_hz = m.clock_hz; }
                            if m.ptime_ms > 0.0 { stats.ptime_ms = m.ptime_ms; }
                            if m.channels > 0   { stats.channels = m.channels; }
                        }
                    }
                }
                sdp_cache.insert(sdp.session_id.clone(), sdp);
            }

            // ── PTP ───────────────────────────────────────
            Some(AvProtocol::Ptp { info }) => {
                let stats = ptp_domains.entry(info.domain).or_insert_with(|| PtpStats::new(info.domain, info.version));
                stats.update(&info);
            }

            // ── AES67 ────────────────────────────────────
            Some(AvProtocol::Aes67 { dst, dst_port, .. }) => {
                let key = format!("AES67 {}:{}", dst, dst_port);
                let stats = streams.entry(key).or_insert_with(|| {
                    let (clock, rtpmap) = sdp_cache.values()
                        .flat_map(|s| s.media.iter())
                        .find(|m| m.port == dst_port)
                        .map(|m| (m.clock_hz, Some(m.rtpmap.clone())))
                        .unwrap_or((DEFAULT_CLOCK_HZ, None));
                    let mut s = StreamStats::new_with_info("AES67", clock, is_aes67_multicast(dst), dst, dst_port);
                    s.sdp_rtpmap = rtpmap;
                    s.media_type = "audio".to_string();
                    s.channels = 1;
                    s
                });
                let ip  = pnet_packet::ipv4::Ipv4Packet::new(eth.payload()).unwrap();
                let udp = pnet_packet::udp::UdpPacket::new(ip.payload()).unwrap();
                if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) { 
                    stats.update(seq, ts, ssrc, udp.payload().len()); 
                }
            }

            // ── ST 2110 ──────────────────────────────────
            Some(AvProtocol::St2110 { dst, dst_port, stream_type, .. }) => {
                let label = match stream_type {
                    St2110Type::Video   => "2110-20",
                    St2110Type::Audio   => "2110-30",
                    St2110Type::Ancdata => "2110-40",
                    St2110Type::Unknown => "2110-??",
                };
                let key = format!("ST {} {}:{}", label, dst, dst_port);
                let default_clock = if matches!(stream_type, St2110Type::Video) { 90_000.0 } else { DEFAULT_CLOCK_HZ };
                let stats = streams.entry(key).or_insert_with(|| {
                    let (clock, rtpmap) = sdp_cache.values()
                        .flat_map(|s| s.media.iter())
                        .find(|m| m.port == dst_port)
                        .map(|m| (m.clock_hz, Some(m.rtpmap.clone())))
                        .unwrap_or((default_clock, None));
                    let mut s = StreamStats::new_with_info(label, clock, is_st2110_multicast(dst), dst, dst_port);
                    s.sdp_rtpmap = rtpmap;
                    s.media_type = match stream_type {
                        St2110Type::Video => "video".to_string(),
                        St2110Type::Audio => "audio".to_string(),
                        St2110Type::Ancdata => "ancillary".to_string(),
                        St2110Type::Unknown => "unknown".to_string(),
                    };
                    s
                });
                let ip  = pnet_packet::ipv4::Ipv4Packet::new(eth.payload()).unwrap();
                let udp = pnet_packet::udp::UdpPacket::new(ip.payload()).unwrap();
                if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) { 
                    stats.update(seq, ts, ssrc, udp.payload().len()); 
                }
            }

            // ── Dante ────────────────────────────────────
            Some(AvProtocol::Dante { kind, src, dst_port }) => {
                match kind {
                    DanteKind::Discovery => {
                        let msg = format!("🔍 Dante discovered: {}", src);
                        println!("{}", msg);
                        logger.log(&msg);
                    }
                    DanteKind::Control     => {}
                    DanteKind::AudioStream => {
                        let key   = format!("Dante {}:{}", src, dst_port);
                        let stats = streams.entry(key)
                            .or_insert_with(|| StreamStats::new("Dante", DEFAULT_CLOCK_HZ));
                        let ip  = pnet_packet::ipv4::Ipv4Packet::new(eth.payload()).unwrap();
                        let udp = pnet_packet::udp::UdpPacket::new(ip.payload()).unwrap();
                        if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) { 
                            stats.update(seq, ts, ssrc, udp.payload().len()); 
                        }
                    }
                }
            }

            // ── NDI ──────────────────────────────────────
            Some(AvProtocol::Ndi { kind, src }) => {
                match kind {
                    NdiKind::Discovery => {
                        let msg = format!("🔍 NDI source: {}", src);
                        println!("{}", msg);
                        logger.log(&msg);
                    },
                    NdiKind::Stream    => {
                        let stats = streams.entry(format!("NDI {}", src))
                            .or_insert_with(|| StreamStats::new("NDI", 0.0));
                        stats.packets += 1;
                    }
                }
            }

            // ── AVB ──────────────────────────────────────
            Some(AvProtocol::Avb { subtype }) => {
                let stats = streams.entry(format!("AVB subtype=0x{:02X}", subtype))
                    .or_insert_with(|| StreamStats::new("AVB", 0.0));
                stats.packets += 1;
            }

            // ── SRT ──────────────────────────────────────
            Some(AvProtocol::Srt { src, dst_port, is_handshake }) => {
                let key = format!("SRT {}:{}", src, dst_port);
                let stats = streams.entry(key)
                    .or_insert_with(|| StreamStats::new("SRT", 0.0));
                stats.packets += 1;
                stats.last_packet_time = Some(Instant::now());
                if is_handshake {
                    let msg = format!("🤝 SRT handshake: {} → port {}", src, dst_port);
                    println!("{}", msg);
                    logger.log(&msg);
                }
            }

            // ── RIST ─────────────────────────────────────
            Some(AvProtocol::Rist { src, dst, dst_port }) => {
                let key = format!("RIST {}:{}", dst, dst_port);
                let stats = streams.entry(key)
                    .or_insert_with(|| {
                        let mut s = StreamStats::new_with_info("RIST", DEFAULT_CLOCK_HZ, is_multicast(dst), dst, dst_port);
                        s.media_type = "video".to_string();
                        s
                    });
                let ip  = pnet_packet::ipv4::Ipv4Packet::new(eth.payload()).unwrap();
                let udp = pnet_packet::udp::UdpPacket::new(ip.payload()).unwrap();
                if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) {
                    stats.update(seq, ts, ssrc, udp.payload().len());
                }
                let _ = src;
            }

            // ── IGMP ─────────────────────────────────────
            Some(AvProtocol::Igmp { src, group, igmp_type }) => {
                let (icon, label) = match &igmp_type {
                    IgmpType::Join       => ("➕", "Join"),
                    IgmpType::Leave      => ("➖", "Leave"),
                    IgmpType::Query      => ("❓", "Query"),
                    IgmpType::Unknown(_) => ("❔", "Unknown")
                };
                let msg = format!("{} IGMP {}: {} → group {}", icon, label, src, group);
                println!("{}", msg);
                logger.log(&msg);
                if matches!(igmp_type, IgmpType::Leave) {
                    for key in streams.keys() {
                        if streams[key].dst_ip == Some(group) {
                            let alert = format!("    ⚠  IGMP Leave on monitored group {}", group);
                            println!("\x1b[33m{}\x1b[0m", alert);
                            logger.log(&alert);
                        }
                    }
                }
            }

            _ => {}
        }

        // ── Dead stream detection ─────────────────────────────
        if last_report.elapsed() > Duration::from_secs(4) {
            for (key, stats) in &streams {
                if let Some(last_time) = stats.last_packet_time {
                    if last_time.elapsed() > Duration::from_secs(STREAM_TIMEOUT_SECS) {
                        let alert = format!("💀 Stream silent (> {}s): {}", STREAM_TIMEOUT_SECS, key);
                        println!("\x1b[31m{}\x1b[0m", alert);
                        logger.log(&alert);
                    }
                }
            }
        }

        // ── TCP Monitoring ────────────────────────────────────
        if let Some((src_ip, dst_ip, src_port, dst_port, has_fin, has_syn, has_rst, seq, ack)) = parse_tcp_packet(&eth) {
            let key = format!("TCP {}:{} → {}:{}", src_ip, src_port, dst_ip, dst_port);
            let tcp_stat = tcp_streams.entry(key.clone()).or_insert_with(|| TcpStreamStats::new(src_ip, src_port, dst_ip, dst_port));
            tcp_stat.packets += 1;
            tcp_stat.last_seen = Instant::now();
            
            let frame_size = eth.packet().len() as u64;
            let estimated_payload = if frame_size > 40 { frame_size - 40 } else { 0 };
            tcp_stat.bytes += estimated_payload;
            
            if has_fin { tcp_stat.fin_packets += 1; }
            if has_rst {
                tcp_stat.rst_packets += 1;
                network_health.tcp_retransmissions += 1;
            }

            if !has_syn {
                if let Some(last_seq) = tcp_stat.last_seq {
                    if seq <= last_seq && tcp_stat.packets > 2 {
                        tcp_stat.retransmissions += 1;
                        network_health.tcp_retransmissions += 1;
                    }
                }
            }
            tcp_stat.last_seq = Some(seq.max(tcp_stat.last_seq.unwrap_or(0)));
            tcp_stat.last_ack = Some(ack);
            
            tcp_stat.update_bitrate();
            tcp_stat.update_quality();
        }

        // ── Network health tracking ───────────────────────────
        network_health.total_packets += 1;
        if let Some(ip) = pnet_packet::ipv4::Ipv4Packet::new(eth.payload()) {
            network_health.total_bytes += eth.packet().len() as u64;
            if is_multicast(ip.get_destination()) {
                network_health.multicast_packets += 1;
                if let Some(udp) = pnet_packet::udp::UdpPacket::new(ip.payload()) {
                    let multicast_key = (ip.get_destination(), udp.get_destination());
                    let count = multicast_seen.entry(multicast_key).or_insert(0);
                    *count += 1;
                    if *count > 1 {
                        network_health.detected_duplicates += 1;
                    }
                }
            } else {
                network_health.unicast_packets += 1;
            }
        }

        // ── Report every 5 seconds ────────────────
        if last_report.elapsed() > Duration::from_secs(5) {
            network_health.calculate_score(&streams, &tcp_streams);
            print_report(&streams, &tcp_streams, &ptp_domains, protocol_requires_ptp(&selected_protocols), &mut logger, &network_health);
            for stats in streams.values_mut() {
                if let Some(last_time) = stats.last_packet_time {
                    if last_time.elapsed() > Duration::from_secs(STREAM_TIMEOUT_SECS) {
                        stats.dead_alerted = true;
                    }
                }
            }
            last_report = Instant::now();
        }
    }
}

// ═══════════════════════════════════════════════════════════
// REPORTING
// ═══════════════════════════════════════════════════════════

fn print_report(streams: &HashMap<String, StreamStats>, tcp_streams: &HashMap<String, TcpStreamStats>, ptp_domains: &HashMap<u8, PtpStats>, requires_valid_ptp: bool, logger: &mut Logger, health: &NetworkHealth) {
    let now = Local::now();
    let header = format!("{} | AVStreamLens report  ({} RTP, {} TCP streams) | Health: {:.0}%", 
        now.format("%Y-%m-%d %H:%M:%S"), streams.len(), tcp_streams.len(), health.network_score);
    logger.log(&format!("\n{}", header));
    
    println!("\n\x1b[36m╔══════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[36m║  {}\x1b[0m", header);
    println!("\x1b[36m╚══════════════════════════════════════════════════════╝\x1b[0m");
    
    let net_summary = format!("\n📊 Network Load: {:.1} Mbps  |  Multicast: {} pkts  |  Unicast: {} pkts  |  Duplicates: {}",
        (health.total_bytes * 8) as f64 / 1_000_000.0, health.multicast_packets, health.unicast_packets, health.detected_duplicates);
    logger.log(&net_summary);
    println!("{}", net_summary);

    let group_order = vec!["AES67", "AVB", "Dante", "NDI", "ST"];
    let mut keys: Vec<&String> = streams.keys().collect();
    keys.sort_by(|a, b| {
        let a_group = group_order.iter().position(|g| a.starts_with(g)).unwrap_or(group_order.len());
        let b_group = group_order.iter().position(|g| b.starts_with(g)).unwrap_or(group_order.len());
        a_group.cmp(&b_group).then(a.cmp(b))
    });

    for key in keys {
        let s = &streams[key];
        let name_str  = s.sdp_name.as_deref().map(|n| format!("  \"{}\"", n)).unwrap_or_default();
        let codec_str = s.sdp_rtpmap.as_deref().map(|c| format!("  [{}]", c)).unwrap_or_default();
        let mc_str = if s.is_multicast { " [MC]" } else { " [UC]" };
        let media_str = if s.media_type != "unknown" { format!("  ({})", s.media_type) } else { String::new() };
        let stream_line = format!("\n  ▸ [{}] {}{}{}{}{}", s.protocol, key, name_str, codec_str, mc_str, media_str);
        logger.log(&stream_line);
        println!("{}", stream_line);

        let status_line = format!("    packets: {}  |  losses: {} ({:.1}%)  |  jitter: {:.2} ms  |  rate: {:.1} Mbps",
            s.packets, s.lost_packets, s.loss_pct(), s.jitter_ms(), (s.bitrate_bps as f64) / 1_000_000.0);
        logger.log(&status_line);
        println!("{}", status_line);

        if s.ts_discontinuities > 0 {
            let ts_alert = format!("    ⚠  Timestamp discontinuities: {} detected", s.ts_discontinuities);
            logger.log(&ts_alert);
            println!("\x1b[33m{}\x1b[0m", ts_alert);
        }
        if s.loss_pct() > 0.0 {
            let alert = "    ⚠  Packet loss";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }
        if s.jitter_ms() > 20.0 {
            let alert = "    ⚠  High jitter (> 20 ms)";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }
        if s.protocol == "AES67" && s.jitter_ms() > 10.0 {
            let alert = "    ⚠  AES67 compliance risk: RTP/PTP drift or strict timing issue";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }
        if s.protocol == "Dante" && (s.loss_pct() > 0.0 || s.jitter_ms() > 15.0) {
            let alert = "    ⚠  Dante subscription or clock mismatch detected";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }
        if s.ssrc_changes > 0 {
            let alert = format!("    ⚠  SSRC changed {} time(s) — source interrupted and reconnected", s.ssrc_changes);
            logger.log(&alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }
        if let Some(last_time) = s.last_packet_time {
            if last_time.elapsed() > Duration::from_secs(STREAM_TIMEOUT_SECS) {
                let alert = format!("    💀 No packet since {:.0}s — stream may be dead",
                    last_time.elapsed().as_secs_f64());
                logger.log(&alert);
                println!("\x1b[31m{}\x1b[0m", alert);
            }
        }
    }

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
            let tcp_line = format!("  {} {}: {} packets, {} bytes, {} Mbps, retransmissions: {}",
                quality_icon, tcp_stat.key, tcp_stat.packets, tcp_stat.bytes, 
                (tcp_stat.bitrate_bps as f64) / 1_000_000.0, tcp_stat.retransmissions);
            logger.log(&tcp_line);
            println!("{}", tcp_line);
            
            if tcp_stat.rst_packets > 0 {
                let alert = format!("    ⚠  RST flags: {} (connection reset)", tcp_stat.rst_packets);
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

    if !ptp_domains.is_empty() {
        logger.log("\nPTP Domains:");
        println!("\n\x1b[35m📡 PTP Domains:\x1b[0m");
        for (domain, stats) in ptp_domains {
            let domain_line = format!("  Domain {} (v{}): {} packets, {} masters",
                domain, stats.version, stats.packets, stats.masters.len());
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
                let alert = format!("    ⚠  Multiple masters detected in domain {}", domain);
                logger.log(&alert);
                println!("\x1b[31m{}\x1b[0m", alert);
            }
            if stats.grandmaster_changes > 0 {
                let alert = format!("    ⚠  Grandmaster changed {} time(s)", stats.grandmaster_changes);
                logger.log(&alert);
                println!("\x1b[33m{}\x1b[0m", alert);
            }
        }
    }

    if requires_valid_ptp {
        let ptp_valid = ptp_domains.values().any(|stats| !stats.masters.is_empty());
        if !ptp_valid {
            let alert = "⚠  No valid PTP clock detected for the selected protocols.";
            logger.log(&format!("\n{}", alert));
            println!("\x1b[31m{}\x1b[0m", alert);
        }
    }

    logger.log("");
}
