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
mod report;

use pcap::{Capture, Device};
use pnet_packet::ethernet::EthernetPacket;
use pnet_packet::Packet;
use std::collections::HashMap;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

// Import types from modules
use crate::protocols::{AvProtocol, SdpSession, DanteKind, NdiKind, St2110Type, IgmpType};
use crate::stats::{StreamStats, TcpStreamStats, NetworkHealth, PtpStats};
use crate::parser::{detect_protocol, parse_tcp_packet, parse_rtp, is_multicast, is_aes67_multicast, is_st2110_multicast};
use crate::report::{create_logger, print_report};

// Constants from protocols module
use protocols::{
    DEFAULT_CLOCK_HZ, STREAM_TIMEOUT_SECS,
};

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

    // ── Interface selection loop ──
    println!("\n👉 Choose the interface index:");
    let mut index: usize = loop {
        print!("> ");
         io::stdout().flush().unwrap();
    
         let mut input = String::new();
         io::stdin().read_line(&mut input).unwrap();
    
        let parsed = input.trim().parse::<usize>();
        match parsed {
            Ok(n) => {
                // Validate range
                if n >= filtered.len() {
                    println!("❌ Invalid selection. Must be between 0 and {}.", filtered.len() - 1);
                    continue;
                }
                break n;
            }
            Err(_) => {
                println!("❌ Invalid input. Please enter a number.");
                continue;
            }
        }
    };

    let device = filtered.get(index)
        .expect("Invalid selection");

    let selected_protocols = report::prompt_protocol_selection(&[]);
    let protocol_names = report::selected_protocol_names(&selected_protocols);
    let bpf_filter  = report::build_bpf_filter(&selected_protocols);
    let mut logger = create_logger(&protocol_names).expect("Unable to create log file");

    println!("Selected protocols: {}", protocol_names);
    logger.log(&format!("Selected protocols: {}", protocol_names));
    println!("\n📡 Listening on {}  (BPF filter: \"{}\")\n", device.name, bpf_filter);
    logger.log(&format!("\n📡 Listening on {}  (BPF filter: \"{}\")\n", device.name, bpf_filter));

    // ── Opening capture with BPF filter ───────────────
    let mut cap = Capture::from_device(device.name.as_str())
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
                    // Enrich stream SDP metadata by port (break on first match)
                    for stats in streams.values_mut() {
                        if stats.dst_port == m.port && stats.sdp_name.is_none() {
                            stats.sdp_name   = Some(sdp.session_name.clone());
                            stats.sdp_rtpmap = Some(m.rtpmap.clone());
                            if m.clock_hz > 0.0 { stats.clock_hz = m.clock_hz; }
                            if m.ptime_ms > 0.0 { stats.ptime_ms = m.ptime_ms; }
                            if m.channels > 0   { stats.channels = m.channels; }
                            break; // O(1) after first match
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
        if last_report.elapsed() > Duration::from_secs(STREAM_TIMEOUT_SECS) {
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
            let requires_valid_ptp = report::protocol_requires_ptp(&selected_protocols);
            print_report(&streams, &tcp_streams, &ptp_domains, requires_valid_ptp, &mut logger, &network_health);
            last_report = Instant::now();
        }
    }
}