// AVStreamLens — main.rs (refactored)
//
// IP AV Monitoring: AES67, SMPTE ST 2110, Dante, NDI, AVB, SRT, RIST
// - Pcap capture with BPF filter
// - Protocol detection by network signature (Audio/Video presets)
// - SAP/SDP parser for stream metadata
// - RFC 3550 jitter, SSRC tracking, dead-stream detection
// - PTP (IEEE 1588) and IGMP always monitored
// - Terminal reporting every 5 seconds

mod cli;
mod parser;
mod protocols;
mod stats;
mod report;

use pcap::Capture;
use pnet_packet::ethernet::EthernetPacket;
use pnet_packet::Packet;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

// Import types from modules
use crate::protocols::{AvProtocol, SdpSession, DanteKind, NdiKind, St2110Type, IgmpType, MsrpDeclType};
use crate::stats::{StreamStats, TcpStreamStats, NetworkHealth, PtpStats, StreamQuality, AvtpStreamStats};
use crate::parser::{detect_protocol, parse_tcp_packet, parse_rtp, parse_ts_refclk, is_multicast, is_aes67_multicast, is_st2110_multicast};
use crate::report::{create_logger, print_report};

// Constants from protocols module
use protocols::{
    DEFAULT_CLOCK_HZ, STREAM_TIMEOUT_SECS,
};

// ═══════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════

fn main() {
    let device = cli::select_interface();
    let selected_protocols = cli::prompt_protocol_selection();
    let protocol_names = cli::selected_protocol_names(&selected_protocols);
    let bpf_filter = cli::build_bpf_filter(&selected_protocols);
    let expanded_protocols: Vec<protocols::ProtocolChoice> = selected_protocols.iter()
        .flat_map(|c| c.includes())
        .collect();
    let mut logger = create_logger(&protocol_names).expect("Unable to create log file");

    let proto_display = cli::selected_protocol_display(&selected_protocols);
    let banner = if proto_display == "all protocols" {
        format!("📡 Listening on {}  —  all protocols", device.name)
    } else {
        format!("📡 Listening on {}  for {}  (+ PTP, IGMP)  streams", device.name, proto_display)
    };
    println!("{}", banner);
    logger.log(&banner);

    // ── Opening capture with BPF filter ───────────────
    let mut cap = Capture::from_device(device.name.as_str())
        .unwrap()
        .promisc(true)
        .immediate_mode(true)
        .timeout(1000)  // unblocks the loop so the 5-second report fires even on quiet networks
        .open()
        .unwrap();

    cap.filter(&bpf_filter, true)
        .expect("BPF filter failure — run as root/sudo");

    // ── Global state ──────────────────────────────────────
    let mut streams:       HashMap<String, StreamStats> = HashMap::new();
    let mut tcp_streams:   HashMap<String, TcpStreamStats> = HashMap::new();
    let mut sdp_cache:     HashMap<String, SdpSession> = HashMap::new();
    // PTP stats keyed by (domain, version) to separate Dante PTPv1 from AES67/ST2110 PTPv2
    let mut ptp_domains:   HashMap<(u8, u8), PtpStats> = HashMap::new();
    let mut network_health: NetworkHealth = NetworkHealth::new();
    // NDI sender IPs learned from mDNS — used for IP-based stream detection
    // (official NDI SDK assigns ports dynamically, port-range matching is unreliable)
    let mut ndi_sources: std::collections::HashSet<Ipv4Addr> = std::collections::HashSet::new();
    // Deduplicates IGMP Join console output — cleared on Leave so re-joins print again
    let mut igmp_joins_seen: std::collections::HashSet<(Ipv4Addr, Ipv4Addr)> = std::collections::HashSet::new();
    // AVB extended state
    let mut avtp_streams: std::collections::HashMap<[u8; 8], AvtpStreamStats> = std::collections::HashMap::new();
    let mut msrp_state:   std::collections::HashMap<[u8; 8], crate::protocols::MsrpDeclaration> = std::collections::HashMap::new();
    let mut mvrp_vlans:   std::collections::HashSet<u16> = std::collections::HashSet::new();
    let mut bytes_this_window: u64 = 0;
    let mut last_report = Instant::now();

    // ── Capture loop ────────────────────────────────
    loop {
        // Report check at the TOP of the loop so it fires even when cap.next_packet()
        // times out (Err path hits `continue` and never reaches code below the read).
        if last_report.elapsed() > Duration::from_secs(5) {
            for stats in ptp_domains.values_mut() {
                if stats.check_timeout() {
                    logger.log(&format!(
                        "❌ PTP Clock LOST (Domain {} v{}) [{}]",
                        stats.domain,
                        stats.version,
                        stats.protocol_kind.as_deref().unwrap_or("?")
                    ));
                }
            }
            for sdp in sdp_cache.values() {
                let session_active = sdp.media.iter().any(|m| {
                    streams.values().any(|s| s.dst_port == m.port && s.packets > 0)
                });
                if !session_active { continue; }
                for m in &sdp.media {
                    if m.ts_refclk.is_empty() { continue; }
                    let Some((claimed_gm, claimed_domain)) = parse_ts_refclk(&m.ts_refclk) else { continue };
                    let entry = ptp_domains.get(&(claimed_domain, protocols::PTP_VERSION_V2))
                        .or_else(|| ptp_domains.get(&(claimed_domain, protocols::PTP_VERSION_V1)));
                    match entry {
                        None => {
                            let alert = format!(
                                "⚠  SDP \"{}\" claims PTP domain {} but no PTP traffic detected",
                                sdp.session_name, claimed_domain
                            );
                            println!("\x1b[33m{}\x1b[0m", alert);
                            logger.log(&alert);
                        }
                        Some(ptp) if ptp.clock_valid => {
                            if let Some(ref active_gm) = ptp.last_grandmaster
                                && *active_gm != claimed_gm
                            {
                                let alert = format!(
                                    "⚠  PTP grandmaster mismatch for SDP \"{}\": claims {} (domain {}), active is {}",
                                    sdp.session_name, claimed_gm, claimed_domain, active_gm
                                );
                                println!("\x1b[33m{}\x1b[0m", alert);
                                logger.log(&alert);
                            }
                        }
                        _ => {}
                    }
                }
            }
            network_health.calculate_score(&streams, &tcp_streams, &ptp_domains, &msrp_state);
            let requires_valid_ptp = cli::protocol_requires_ptp(&selected_protocols);
            print_report(&streams, &tcp_streams, &ptp_domains, requires_valid_ptp, &mut logger, &network_health, bytes_this_window, &avtp_streams, &msrp_state, &mvrp_vlans);
            bytes_this_window = 0;
            last_report = Instant::now();
            streams.retain(|_, s| {
                s.last_packet_time
                    .map_or(true, |t| t.elapsed().as_secs() < STREAM_TIMEOUT_SECS * 2)
            });
            tcp_streams.retain(|_, s| {
                s.last_seen.elapsed().as_secs() < STREAM_TIMEOUT_SECS * 2
                    && !matches!(s.stream_quality, StreamQuality::Terminated)
            });
            avtp_streams.retain(|_, s| {
                s.last_seen.elapsed().as_secs() < STREAM_TIMEOUT_SECS * 2
            });
        }

        let packet = match cap.next_packet() { Ok(p) => p, Err(_) => continue };
        let eth    = match EthernetPacket::new(packet.data) { Some(e) => e, _ => continue };
        let now    = Instant::now();

        if let Some(proto) = detect_protocol(&eth) {
            let should_process = match &proto {
                AvProtocol::Ptp { .. } | AvProtocol::Igmp { .. } | AvProtocol::Sap { .. } => true,
                _ => proto.is_selected(&expanded_protocols),
            };
            if should_process {
                match proto {

                    // ── SAP/SDP ──────────────────────────────────
                    AvProtocol::Sap { src: _, sdp } => {
                        for m in &sdp.media {
                            // Enrich stream SDP metadata by port (break on first match)
                            for stats in streams.values_mut() {
                                if stats.dst_port == m.port && stats.sdp_name.is_none() {
                                    stats.sdp_name   = Some(sdp.session_name.clone());
                                    stats.sdp_rtpmap = Some(m.rtpmap.clone());
                                    if m.clock_hz > 0.0 { stats.clock_hz = m.clock_hz; }
                                    if m.ptime_ms > 0.0 { stats.ptime_ms = m.ptime_ms; }
                                    if m.channels > 0   { stats.channels = m.channels; }
                                    break;
                                }
                            }
                        }
                        sdp_cache.insert(sdp.session_id.clone(), sdp);
                    }

                    // ── PTP ───────────────────────────────────────
                    AvProtocol::Ptp { info } => {
                        let stats = ptp_domains
                            .entry((info.domain, info.version))
                            .or_insert_with(|| PtpStats::new(info.domain, info.version));
                        stats.update(&info, &info.protocol_kind);
                    }

                    // ── AES67 ────────────────────────────────────
                    AvProtocol::Aes67 { dst, dst_port, .. } => {
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
                        if let Some(ip) = pnet_packet::ipv4::Ipv4Packet::new(eth.payload()) {
                            if let Some(udp) = pnet_packet::udp::UdpPacket::new(ip.payload()) {
                                network_health.track_dscp(&ip);
                                if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) {
                                    stats.update(seq, ts, ssrc, udp.payload().len());
                                }
                            }
                        }
                    }

                    // ── ST 2110 ──────────────────────────────────
                    AvProtocol::St2110 { dst, dst_port, stream_type, .. } => {
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
                        if let Some(ip) = pnet_packet::ipv4::Ipv4Packet::new(eth.payload()) {
                            if let Some(udp) = pnet_packet::udp::UdpPacket::new(ip.payload()) {
                                network_health.track_dscp(&ip);
                                if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) {
                                    stats.update(seq, ts, ssrc, udp.payload().len());
                                }
                            }
                        }
                    }

                    // ── Dante ────────────────────────────────────
                    AvProtocol::Dante { kind, src, dst_port } => {
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
                                if let Some(ip) = pnet_packet::ipv4::Ipv4Packet::new(eth.payload()) {
                                    if let Some(udp) = pnet_packet::udp::UdpPacket::new(ip.payload()) {
                                        if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) {
                                            stats.update(seq, ts, ssrc, udp.payload().len());
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // ── NDI ──────────────────────────────────────
                    AvProtocol::Ndi { kind, src } => {
                        match kind {
                            NdiKind::Discovery => {
                                ndi_sources.insert(src);
                                let msg = format!("🔍 NDI source: {}", src);
                                println!("{}", msg);
                                logger.log(&msg);
                            }
                            _ => {}
                        }
                    }

                    // ── AVB ──────────────────────────────────────
                    AvProtocol::Avb { subtype, stream_id } => {
                        let stats = streams.entry(format!("AVB subtype=0x{:02X}", subtype))
                            .or_insert_with(|| StreamStats::new("AVB", 0.0));
                        stats.packets += 1;
                        stats.last_packet_time = Some(now);
                        if let Some(sid) = stream_id {
                            let entry = avtp_streams.entry(sid)
                                .or_insert_with(|| AvtpStreamStats::new(sid, subtype));
                            entry.packets += 1;
                            entry.last_seen = now;
                        }
                    }

                    // ── MSRP ─────────────────────────────────────
                    AvProtocol::Msrp { declarations } => {
                        for decl in declarations {
                            if matches!(decl.decl_type, MsrpDeclType::TalkerFailed) {
                                let code_str = match decl.failure_code {
                                    Some(1) => " (insufficient bandwidth)",
                                    Some(2) => " (insufficient bridge resources)",
                                    Some(3) => " (insufficient bandwidth for Traffic Class)",
                                    Some(n) => { let _ = n; " (failure)" }
                                    None    => "",
                                };
                                let id = &decl.stream_id;
                                let alert = format!(
                                    "⚠  MSRP Talker Failed: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:04x}{}",
                                    id[0], id[1], id[2], id[3], id[4], id[5],
                                    u16::from_be_bytes([id[6], id[7]]),
                                    code_str
                                );
                                println!("\x1b[33m{}\x1b[0m", alert);
                                logger.log(&alert);
                            }
                            msrp_state.insert(decl.stream_id, decl);
                        }
                    }

                    // ── MVRP ─────────────────────────────────────
                    AvProtocol::Mvrp { vlan_ids } => {
                        for vid in vlan_ids {
                            if mvrp_vlans.insert(vid) {
                                let msg = format!("🔖 MVRP: VLAN {} registered", vid);
                                println!("{}", msg);
                                logger.log(&msg);
                            }
                        }
                    }

                    // ── SRT ──────────────────────────────────────
                    AvProtocol::Srt { src, dst, dst_port, is_handshake }
                        if !ndi_sources.contains(&src) && !ndi_sources.contains(&dst) => {
                        let key = format!("SRT {}:{}", src, dst_port);
                        let stats = streams.entry(key)
                            .or_insert_with(|| StreamStats::new("SRT", 0.0));
                        stats.packets += 1;
                        stats.last_packet_time = Some(now);
                        if is_handshake {
                            let msg = format!("🤝 SRT handshake: {} → port {}", src, dst_port);
                            println!("{}", msg);
                            logger.log(&msg);
                        }
                    }

                    // ── RIST ─────────────────────────────────────
                    AvProtocol::Rist { src, dst, dst_port }
                        if !ndi_sources.contains(&src) && !ndi_sources.contains(&dst) => {
                        let key = format!("RIST {}:{}", dst, dst_port);
                        let stats = streams.entry(key)
                            .or_insert_with(|| {
                                let mut s = StreamStats::new_with_info("RIST", DEFAULT_CLOCK_HZ, is_multicast(dst), dst, dst_port);
                                s.media_type = "video".to_string();
                                s
                            });
                        if let Some(ip) = pnet_packet::ipv4::Ipv4Packet::new(eth.payload()) {
                            if let Some(udp) = pnet_packet::udp::UdpPacket::new(ip.payload()) {
                                if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) {
                                    stats.update(seq, ts, ssrc, udp.payload().len());
                                }
                            }
                        }
                        let _ = src;
                    }

                    // ── IGMP ─────────────────────────────────────
                    AvProtocol::Igmp { src, group, igmp_type } => {
                        match &igmp_type {
                            IgmpType::Join => {
                                if igmp_joins_seen.insert((src, group)) {
                                    let msg = format!("➕ IGMP Join: {} → group {}", src, group);
                                    println!("{}", msg);
                                    logger.log(&msg);
                                }
                            }
                            IgmpType::Leave => {
                                igmp_joins_seen.remove(&(src, group));
                                let msg = format!("➖ IGMP Leave: {} → group {}", src, group);
                                println!("{}", msg);
                                logger.log(&msg);
                                for key in streams.keys() {
                                    if streams[key].dst_ip == Some(group) {
                                        let alert = format!("    ⚠  IGMP Leave on monitored group {}", group);
                                        println!("\x1b[33m{}\x1b[0m", alert);
                                        logger.log(&alert);
                                    }
                                }
                            }
                            IgmpType::Query => {
                                network_health.last_igmp_query = Some(now);
                                let msg = format!("❓ IGMP Query: {} → group {}", src, group);
                                println!("{}", msg);
                                logger.log(&msg);
                            }
                            IgmpType::Unknown(t) => {
                                let msg = format!("❔ IGMP Unknown(0x{:02x}): {} → group {}", t, src, group);
                                println!("{}", msg);
                                logger.log(&msg);
                            }
                        }
                    }

                    _ => {}
                }
            }
        }

        // ── Hoist IPv4 parse — shared by NDI detection and health tracking ───
        let outer_ip = pnet_packet::ipv4::Ipv4Packet::new(eth.payload());

        // ── NDI stream via known source IP ───────────────────────────────────
        // The official NDI SDK uses dynamically assigned ports advertised in mDNS.
        // Port-range matching is unreliable; we identify NDI traffic by the sender
        // IP learned from mDNS discovery instead.
        let ndi_selected = expanded_protocols.iter().any(|c| matches!(c, protocols::ProtocolChoice::NDI | protocols::ProtocolChoice::All));
        if ndi_selected {
        if let Some(ref ip) = outer_ip {
            if !ndi_sources.is_empty()
                && ip.get_next_level_protocol() == pnet_packet::ip::IpNextHeaderProtocols::Tcp
            {
                let s = ip.get_source();
                let d = ip.get_destination();
                let sender = if ndi_sources.contains(&s) { Some(s) }
                            else if ndi_sources.contains(&d) { Some(d) }
                            else { None };
                if let Some(sender_ip) = sender {
                    let stats = streams.entry(format!("NDI {}", sender_ip))
                        .or_insert_with(|| StreamStats::new("NDI", 0.0));
                    stats.packets += 1;
                    stats.last_packet_time = Some(now);
                }
            }
        }
        } // ndi_selected

        // ── TCP Monitoring — NDI ports only ──────────────────
        // Only track TCP flows on NDI ports (5960-5980). Unrelated TCP (HTTP, SSH, etc.)
        // is ignored even when `tcp` is in the BPF filter, keeping the report clean.
        let is_tcp = outer_ip.as_ref().map_or(false, |ip| {
            ip.get_next_level_protocol() == pnet_packet::ip::IpNextHeaderProtocols::Tcp
        });
        if is_tcp {
        if let Some((src_ip, dst_ip, src_port, dst_port, has_fin, has_syn, has_rst, seq, ack)) = parse_tcp_packet(&eth) {
            let ndi_range = protocols::NDI_PORT_MIN..=protocols::NDI_PORT_MAX;
            let is_ndi = ndi_range.contains(&src_port) || ndi_range.contains(&dst_port)
                      || ndi_sources.contains(&src_ip) || ndi_sources.contains(&dst_ip);
            if is_ndi {
                let key = format!("TCP {}:{} → {}:{}", src_ip, src_port, dst_ip, dst_port);
                let tcp_stat = tcp_streams.entry(key.clone()).or_insert_with(|| TcpStreamStats::new(src_ip, src_port, dst_ip, dst_port));
                tcp_stat.packets += 1;
                tcp_stat.last_seen = now;

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
        } // end is_tcp guard
        }

        // ── Network health tracking ───────────────────────────
        network_health.total_packets += 1;
        bytes_this_window += eth.packet().len() as u64;
        if let Some(ref ip) = outer_ip {
            if is_multicast(ip.get_destination()) {
                network_health.multicast_packets += 1;
            } else {
                network_health.unicast_packets += 1;
            }
        }

    }
}