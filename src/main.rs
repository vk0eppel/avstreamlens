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
use crate::stats::{StreamStats, TcpStreamStats, NetworkHealth, PtpStats, PtpEvent, StreamQuality, AvtpStreamStats};
use crate::parser::{detect_protocol, parse_tcp_packet, parse_rtp, parse_ts_refclk, is_multicast, is_aes67_multicast, is_st2110_multicast, unwrap_vlan};
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
    // Deduplicates IGMP Join console output — cleared on Leave so re-joins print again.
    // Stores last-seen Instant so abandoned entries (host crash, no Leave) can be purged.
    let mut igmp_joins_seen: std::collections::HashMap<(Ipv4Addr, Ipv4Addr), Instant> = std::collections::HashMap::new();
    // Dante device names learned from mDNS TXT records, keyed by transmitter IP
    let mut dante_names: std::collections::HashMap<Ipv4Addr, String> = std::collections::HashMap::new();
    // NDI source names learned from mDNS TXT records, keyed by source IP
    let mut ndi_names: std::collections::HashMap<Ipv4Addr, String> = std::collections::HashMap::new();
    // AVB extended state
    let mut avtp_streams: std::collections::HashMap<[u8; 8], AvtpStreamStats> = std::collections::HashMap::new();
    let mut msrp_state:   std::collections::HashMap<[u8; 8], crate::protocols::MsrpDeclaration> = std::collections::HashMap::new();
    let mut mvrp_vlans:   std::collections::HashSet<u16> = std::collections::HashSet::new();
    // EEE detection: keyed by (chassis_id, port_id) → (tx_wake_us, rx_wake_us)
    let mut eee_ports:    std::collections::HashMap<(String, String), (u16, u16)> = std::collections::HashMap::new();
    let mut bytes_this_window: u64 = 0;
    let mut last_report = Instant::now();

    // ── Capture loop ────────────────────────────────
    loop {
        // Report check at the TOP of the loop so it fires even when cap.next_packet()
        // times out (Err path hits `continue` and never reaches code below the read).
        if last_report.elapsed() > Duration::from_secs(5) {
            for stats in ptp_domains.values_mut() {
                if let Some(PtpEvent::ClockLost) = stats.check_timeout() {
                    let msg = format!(
                        "❌ PTP Clock LOST (Domain {} v{}) [{}]",
                        stats.domain,
                        stats.version,
                        stats.protocol_kind.as_deref().unwrap_or("?")
                    );
                    println!("\x1b[31m{}\x1b[0m", msg);
                    logger.log(&msg);
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
            // Aggregate NDI bitrate from all TCP flows matching the source IP
            for stream in streams.values_mut() {
                if stream.protocol == "NDI"
                    && let Some(src_ip) = stream.dst_ip
                {
                    stream.bitrate_bps = tcp_streams.values()
                        .filter(|t| t.src_ip == src_ip || t.dst_ip == src_ip)
                        .map(|t| t.bitrate_bps)
                        .sum();
                }
            }

            network_health.calculate_score(&streams, &tcp_streams, &ptp_domains, &msrp_state, &eee_ports);

            // Version-aware PTP clock check:
            //   AES67/ST2110 require PTPv2 (a PTPv1 clock is not sufficient)
            //   Dante accepts PTPv1 or PTPv2
            //   AVB requires L2 gPTP (protocol_kind = "AVB")
            let ptp_ok = !cli::protocol_requires_ptp(&selected_protocols) || {
                let needs_ptpv2 = expanded_protocols.iter().any(|c|
                    matches!(c, protocols::ProtocolChoice::AES67 | protocols::ProtocolChoice::ST2110));
                let needs_ptp_any = expanded_protocols.iter().any(|c|
                    matches!(c, protocols::ProtocolChoice::Dante));
                let needs_gptp = expanded_protocols.iter().any(|c|
                    matches!(c, protocols::ProtocolChoice::AVB));

                let has_ptpv2 = ptp_domains.values().any(|s|
                    s.clock_valid && s.version == protocols::PTP_VERSION_V2
                    && s.protocol_kind.as_deref() != Some("AVB"));
                let has_ptp = ptp_domains.values().any(|s| s.clock_valid);
                let has_gptp = ptp_domains.values().any(|s|
                    s.clock_valid && s.protocol_kind.as_deref() == Some("AVB"));

                (!needs_ptpv2 || has_ptpv2)
                && (!needs_ptp_any || has_ptp)
                && (!needs_gptp || has_gptp)
            };

            print_report(&streams, &tcp_streams, &ptp_domains, ptp_ok, &mut logger, &network_health, bytes_this_window, &avtp_streams, &msrp_state, &mvrp_vlans, &eee_ports);
            bytes_this_window = 0;
            last_report = Instant::now();
            // Reset per-cycle counters so alerts reflect the current 5s window
            for s in streams.values_mut() {
                s.gap_events      = 0;
                s.max_iat_ms      = 0.0;
                s.pt_mismatches   = 0;
                s.dscp_violations = 0;
                s.ssrc_changes    = 0;
            }
            streams.retain(|_, s| {
                s.last_packet_time
                    .is_none_or(|t| t.elapsed().as_secs() < STREAM_TIMEOUT_SECS * 2)
            });
            tcp_streams.retain(|_, s| {
                s.last_seen.elapsed().as_secs() < STREAM_TIMEOUT_SECS * 2
                    && !matches!(s.stream_quality, StreamQuality::Terminated)
            });
            avtp_streams.retain(|_, s| {
                s.last_seen.elapsed().as_secs() < STREAM_TIMEOUT_SECS * 2
            });
            // Drop IGMP Join entries from hosts that vanished without sending a Leave
            // (cable pull, crash). 5 minutes is well above the IGMPv2 query interval.
            igmp_joins_seen.retain(|_, t| t.elapsed() < Duration::from_secs(300));
        }

        let packet = match cap.next_packet() {
            Ok(p) => p,
            Err(pcap::Error::TimeoutExpired) => continue, // expected on quiet networks
            Err(e) => {
                // Real capture failure (interface down, permissions revoked, etc.).
                // Log once and exit — busy-looping on a broken handle helps no one.
                let msg = format!("❌ Capture error: {} — exiting", e);
                eprintln!("\x1b[31m{}\x1b[0m", msg);
                logger.log(&msg);
                std::process::exit(1);
            }
        };
        let eth    = match EthernetPacket::new(packet.data) { Some(e) => e, _ => continue };
        let now    = Instant::now();
        // VLAN-unwrapped L2 payload (handles 802.1Q / QinQ tagged frames).
        let (l2_et, l2_payload) = unwrap_vlan(&eth).unwrap_or((0, &[][..]));

        if let Some(proto) = detect_protocol(&eth)
            && proto.is_selected(&expanded_protocols)
        {
            match proto {

                    // ── SAP/SDP ──────────────────────────────────
                    AvProtocol::Sap { src: _, sdp } => {
                        for m in &sdp.media {
                            // Enrich stream SDP metadata by port (break on first match)
                            for stats in streams.values_mut() {
                                if stats.dst_port == m.port && stats.sdp_name.is_none() {
                                    stats.sdp_name   = Some(sdp.session_name.clone());
                                    stats.sdp_rtpmap = Some(m.rtpmap.clone());
                                    if m.clock_hz > 0.0 {
                                        stats.clock_hz = m.clock_hz;
                                        stats.clock_hz_confirmed = true;
                                    }
                                    if m.ptime_ms > 0.0 { stats.ptime_ms = m.ptime_ms; }
                                    if m.channels > 0   { stats.channels = m.channels; }
                                    if let Some(pt) = m.payload_types.first().copied() {
                                        stats.expected_pt = Some(pt);
                                    }
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
                        if let Some(event) = stats.update(&info, &info.protocol_kind) {
                            let gm = stats.last_grandmaster.as_deref().unwrap_or("?");
                            let (msg, color) = match event {
                                PtpEvent::GrandmasterDetected => (
                                    format!("✓  GRANDMASTER DETECTED (Domain {} v{}): {}",
                                        stats.domain, stats.version, gm),
                                    "32",
                                ),
                                PtpEvent::GrandmasterChanged { from } => (
                                    format!("⚠️  GRANDMASTER CHANGED (Domain {} v{}): {} → {}",
                                        stats.domain, stats.version, from, gm),
                                    "33",
                                ),
                                // update() does not emit ClockLost — only check_timeout() does.
                                PtpEvent::ClockLost => unreachable!(),
                            };
                            println!("\x1b[{}m{}\x1b[0m", color, msg);
                            logger.log(&msg);
                        }
                    }

                    // ── AES67 ────────────────────────────────────
                    AvProtocol::Aes67 { dst, dst_port, payload_type, .. } => {
                        let key = format!("AES67 {}:{}", dst, dst_port);
                        let stats = streams.entry(key).or_insert_with(|| {
                            let sdp_media = sdp_cache.values()
                                .flat_map(|s| s.media.iter())
                                .find(|m| m.port == dst_port);
                            let (clock, rtpmap, exp_pt, confirmed) = sdp_media
                                .map(|m| (m.clock_hz, Some(m.rtpmap.clone()), m.payload_types.first().copied(), m.clock_hz > 0.0))
                                .unwrap_or((DEFAULT_CLOCK_HZ, None, None, false));
                            let mut s = StreamStats::new_with_info("AES67", clock, is_aes67_multicast(dst), dst, dst_port);
                            s.sdp_rtpmap = rtpmap;
                            s.media_type = "audio".to_string();
                            s.channels = 1;
                            s.expected_pt = exp_pt;
                            s.clock_hz_confirmed = confirmed;
                            s
                        });
                        if let Some(ip) = pnet_packet::ipv4::Ipv4Packet::new(l2_payload)
                            && let Some(udp) = pnet_packet::udp::UdpPacket::new(ip.payload())
                        {
                            // AES67 requires DSCP EF (46) per spec
                            if ip.get_dscp() != 46 { stats.dscp_violations += 1; }
                            if ip.get_ecn() == 3 { network_health.ecn_congestion_marks += 1; }
                            if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) {
                                if stats.expected_pt.is_some_and(|exp| payload_type != exp) {
                                    stats.pt_mismatches += 1;
                                }
                                stats.update(seq, ts, ssrc, udp.payload().len());
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
                            let sdp_media = sdp_cache.values()
                                .flat_map(|s| s.media.iter())
                                .find(|m| m.port == dst_port);
                            let (clock, rtpmap, exp_pt, confirmed) = sdp_media
                                .map(|m| (m.clock_hz, Some(m.rtpmap.clone()), m.payload_types.first().copied(), m.clock_hz > 0.0))
                                .unwrap_or((default_clock, None, None, false));
                            let mut s = StreamStats::new_with_info(label, clock, is_st2110_multicast(dst), dst, dst_port);
                            s.sdp_rtpmap = rtpmap;
                            s.media_type = match stream_type {
                                St2110Type::Video => "video".to_string(),
                                St2110Type::Audio => "audio".to_string(),
                                St2110Type::Ancdata => "ancillary".to_string(),
                                St2110Type::Unknown => "unknown".to_string(),
                            };
                            s.expected_pt = exp_pt;
                            // ST2110-20 video always uses 90 kHz per spec — enable TS
                            // discontinuity detection even without SDP.
                            // ST2110-30 audio: default 1 ms ptime enables burst detection.
                            s.clock_hz_confirmed = confirmed || matches!(stream_type, St2110Type::Video);
                            if !confirmed && matches!(stream_type, St2110Type::Audio) {
                                s.ptime_ms = 1.0;
                            }
                            s
                        });
                        if let Some(ip) = pnet_packet::ipv4::Ipv4Packet::new(l2_payload)
                            && let Some(udp) = pnet_packet::udp::UdpPacket::new(ip.payload())
                        {
                            // ST2110-20 video accepts EF/CS5/AF41; audio/anc require EF only
                            let dscp_ok = if matches!(stream_type, St2110Type::Video) {
                                matches!(ip.get_dscp(), 46 | 40 | 34)
                            } else {
                                ip.get_dscp() == 46
                            };
                            if !dscp_ok { stats.dscp_violations += 1; }
                            if ip.get_ecn() == 3 { network_health.ecn_congestion_marks += 1; }
                            if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) {
                                let rtp_pt = udp.payload()[1] & 0x7F;
                                if stats.expected_pt.is_some_and(|exp| rtp_pt != exp) {
                                    stats.pt_mismatches += 1;
                                }
                                stats.update(seq, ts, ssrc, udp.payload().len());
                            }
                        }
                    }

                    // ── Dante ────────────────────────────────────
                    AvProtocol::Dante { kind, src, dst_port } => {
                        match kind {
                            DanteKind::Discovery { device_name } => {
                                if let Some(ref name) = device_name {
                                    dante_names.insert(src, name.clone());
                                }
                                let label = device_name.as_deref().unwrap_or("unknown device");
                                let msg = format!("🔍 Dante discovered: {}  \"{}\"", src, label);
                                println!("{}", msg);
                                logger.log(&msg);
                            }
                            DanteKind::Control     => {}
                            DanteKind::AudioStream => {
                                let key   = format!("Dante {}:{}", src, dst_port);
                                let stats = streams.entry(key)
                                    .or_insert_with(|| {
                                        let mut s = StreamStats::new("Dante", DEFAULT_CLOCK_HZ);
                                        s.ptime_ms = 1.0; // Dante standard: 48 samples @ 48kHz = 1ms
                                        s.sdp_name = dante_names.get(&src).cloned();
                                        s
                                    });
                                if let Some(ip) = pnet_packet::ipv4::Ipv4Packet::new(l2_payload)
                                    && let Some(udp) = pnet_packet::udp::UdpPacket::new(ip.payload())
                                {
                                    // Dante audio requires DSCP EF (46)
                                    if ip.get_dscp() != 46 { stats.dscp_violations += 1; }
                                    if ip.get_ecn() == 3 { network_health.ecn_congestion_marks += 1; }
                                    if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) {
                                        stats.update(seq, ts, ssrc, udp.payload().len());
                                    }
                                }
                            }
                        }
                    }

                    // ── NDI ──────────────────────────────────────
                    AvProtocol::Ndi { kind: NdiKind::Discovery { source_name }, src } => {
                        ndi_sources.insert(src);
                        if let Some(ref name) = source_name {
                            ndi_names.insert(src, name.clone());
                        }
                        let label = source_name.as_deref().unwrap_or("unknown source");
                        let msg = format!("🔍 NDI source: {}  \"{}\"", src, label);
                        println!("{}", msg);
                        logger.log(&msg);
                    }

                    // ── AVB ──────────────────────────────────────
                    AvProtocol::Avb { subtype, stream_id } => {
                        let label = protocols::avtp_subtype_name(subtype);
                        let frame_bytes = eth.packet().len() as u64;
                        let stats = streams.entry(format!("AVB {}", label))
                            .or_insert_with(|| StreamStats::new("AVB", 0.0));
                        stats.packets += 1;
                        stats.last_packet_time = Some(now);
                        // Aggregate bitrate from Ethernet frame size
                        stats.bytes_total += frame_bytes;
                        let elapsed = stats.last_bitrate_check.elapsed();
                        if elapsed > Duration::from_secs(1) {
                            let delta = stats.bytes_total.saturating_sub(stats.bytes_at_check);
                            stats.bitrate_bps = (delta as f64 * 8.0 / elapsed.as_secs_f64()) as u64;
                            stats.bytes_at_check = stats.bytes_total;
                            stats.packets_at_check = stats.packets;
                            stats.last_bitrate_check = now;
                        }
                        if let Some(sid) = stream_id {
                            // AVTP sequence counter is byte 2 of the AVTP payload
                            let avtp_seq = eth.payload().get(2).copied();
                            let entry = avtp_streams.entry(sid)
                                .or_insert_with(|| AvtpStreamStats::new(sid, subtype));
                            entry.packets += 1;
                            entry.last_seen = now;
                            entry.update_bitrate(frame_bytes, now);
                            if let Some(seq) = avtp_seq { entry.update_seq(seq); }
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

                    // ── LLDP / EEE ───────────────────────────────
                    AvProtocol::LldpEee { chassis_id, port_id, tx_wake_us, rx_wake_us } => {
                        let key = (chassis_id.clone(), port_id.clone());
                        if eee_ports.insert(key, (tx_wake_us, rx_wake_us)).is_none() {
                            let alert = format!(
                                "⚠  EEE active on switch port \"{}\" (chassis {})  —  Tx wake: {}µs  Rx wake: {}µs  —  disable EEE for AV reliability",
                                port_id, chassis_id, tx_wake_us, rx_wake_us
                            );
                            println!("\x1b[33m{}\x1b[0m", alert);
                            logger.log(&alert);
                        }
                    }

                    // ── IGMP ─────────────────────────────────────
                    AvProtocol::Igmp { src, group, igmp_type } => {
                        match &igmp_type {
                            IgmpType::Join => {
                                let first_time = !igmp_joins_seen.contains_key(&(src, group));
                                igmp_joins_seen.insert((src, group), now);
                                if first_time {
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
                                // Track interval between consecutive queries (RFC 3376 default 125s)
                                if let Some(last) = network_health.last_igmp_query {
                                    network_health.igmp_query_interval_secs =
                                        Some(last.elapsed().as_secs());
                                }
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

            }
        }

        // ── Hoist IPv4 parse — shared by NDI detection and health tracking ───
        let outer_ip = if l2_et == 0x0800 {
            pnet_packet::ipv4::Ipv4Packet::new(l2_payload)
        } else {
            None
        };

        // ── NDI stream via known source IP ───────────────────────────────────
        // The official NDI SDK uses dynamically assigned ports advertised in mDNS.
        // Port-range matching is unreliable; we identify NDI traffic by the sender
        // IP learned from mDNS discovery instead.
        let ndi_selected = expanded_protocols.iter().any(|c| matches!(c, protocols::ProtocolChoice::NDI | protocols::ProtocolChoice::All));
        if ndi_selected
            && let Some(ref ip) = outer_ip
            && !ndi_sources.is_empty()
            && ip.get_next_level_protocol() == pnet_packet::ip::IpNextHeaderProtocols::Tcp
        {
            let s = ip.get_source();
            let d = ip.get_destination();
            let sender = if ndi_sources.contains(&s) { Some(s) }
                        else if ndi_sources.contains(&d) { Some(d) }
                        else { None };
            if let Some(sender_ip) = sender {
                let stats = streams.entry(format!("NDI {}", sender_ip))
                    .or_insert_with(|| {
                        let mut s = StreamStats::new_with_info("NDI", 0.0, false, sender_ip, 0);
                        s.sdp_name = ndi_names.get(&sender_ip).cloned();
                        s
                    });
                stats.packets += 1;
                stats.last_packet_time = Some(now);
            }
        }

        // ── TCP Monitoring — NDI ports only ──────────────────
        // Only track TCP flows on NDI ports (5960-5980). Unrelated TCP (HTTP, SSH, etc.)
        // is ignored even when `tcp` is in the BPF filter, keeping the report clean.
        let is_tcp = outer_ip.as_ref().is_some_and(|ip| {
            ip.get_next_level_protocol() == pnet_packet::ip::IpNextHeaderProtocols::Tcp
        });
        if is_tcp
            && let Some((src_ip, dst_ip, src_port, dst_port, has_fin, has_syn, has_rst, seq, ack)) = parse_tcp_packet(&eth)
        {
            let ndi_range = protocols::NDI_PORT_MIN..=protocols::NDI_PORT_MAX;
            let is_ndi = ndi_range.contains(&src_port) || ndi_range.contains(&dst_port)
                      || ndi_sources.contains(&src_ip) || ndi_sources.contains(&dst_ip);
            if is_ndi {
                let key = format!("TCP {}:{} → {}:{}", src_ip, src_port, dst_ip, dst_port);
                let tcp_stat = tcp_streams.entry(key.clone()).or_insert_with(|| TcpStreamStats::new(src_ip, dst_ip));
                tcp_stat.packets += 1;
                tcp_stat.last_seen = now;

                let estimated_payload = (eth.packet().len() as u64).saturating_sub(40);
                tcp_stat.bytes += estimated_payload;

                if has_fin { tcp_stat.fin_packets += 1; }
                if has_rst {
                    tcp_stat.rst_packets += 1;
                    network_health.tcp_retransmissions += 1;
                }

                // Wrap-aware: negative delta means seq went backward → retransmission
                if !has_syn
                    && let Some(last_seq) = tcp_stat.last_seq
                    && (seq.wrapping_sub(last_seq) as i32) < 0
                    && tcp_stat.packets > 2
                {
                    tcp_stat.retransmissions += 1;
                    network_health.tcp_retransmissions += 1;
                }
                // Advance last_seq only when seq moves forward (wrap-aware)
                if let Some(last_seq) = tcp_stat.last_seq {
                    if (seq.wrapping_sub(last_seq) as i32) > 0 {
                        tcp_stat.last_seq = Some(seq);
                    }
                } else {
                    tcp_stat.last_seq = Some(seq);
                }
                tcp_stat.last_ack = Some(ack);

                tcp_stat.update_bitrate();
                tcp_stat.update_quality();
            }
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