// AVStreamLens — main.rs
//
// IP AV Monitoring: AES67, SMPTE ST 2110, Dante, NDI, AVB
// - Pcap capture with BPF filter
// - Protocol detection by network signature (Audio/Video presets)
// - SAP/SDP parser for stream metadata
// - RFC 3550 jitter, SSRC tracking, dead-stream detection
// - PTP (IEEE 1588) and IGMP monitored when relevant to the selection
// - Terminal reporting every 5 seconds
//
// The capture loop here is intentionally thin. Per-protocol handlers live in
// capture.rs as methods on CaptureState; this fn owns the pcap handle, the
// 5-second report timer, and the post-dispatch IPv4/TCP tracking.

mod cli;
mod parser;
mod protocols;
mod stats;
mod report;
mod capture;

use pcap::Capture;
use pnet_packet::ethernet::EthernetPacket;
use pnet_packet::Packet;
use std::time::{Duration, Instant};

use crate::capture::{Alert, CaptureState};
use crate::parser::{detect_protocol, parse_tcp_packet, parse_ts_refclk, is_multicast, unwrap_vlan};
use crate::report::{create_logger, print_report};
use crate::stats::StreamStats;

fn main() {
    let device = cli::select_interface();
    let selected_protocols = cli::prompt_protocol_selection();
    let protocol_names = cli::selected_protocol_names(&selected_protocols);
    let bpf_filter = cli::build_bpf_filter(&selected_protocols);
    let expanded_protocols: Vec<protocols::ProtocolChoice> = selected_protocols.iter()
        .flat_map(|c| c.includes())
        .collect();
    let ndi_selected = expanded_protocols.iter().any(|c| matches!(c, protocols::ProtocolChoice::NDI));
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
        .expect("Unable to find capture device")
        .promisc(true)
        .immediate_mode(true)
        .timeout(1000)  // unblocks the loop so the 5-second report fires even on quiet networks
        .open()
        .expect("Unable to open capture — run as root/sudo (or as Administrator on Windows)");

    cap.filter(&bpf_filter, true)
        .expect("BPF filter failure — run as root/sudo");

    let mut state = CaptureState::new();
    let mut last_report = Instant::now();

    // ── Capture loop ────────────────────────────────
    loop {
        // Report check at the TOP of the loop so it fires even when cap.next_packet()
        // times out (Err path hits `continue` and never reaches code below the read).
        if last_report.elapsed() > Duration::from_secs(5) {
            // PTP clock-loss alerts
            let timeout_alerts = state.check_ptp_timeouts();
            capture::emit(&timeout_alerts, &mut logger);

            // ts-refclk cross-check: SDP-claimed grandmaster vs active PTP
            let sdp_alerts = ts_refclk_alerts(&state);
            capture::emit(&sdp_alerts, &mut logger);

            // Aggregate NDI bitrate from matching TCP flows
            state.aggregate_ndi_bitrate();

            state.network_health.calculate_score(
                &state.streams, &state.tcp_streams, &state.ptp_domains,
                &state.msrp_state, &state.eee_ports,
            );

            let missing_ptp = state.missing_ptp_clocks(&expanded_protocols);

            // Snapshot pcap kernel drop counters just before the report so the
            // numbers reflect the full capture window. Failures are silently
            // ignored — the report renders fine without them.
            let pcap_stats = cap.stats().ok().map(|s| (s.received, s.dropped, s.if_dropped));

            print_report(
                &state.streams, &state.tcp_streams, &state.ptp_domains, &missing_ptp,
                &mut logger, &state.network_health, state.bytes_this_window,
                &state.avtp_streams, &state.msrp_state, &state.mvrp_vlans, &state.eee_ports,
                state.pause_frames_this_window, state.pfc_frames_this_window,
                pcap_stats,
            );

            state.reset_window();
            last_report = Instant::now();
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
        let eth = match EthernetPacket::new(packet.data) { Some(e) => e, _ => continue };
        let now = Instant::now();
        // VLAN-unwrapped L2 payload (handles 802.1Q / QinQ tagged frames).
        let (l2_et, l2_payload) = unwrap_vlan(&eth).unwrap_or((0, &[][..]));
        let frame_bytes = eth.packet().len() as u64;
        // AVTP sequence counter is byte 2 of the AVTP payload — only meaningful for AVB.
        let avtp_seq = eth.payload().get(2).copied();

        if let Some(proto) = detect_protocol(&eth)
            && proto.is_selected(&expanded_protocols)
        {
            capture::dispatch(&mut state, proto, l2_payload, frame_bytes, avtp_seq, now, &mut logger);
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
        if ndi_selected
            && let Some(ref ip) = outer_ip
            && !state.ndi_sources.is_empty()
            && ip.get_next_level_protocol() == pnet_packet::ip::IpNextHeaderProtocols::Tcp
        {
            let s = ip.get_source();
            let d = ip.get_destination();
            let sender = if state.ndi_sources.contains(&s) { Some(s) }
                        else if state.ndi_sources.contains(&d) { Some(d) }
                        else { None };
            if let Some(sender_ip) = sender {
                let names = &state.ndi_names;
                let stats = state.streams.entry(format!("NDI {}", sender_ip))
                    .or_insert_with(|| {
                        let mut s = StreamStats::new_with_info("NDI", 0.0, false, sender_ip, 0);
                        s.sdp_name = names.get(&sender_ip).cloned();
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
                      || state.ndi_sources.contains(&src_ip) || state.ndi_sources.contains(&dst_ip);
            if is_ndi {
                let key = format!("TCP {}:{} → {}:{}", src_ip, src_port, dst_ip, dst_port);
                let tcp_stat = state.tcp_streams.entry(key).or_insert_with(|| crate::stats::TcpStreamStats::new(src_ip, dst_ip));
                tcp_stat.packets += 1;
                tcp_stat.last_seen = now;

                let estimated_payload = frame_bytes.saturating_sub(40);
                tcp_stat.bytes += estimated_payload;

                if has_fin { tcp_stat.fin_packets += 1; }
                if has_rst {
                    tcp_stat.rst_packets += 1;
                    state.network_health.tcp_retransmissions += 1;
                }

                // Wrap-aware: negative delta means seq went backward → retransmission
                if !has_syn
                    && let Some(last_seq) = tcp_stat.last_seq
                    && (seq.wrapping_sub(last_seq) as i32) < 0
                    && tcp_stat.packets > 2
                {
                    tcp_stat.retransmissions += 1;
                    state.network_health.tcp_retransmissions += 1;
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
        state.network_health.total_packets += 1;
        state.bytes_this_window += frame_bytes;
        if let Some(ref ip) = outer_ip {
            if is_multicast(ip.get_destination()) {
                state.network_health.multicast_packets += 1;
            } else {
                state.network_health.unicast_packets += 1;
            }
        }
    }
}

/// SDP `ts-refclk` cross-check: every 5s, validate that each SDP-claimed
/// grandmaster matches what's actually on the wire for that domain.
fn ts_refclk_alerts(state: &CaptureState) -> Vec<Alert> {
    let mut alerts = Vec::new();
    for sdp in state.sdp_cache.values() {
        let session_active = sdp.media.iter().any(|m| {
            state.streams.values().any(|s| s.dst_port == m.port && s.packets > 0)
        });
        if !session_active { continue; }
        for m in &sdp.media {
            if m.ts_refclk.is_empty() { continue; }
            let Some((claimed_gm, claimed_domain)) = parse_ts_refclk(&m.ts_refclk) else { continue };
            let entry = state.ptp_domains.get(&(claimed_domain, protocols::PTP_VERSION_V2))
                .or_else(|| state.ptp_domains.get(&(claimed_domain, protocols::PTP_VERSION_V1)));
            match entry {
                None => {
                    alerts.push(Alert::warn(format!(
                        "⚠  SDP \"{}\" claims PTP domain {} but no PTP traffic detected",
                        sdp.session_name, claimed_domain
                    )));
                }
                Some(ptp) if ptp.clock_valid => {
                    if let Some(ref active_gm) = ptp.last_grandmaster
                        && *active_gm != claimed_gm
                    {
                        alerts.push(Alert::warn(format!(
                            "⚠  PTP grandmaster mismatch for SDP \"{}\": claims {} (domain {}), active is {}",
                            sdp.session_name, claimed_gm, claimed_domain, active_gm
                        )));
                    }
                }
                _ => {}
            }
        }
    }
    alerts
}

