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
// capture.rs as methods on CaptureState, reached through dispatch() for every
// protocol including NDI/TCP; this fn owns the pcap handle, the 5-second
// report timer, and dynamic IGMP join draining.

mod cli;
mod parser;
mod protocols;
mod stats;
mod report;
mod capture;

use pcap::{Activated, Capture};
use pnet_packet::ethernet::EthernetPacket;
use pnet_packet::Packet;
use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::capture::{Alert, CaptureState};
use crate::parser::{detect_protocol_unwrapped, parse_ts_refclk, is_multicast, unwrap_vlan};
use crate::report::{create_logger, print_report, ReportSnapshot, ReportSession};

use std::collections::HashSet;
use std::net::{Ipv4Addr, UdpSocket};

/// Global colour flag — set once at startup, read-only after that.
/// Use `color_enabled()` everywhere rather than accessing this directly.
static COLOR: AtomicBool = AtomicBool::new(true);

/// Returns `true` when ANSI colour output is enabled (the default).
/// Set to `false` by `--no-color` or the `NO_COLOR` environment variable.
pub fn color_enabled() -> bool { COLOR.load(Ordering::Relaxed) }

/// Join multicast groups needed for AV protocol discovery on IGMP-snooped switches.
/// Returns the sockets — caller must keep them alive for the process lifetime.
/// Failure to join a group is non-fatal (missing permission, no route) — we log and continue.
fn join_multicast_groups(
    iface_ip: Ipv4Addr,
    expanded: &[protocols::ProtocolChoice],
    logger: &mut crate::report::Logger,
) -> Vec<UdpSocket> {
    let needs_ptp = expanded.iter().any(|c| matches!(c,
        protocols::ProtocolChoice::AES67 | protocols::ProtocolChoice::ST2110
        | protocols::ProtocolChoice::Dante | protocols::ProtocolChoice::AVB));
    let needs_sap = expanded.iter().any(|c| matches!(c,
        protocols::ProtocolChoice::AES67 | protocols::ProtocolChoice::ST2110));

    let mut groups: Vec<(Ipv4Addr, &str)> = Vec::new();
    if needs_ptp {
        groups.push((Ipv4Addr::new(224, 0, 1, 129), "PTPv1/v2 _DFLT (224.0.1.129)"));
        groups.push((Ipv4Addr::new(224, 0, 1, 130), "PTPv1 _ALT1 (224.0.1.130)"));
        groups.push((Ipv4Addr::new(224, 0, 1, 131), "PTPv1 _ALT2 (224.0.1.131)"));
        groups.push((Ipv4Addr::new(224, 0, 1, 132), "PTPv1 _ALT3 (224.0.1.132)"));
        groups.push((Ipv4Addr::new(224, 0, 0, 107), "PTPv2 peer-delay (224.0.0.107)"));
        // IGMPv3 Membership Reports go to 224.0.0.22 (all IGMPv3 routers).
        // Compliant snooping switches must flood 224.0.0.x, but joining defensively
        // ensures we receive reports on switches that snoop this range too.
        // Seeing these reports lets us learn — and then join — stream multicast groups
        // (e.g. Dante 239.255.x.x) that are otherwise pruned by IGMP snooping.
        groups.push((Ipv4Addr::new(224, 0, 0, 22), "IGMPv3 reports (224.0.0.22)"));
    }
    if needs_sap {
        groups.push((Ipv4Addr::new(224, 2, 127, 254), "SAP (224.2.127.254)"));
        // Dante announces AES67-mode sessions to 239.255.255.255 (per Audinate's
        // official port list), not the classic SAP group above. This address is
        // inside 239.255/16, so snooping switches prune it unless we join.
        groups.push((Ipv4Addr::new(239, 255, 255, 255), "SAP Dante/AES67 (239.255.255.255)"));
    }

    let mut sockets = Vec::new();
    for (group, label) in groups {
        match UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| { s.join_multicast_v4(&group, &iface_ip)?; Ok(s) })
        {
            Ok(s) => {
                let msg = format!("   ✓ Joined multicast group {}", label);
                logger.log(&msg);
                println!("{}", msg);
                sockets.push(s);
            }
            Err(e) => {
                let msg = format!("   ⚠ Could not join {} — {}", label, e);
                logger.log(&msg);
                println!("{}", msg);
            }
        }
    }
    sockets
}

/// Returns true if `group` is a stream multicast address that should be joined
/// given the selected protocols. Only 239.x.x.x (admin-scoped) addresses are
/// ever joined dynamically; 224.x.x.x PTP/mDNS groups are handled at startup.
fn should_join_group(group: &Ipv4Addr, expanded: &[protocols::ProtocolChoice]) -> bool {
    let oct = group.octets();
    if oct[0] != 239 { return false; }
    match oct[1] {
        69  => expanded.iter().any(|c| matches!(c, protocols::ProtocolChoice::AES67)),
        255 => expanded.iter().any(|c| matches!(c, protocols::ProtocolChoice::Dante)),
        _   => expanded.iter().any(|c| matches!(c, protocols::ProtocolChoice::ST2110)),
    }
}

/// Resets SIGPIPE to its default disposition (SIG_DFL) so a write to a
/// closed stdout (e.g. piping into `head`) kills the process directly
/// instead of the standard library turning the failed write into a panic
/// inside `println!`/`print!`. Rust installs SIG_IGN for SIGPIPE at startup;
/// this undoes that, matching the behavior of ripgrep, fd, and other Unix
/// CLI tools. No equivalent needed on Windows, which has no SIGPIPE.
#[cfg(unix)]
fn reset_sigpipe() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

fn main() {
    #[cfg(unix)]
    reset_sigpipe();

    let args = cli::parse_cli_args();
    let stdout_is_tty = std::io::stdout().is_terminal();
    COLOR.store(cli::resolve_color_enabled(args.no_color, stdout_is_tty), Ordering::Relaxed);
    let quiet = args.quiet;
    let duration_secs = args.duration;
    let is_offline = args.read_file.is_some();

    // ── Protocol selection ────────────────────────────────────────────────────
    // When replaying a file, default to All rather than prompting interactively
    // (the user typically just wants to analyse everything in the capture).
    let selected_protocols = match args.protocols {
        Some(p) => p,
        None if is_offline => vec![protocols::ProtocolChoice::All],
        None => cli::prompt_protocol_selection(),
    };
    let protocol_names = cli::selected_protocol_names(&selected_protocols);
    let bpf_filter = cli::build_bpf_filter(&selected_protocols);
    let expanded_protocols: Vec<protocols::ProtocolChoice> = selected_protocols.iter()
        .flat_map(|c| c.includes())
        .collect();
    let mut logger = create_logger(&protocol_names).expect("Unable to create log file");

    let proto_display = cli::selected_protocol_display(&selected_protocols);
    let extras = cli::selected_extras_display(&expanded_protocols);

    if let Some(ref path) = args.read_file {
        // ── Offline replay mode ───────────────────────────────────────────────
        let mut cap = Capture::from_file(path)
            .unwrap_or_else(|e| {
                eprintln!("❌ Cannot open '{}': {}", path, e);
                std::process::exit(1);
            });
        if let Err(e) = cap.filter(&bpf_filter, true) {
            eprintln!("❌ BPF filter error: {}", e);
            std::process::exit(1);
        }

        let banner = if proto_display == "all protocols" {
            format!("📁 Replaying {}  —  all protocols", path)
        } else {
            format!("📁 Replaying {}  —  {}{}", path, proto_display, extras)
        };
        println!("{}", banner);
        logger.log(&banner);
        println!("🔍 BPF filter: {}", bpf_filter);
        logger.log(&format!("BPF filter: {}", bpf_filter));

        let mut state = CaptureState::new();
        run_loop(&mut cap, &mut state, None,
                 &expanded_protocols, quiet, &mut logger);
    } else {
        // ── Live capture mode ─────────────────────────────────────────────────
        let device = match args.interface {
            Some(ref name) => cli::resolve_interface_by_name(name),
            None           => cli::select_interface(),
        };
        let banner = if proto_display == "all protocols" {
            format!("📡 Listening on {}  —  all protocols", device.name)
        } else {
            format!("📡 Listening on {}  for {}{}  streams", device.name, proto_display, extras)
        };
        println!("{}", banner);
        logger.log(&banner);
        println!("🔍 BPF filter: {}", bpf_filter);
        logger.log(&format!("BPF filter: {}", bpf_filter));

        let iface_ip = device.addresses.iter()
            .find_map(|a| if let std::net::IpAddr::V4(v4) = a.addr { Some(v4) } else { None })
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        let mut mc_sockets = join_multicast_groups(iface_ip, &expanded_protocols, &mut logger);
        let mut mc_joined: HashSet<Ipv4Addr> = HashSet::new();

        #[cfg(unix)]
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("❌  Packet capture requires elevated privileges.");
            eprintln!("    → Re-run with: sudo {}", std::env::args().next().unwrap_or_default());
            std::process::exit(1);
        }

        let mut cap = Capture::from_device(device.name.as_str())
            .unwrap_or_else(|e| {
                eprintln!("❌  Cannot find capture device '{}': {}", device.name, e);
                std::process::exit(1);
            })
            .promisc(true)
            .immediate_mode(true)
            .timeout(1000)
            .open()
            .unwrap_or_else(|e| {
                eprintln!("❌  Cannot open capture device '{}': {}", device.name, e);
                eprintln!("    → Run as root/sudo (Linux/macOS) or as Administrator (Windows).");
                eprintln!("    → On Windows, ensure Npcap is installed: https://npcap.com");
                std::process::exit(1);
            });
        if let Err(e) = cap.filter(&bpf_filter, true) {
            eprintln!("❌  BPF filter error: {}", e);
            std::process::exit(1);
        }

        send_mdns_startup_probe(iface_ip, &expanded_protocols, &mut logger);

        let mut state = CaptureState::new();
        state.local_ips = device.addresses.iter()
            .filter_map(|a| if let std::net::IpAddr::V4(v4) = a.addr { Some(v4) } else { None })
            .collect();
        run_loop(&mut cap, &mut state, Some(LiveConfig {
                     iface_ip, duration_secs,
                     mc_sockets: &mut mc_sockets, mc_joined: &mut mc_joined,
                 }), &expanded_protocols, quiet, &mut logger);
    }
}

/// Parameters used only in live-capture mode. Passed as `None` for offline replay.
struct LiveConfig<'a> {
    iface_ip:      Ipv4Addr,
    duration_secs: Option<u64>,
    mc_sockets:    &'a mut Vec<UdpSocket>,
    mc_joined:     &'a mut HashSet<Ipv4Addr>,
}

/// Unified capture loop for live (`Capture<Active>`) and offline (`Capture<Offline>`).
///
/// Live mode:   5s wall-clock timer drives reports; `TimeoutExpired` continues;
///              dynamic IGMP joins; pcap drop stats shown.
/// Offline mode: pcap timestamps drive 5s report windows; `NoMorePackets` prints
///              a final report and exits; IGMP joins skipped (meaningless offline).
fn run_loop<T: Activated>(
    cap: &mut Capture<T>,
    state: &mut CaptureState,
    mut live: Option<LiveConfig<'_>>,
    expanded_protocols: &[protocols::ProtocolChoice],
    quiet: bool,
    logger: &mut crate::report::Logger,
) {
    let is_offline = live.is_none();
    let mut last_report      = Instant::now();
    let mut last_report_pcap = 0i64;   // pcap seconds; initialised on first packet
    let mut pcap_ts_init     = false;
    let run_start            = Instant::now();
    // Session-lifetime report config: `quiet` is fixed; `no_flows_diagnostic_shown`
    // latches after the no-active-flows diagnostic first appears.
    let mut session = ReportSession { quiet, no_flows_diagnostic_shown: false };

    loop {
        // ── Live: report at TOP so it fires even when next_packet() times out ─
        if !is_offline && last_report.elapsed() > Duration::from_secs(5) {
            let pcap_stats = cap.stats().ok().map(|s| (s.received, s.dropped, s.if_dropped));
            emit_periodic_alerts(state, is_offline, logger);
            do_report(state, expanded_protocols, pcap_stats, &mut session, logger);
            last_report = Instant::now();

            if let Some(secs) = live.as_ref().and_then(|l| l.duration_secs)
                && run_start.elapsed().as_secs() >= secs
            {
                let healthy = state.network_health.network_score >= 100.0;
                std::process::exit(if healthy { 0 } else { 1 });
            }
        }

        let packet = match cap.next_packet() {
            Ok(p)  => p,
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(pcap::Error::NoMorePackets)  => {
                // EOF — print whatever accumulated in the last partial window.
                emit_periodic_alerts(state, is_offline, logger);
                do_report(state, expanded_protocols, None, &mut session, logger);
                let healthy = state.network_health.network_score >= 100.0;
                std::process::exit(if healthy { 0 } else { 1 });
            }
            Err(e) => {
                let msg = format!("❌ Capture error: {} — exiting", e);
                if color_enabled() { eprintln!("\x1b[31m{}\x1b[0m", msg); } else { eprintln!("{}", msg); }
                logger.log(&msg);
                std::process::exit(1);
            }
        };

        // Extract pcap timestamp before borrowing packet.data.
        let pkt_ts = packet.header.ts.tv_sec as i64;

        let eth = match EthernetPacket::new(packet.data) { Some(e) => e, _ => continue };
        let now = Instant::now();
        let (l2_et, l2_payload) = unwrap_vlan(&eth).unwrap_or((0, &[][..]));
        let frame_bytes = eth.packet().len() as u64;

        state.packets_dispatched += 1;
        // Reuse the VLAN unwrap above instead of letting detect_protocol walk the
        // tag stack a second time on every packet.
        if let Some(proto) = detect_protocol_unwrapped(&eth, l2_et, l2_payload)
            && proto.is_selected(expanded_protocols)
        {
            capture::dispatch(state, proto, l2_payload, frame_bytes, now, logger);
        }

        // ── Dynamic IGMP joins (live only) ───────────────────────────────────
        if let Some(ref mut lc) = live {
            for group in state.pending_join_groups.drain(..) {
                if should_join_group(&group, expanded_protocols) && !lc.mc_joined.contains(&group) {
                    match UdpSocket::bind("0.0.0.0:0")
                        .and_then(|s| { s.join_multicast_v4(&group, &lc.iface_ip)?; Ok(s) })
                    {
                        Ok(s) => {
                            lc.mc_joined.insert(group);
                            state.joined_multicast.insert(group);
                            lc.mc_sockets.push(s);
                            logger.log(&format!("   ✓ Joined stream multicast {}", group));
                        }
                        Err(e) => {
                            logger.log(&format!("   ⚠ Could not join {} — {}", group, e));
                        }
                    }
                }
            }
        } else {
            state.pending_join_groups.clear();
        }

        // ── IPv4 parse for multicast/unicast health tracking ─────────────────
        let outer_ip = if l2_et == 0x0800 {
            pnet_packet::ipv4::Ipv4Packet::new(l2_payload)
        } else {
            None
        };

        // ── Network health tracking ───────────────────────────────────────────
        state.network_health.total_packets += 1;
        state.bytes_this_window += frame_bytes;
        if let Some(ref ip) = outer_ip {
            if is_multicast(ip.get_destination()) {
                state.network_health.multicast_packets += 1;
                state.multicast_bytes_this_window += frame_bytes;
            } else {
                state.network_health.unicast_packets += 1;
            }
        }

        // ── Offline: report based on pcap timestamp ───────────────────────────
        // eth/outer_ip are no longer used past this point — NLL ends their borrows
        // of packet.data before we access pkt_ts (which was copied earlier).
        if is_offline {
            if !pcap_ts_init {
                last_report_pcap = pkt_ts;
                pcap_ts_init = true;
            } else if pkt_ts - last_report_pcap >= 5 {
                emit_periodic_alerts(state, is_offline, logger);
                do_report(state, expanded_protocols, None, &mut session, logger);
                last_report_pcap = pkt_ts;
            }
        }
    }
}

/// Periodic check helpers called before every report cycle.
/// The four Discovered/Clock Sources diagnostics are computed in do_report and
/// rendered inline in print_report instead of emitted here as free-standing output.
fn emit_periodic_alerts(state: &mut CaptureState, is_offline: bool, logger: &mut crate::report::Logger) {
    capture::emit(&state.ptp.check_ptp_timeouts(),    logger);
    capture::emit(&state.check_stream_count_anomaly(), logger);
    capture::emit(&state.check_igmp_query_interval(),      logger);
    let has_active_multicast = state.has_active_multicast();
    capture::emit(&state.igmp.check_multiple_queriers(&mut state.network_health, has_active_multicast), logger);
    capture::emit(&state.igmp.check_version_mismatch(),    logger);
    capture::emit(&state.check_filter_unregistered_multicast(), logger);
    capture::emit(&state.check_high_multicast_bandwidth(), logger);
    capture::emit(&state.check_igmp_snooping_blocking_ptp(is_offline), logger);
    capture::emit(&ts_refclk_alerts(state),           logger);
    state.aggregate_ndi_bitrate();
}

/// Score, render, and reset a 5s report window.
fn do_report(
    state: &mut CaptureState,
    expanded_protocols: &[protocols::ProtocolChoice],
    pcap_stats: Option<(u32, u32, u32)>,
    session: &mut ReportSession,
    logger: &mut crate::report::Logger,
) {
    // Compute the four section-level diagnostics before borrowing state fields.
    let ip_config_alerts     = state.dante.check_ip_config();
    let conmon_bridge_alerts = state.dante.check_conmon_bridge();
    let follower_census_alerts = state.dante.check_follower_census(&state.ptp);
    let ptp_sync_alerts      = state.ptp.check_ptp_sync_conflict();
    let dante_unverified     = state.dante.unverified();

    state.network_health.calculate_score(
        &state.streams, &state.tcp_streams, &state.ptp.domains,
        &state.avb.msrp_state, &state.eee_ports,
    );
    let missing_ptp = state.missing_ptp_clocks(expanded_protocols);

    // Gather everything this Window needs behind one borrow. Built here (not in
    // print_report) so the score and missing-clock computations above — which
    // need &mut access to network_health and the expanded protocol list — finish
    // before the immutable snapshot borrows take hold.
    let snap = ReportSnapshot {
        streams: &state.streams,
        tcp_streams: &state.tcp_streams,
        ptp_domains: &state.ptp.domains,
        missing_ptp: &missing_ptp,
        health: &state.network_health,
        bytes_this_window: state.bytes_this_window,
        avtp_streams: &state.avb.avtp_streams,
        msrp_state: &state.avb.msrp_state,
        mvrp_vlans: &state.avb.mvrp_vlans,
        eee_ports: &state.eee_ports,
        dante_sources: &state.dante.sources,
        dante_names: &state.dante.names,
        dante_conmon: &state.dante.conmon,
        dante_unverified: &dante_unverified,
        ndi_sources: &state.ndi.sources,
        ndi_names: &state.ndi.names,
        avdecc_entities: &state.avb.avdecc_entities,
        pause_frames: state.pause_frames_this_window,
        pfc_frames: state.pfc_frames_this_window,
        pcap_stats,
        packets_dispatched: state.packets_dispatched,
        ip_config_alerts: &ip_config_alerts,
        conmon_bridge_alerts: &conmon_bridge_alerts,
        follower_census_alerts: &follower_census_alerts,
        ptp_sync_alerts: &ptp_sync_alerts,
    };
    print_report(&snap, session, logger);
    state.reset_window();
}

/// Send mDNS PTR queries for Dante (and optionally NDI) service types at startup.
/// Devices respond to 224.0.0.251:5353, which pcap is already capturing — so
/// responses land in the first few loop iterations and names appear in cycle 1.
fn send_mdns_startup_probe(iface_ip: Ipv4Addr, expanded: &[protocols::ProtocolChoice], logger: &mut crate::report::Logger) {
    let dante = expanded.iter().any(|c| matches!(c, protocols::ProtocolChoice::Dante));
    let ndi   = expanded.iter().any(|c| matches!(c, protocols::ProtocolChoice::NDI));
    if !dante && !ndi { return; }

    let mut services: Vec<&str> = Vec::new();
    if dante {
        services.extend_from_slice(&["_netaudio-arc._udp.local", "_netaudio-cmc._udp.local", "_netaudio._udp.local"]);
    }
    if ndi {
        services.push("_ndi._tcp.local");
    }

    let mut packet: Vec<u8> = Vec::new();
    packet.extend_from_slice(&[0x00, 0x00]); // transaction ID (0 = mDNS)
    packet.extend_from_slice(&[0x00, 0x00]); // flags: standard query
    packet.extend_from_slice(&(services.len() as u16).to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR = 0

    for service in &services {
        for label in service.split('.') {
            if !label.is_empty() {
                packet.push(label.len() as u8);
                packet.extend_from_slice(label.as_bytes());
            }
        }
        packet.push(0); // root label
        packet.extend_from_slice(&[0x00, 0x0C]); // QTYPE = PTR (12)
        packet.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    }

    // Bind to the interface IP so the multicast send goes out the right interface.
    let bind_addr = format!("{}:0", iface_ip);
    match UdpSocket::bind(&bind_addr).or_else(|_| UdpSocket::bind("0.0.0.0:0")) {
        Ok(sock) => {
            let _ = sock.set_multicast_ttl_v4(255);
            let dest = std::net::SocketAddr::from(([224, 0, 0, 251], 5353u16));
            match sock.send_to(&packet, dest) {
                Ok(_) => {
                    let msg = format!("   → mDNS probe sent ({})", services.join(", "));
                    logger.log(&msg);
                    println!("{}", msg);
                }
                Err(e) => logger.log(&format!("   ⚠ mDNS probe send failed: {}", e)),
            }
        }
        Err(e) => logger.log(&format!("   ⚠ mDNS probe socket failed: {}", e)),
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
            let entry = state.ptp.domains.get(&(claimed_domain, protocols::PTP_VERSION_V2))
                .or_else(|| state.ptp.domains.get(&(claimed_domain, protocols::PTP_VERSION_V1)));
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

