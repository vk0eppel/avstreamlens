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
    let needs_ptp = expanded.iter().any(|c| c.needs_ptp());
    let needs_sap = expanded.iter().any(|c| c.needs_sap());

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

/// Offline replay's report-timing decision: a report fires every 5 seconds of
/// *pcap* time (the packet's own timestamp), not wall-clock time — extracted out
/// of `run_loop` so the decision is testable without a real pcap capture. Live
/// capture's report timing stays a plain wall-clock check in `run_loop` (it has
/// no per-packet state to extract).
#[derive(Default)]
struct OfflineReportClock {
    last_report_pcap: i64,
    initialized: bool,
}

impl OfflineReportClock {
    /// `true` exactly when at least 5 seconds of pcap time have elapsed since the
    /// last report (or since the first packet, for the first window). Rebases
    /// its baseline every time it returns `true`.
    fn should_report(&mut self, pkt_ts: i64) -> bool {
        if !self.initialized {
            self.last_report_pcap = pkt_ts;
            self.initialized = true;
            return false;
        }
        if pkt_ts - self.last_report_pcap >= 5 {
            self.last_report_pcap = pkt_ts;
            return true;
        }
        false
    }
}

/// Per-packet dispatch + network-health tracking — takes an already-parsed
/// `EthernetPacket`, never a raw `pcap::Packet` or `Capture<T>`, so it's testable
/// with hand-built frames the same way `capture.rs`'s `handle_*` methods are.
/// Excludes the join-drain (see `drain_pending_joins`) and report-timing
/// decisions, which are `run_loop`'s own per-cycle concerns, not per-packet ones.
fn process_packet(
    state: &mut CaptureState,
    eth: &EthernetPacket,
    expanded_protocols: &[protocols::ProtocolChoice],
    now: Instant,
    logger: &mut crate::report::Logger,
) {
    let (l2_et, l2_pcp, l2_payload) = unwrap_vlan(eth).unwrap_or((0, None, &[][..]));
    let frame_bytes = eth.packet().len() as u64;

    state.packets_dispatched += 1;
    // Reuse the VLAN unwrap above instead of letting detect_protocol walk the
    // tag stack a second time on every packet.
    if let Some(proto) = detect_protocol_unwrapped(eth, l2_et, l2_payload)
        && proto.is_selected(expanded_protocols)
    {
        capture::dispatch(state, proto, l2_payload, l2_pcp, frame_bytes, now, logger);
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
}

/// Drain `state.pending_join_groups`, joining any newly-learned stream
/// multicast group on the live capture interface. A no-op (beyond clearing the
/// queue) in offline replay, where joining a group is meaningless — there is no
/// live interface to join on. Takes `Option<&mut LiveConfig>` rather than the
/// pcap `Capture<T>` itself, so it only depends on the socket/group bookkeeping.
fn drain_pending_joins(
    state: &mut CaptureState,
    live: Option<&mut LiveConfig<'_>>,
    expanded_protocols: &[protocols::ProtocolChoice],
    logger: &mut crate::report::Logger,
) {
    if let Some(lc) = live {
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
    let mut offline_clock    = OfflineReportClock::default();
    let run_start            = Instant::now();
    // Session-lifetime report config: `quiet` is fixed; `no_flows_diagnostic_shown`
    // latches after the no-active-flows diagnostic first appears.
    let mut session = ReportSession { quiet, no_flows_diagnostic_shown: false };

    loop {
        // ── Live: report at TOP so it fires even when next_packet() times out ─
        if !is_offline && last_report.elapsed() > Duration::from_secs(5) {
            let pcap_stats = cap.stats().ok().map(|s| (s.received, s.dropped, s.if_dropped));
            do_report(state, expanded_protocols, is_offline, pcap_stats, &mut session, logger);
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
                do_report(state, expanded_protocols, is_offline, None, &mut session, logger);
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
        process_packet(state, &eth, expanded_protocols, Instant::now(), logger);
        drain_pending_joins(state, live.as_mut(), expanded_protocols, logger);

        // ── Offline: report based on pcap timestamp ───────────────────────────
        // eth/outer_ip are no longer used past this point — NLL ends their borrows
        // of packet.data before we access pkt_ts (which was copied earlier).
        if is_offline && offline_clock.should_report(pkt_ts) {
            do_report(state, expanded_protocols, is_offline, None, &mut session, logger);
        }
    }
}

/// Score, render, and reset a 5s report window. `CaptureState::end_of_window`
/// owns the ordering invariant (every check before `reset_window`) — this
/// function's job is just to emit what it returns and build the snapshot.
/// `ts_refclk_alerts` is computed here rather than inside `end_of_window`
/// because it needs `&CaptureState` immutably while `end_of_window` needs
/// `&mut self` throughout; it must run before `end_of_window` so the streams/
/// domains it reads haven't been pruned yet.
fn do_report(
    state: &mut CaptureState,
    expanded_protocols: &[protocols::ProtocolChoice],
    is_offline: bool,
    pcap_stats: Option<(u32, u32, u32)>,
    session: &mut ReportSession,
    logger: &mut crate::report::Logger,
) {
    let ts_refclk = ts_refclk_alerts(state);
    let checks = state.end_of_window(expanded_protocols, is_offline);

    if let Some(ref combined) = checks.clock_dropout_alert {
        capture::emit(std::slice::from_ref(combined), logger);
    } else {
        capture::emit(&checks.clock_alerts, logger);
    }
    capture::emit(&checks.stream_count_alerts, logger);
    capture::emit(&checks.igmp_query_interval_alerts, logger);
    capture::emit(&checks.multiple_queriers_alerts, logger);
    capture::emit(&checks.version_mismatch_alerts, logger);
    capture::emit(&checks.filter_unregistered_alerts, logger);
    capture::emit(&checks.high_bandwidth_alerts, logger);
    capture::emit(&checks.igmp_snooping_ptp_alerts, logger);
    capture::emit(&ts_refclk, logger);

    // `end_of_window`'s `&mut self` borrow (which needed the expanded protocol
    // list and computed the score) has already finished, so `state` and `checks`
    // can both be borrowed immutably here.
    let snap = ReportSnapshot::from_state(state, &checks, pcap_stats);
    print_report(&snap, session, logger);
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── OfflineReportClock — offline replay's per-packet report-timing decision,
    // extracted out of run_loop so it's testable without a real pcap capture ──

    #[test]
    fn offline_clock_does_not_report_on_first_packet() {
        // The first packet only initialises the baseline timestamp — it must not
        // itself trigger a report (there is no elapsed window yet).
        let mut clock = OfflineReportClock::default();
        assert!(!clock.should_report(1_000));
    }

    #[test]
    fn offline_clock_reports_after_five_seconds_of_pcap_time() {
        let mut clock = OfflineReportClock::default();
        assert!(!clock.should_report(1_000)); // baseline
        assert!(!clock.should_report(1_003)); // 3s elapsed — not yet
        assert!(clock.should_report(1_005));  // 5s elapsed — report
    }

    #[test]
    fn offline_clock_rebases_after_reporting() {
        let mut clock = OfflineReportClock::default();
        clock.should_report(1_000);
        assert!(clock.should_report(1_005), "first 5s window");
        assert!(!clock.should_report(1_007), "only 2s since the last report");
        assert!(clock.should_report(1_010), "another full 5s window");
    }

    // ── process_packet — dispatch + network-health tracking, pcap-free ────────

    /// Build a raw Ethernet+IPv4+UDP+RTP frame (AES67 shape: dst 239.69.0.1:5004).
    fn eth_aes67_frame() -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
        let mut ip = vec![0u8; 20 + 8 + 12];
        ip[0] = 0x45;
        let total: u16 = (20 + 8 + 12) as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip[8] = 64;
        ip[9] = 0x11; // UDP
        ip[12..16].copy_from_slice(&[192, 168, 1, 10]); // src (unicast)
        ip[16..20].copy_from_slice(&[239, 69, 0, 1]);   // dst (AES67 multicast)
        // Port 6004, not 5004: both-ports-even-5000-6000 is Dante's strict audio
        // heuristic (parser.rs::is_likely_dante_audio) — it runs before the AES67
        // IP-block check and would steal this frame (see parser.rs's
        // dante_port_heuristic_wins_over_aes67_multicast_address regression test).
        ip[20..22].copy_from_slice(&6004u16.to_be_bytes());
        ip[22..24].copy_from_slice(&6004u16.to_be_bytes());
        ip[24..26].copy_from_slice(&20u16.to_be_bytes());
        ip[28] = 0x80; // RTP V=2
        ip[29] = 96;   // PT 96
        f.extend_from_slice(&ip);
        f
    }

    #[test]
    fn process_packet_dispatches_and_creates_a_stream() {
        let mut state = CaptureState::new();
        let mut logger = crate::report::Logger::for_test();
        let frame = eth_aes67_frame();
        let eth = EthernetPacket::new(&frame).unwrap();
        let expanded = vec![protocols::ProtocolChoice::AES67];

        process_packet(&mut state, &eth, &expanded, Instant::now(), &mut logger);

        assert_eq!(state.packets_dispatched, 1);
        assert!(state.streams.values().any(|s| s.protocol == "AES67"),
            "an AES67 RTP frame must create a stream");
    }

    #[test]
    fn process_packet_counts_multicast_bandwidth() {
        let mut state = CaptureState::new();
        let mut logger = crate::report::Logger::for_test();
        let frame = eth_aes67_frame();
        let eth = EthernetPacket::new(&frame).unwrap();
        let expanded = vec![protocols::ProtocolChoice::AES67];

        process_packet(&mut state, &eth, &expanded, Instant::now(), &mut logger);

        assert_eq!(state.network_health.total_packets, 1);
        assert_eq!(state.network_health.multicast_packets, 1);
        assert_eq!(state.network_health.unicast_packets, 0);
        assert!(state.bytes_this_window > 0);
        assert!(state.multicast_bytes_this_window > 0);
    }

    #[test]
    fn process_packet_does_not_dispatch_unselected_protocol() {
        // AES67 frame, but only Dante is selected — must not create a stream.
        let mut state = CaptureState::new();
        let mut logger = crate::report::Logger::for_test();
        let frame = eth_aes67_frame();
        let eth = EthernetPacket::new(&frame).unwrap();
        let expanded = vec![protocols::ProtocolChoice::Dante];

        process_packet(&mut state, &eth, &expanded, Instant::now(), &mut logger);

        assert!(state.streams.is_empty());
        assert_eq!(state.packets_dispatched, 1, "dispatched counter still increments");
    }

    // ── drain_pending_joins — dynamic IGMP join bootstrap, pcap-free ──────────

    #[test]
    fn drain_pending_joins_offline_clears_queue_without_joining() {
        // Joining a multicast group is meaningless in offline replay — there is
        // no live interface. `live: None` must still drain the queue so it
        // doesn't grow unbounded across packets.
        let mut state = CaptureState::new();
        let mut logger = crate::report::Logger::for_test();
        state.pending_join_groups.push(Ipv4Addr::new(239, 255, 0, 1));
        let expanded = vec![protocols::ProtocolChoice::Dante];

        drain_pending_joins(&mut state, None, &expanded, &mut logger);

        assert!(state.pending_join_groups.is_empty());
        assert!(state.joined_multicast.is_empty());
    }

    #[test]
    fn drain_pending_joins_live_joins_group_matching_selected_protocol() {
        let mut state = CaptureState::new();
        let mut logger = crate::report::Logger::for_test();
        let group = Ipv4Addr::new(239, 255, 0, 1); // octet[1]=255 → gated on Dante
        state.pending_join_groups.push(group);
        let expanded = vec![protocols::ProtocolChoice::Dante];

        let mut mc_sockets = Vec::new();
        let mut mc_joined = HashSet::new();
        let mut live = LiveConfig {
            iface_ip: Ipv4Addr::new(127, 0, 0, 1),
            duration_secs: None,
            mc_sockets: &mut mc_sockets,
            mc_joined: &mut mc_joined,
        };

        drain_pending_joins(&mut state, Some(&mut live), &expanded, &mut logger);

        assert!(state.pending_join_groups.is_empty());
        assert!(mc_joined.contains(&group), "group matching the selection must be joined");
        assert!(state.joined_multicast.contains(&group));
        assert_eq!(mc_sockets.len(), 1);
    }

    #[test]
    fn drain_pending_joins_skips_group_not_matching_selected_protocol() {
        // octet[1]=69 is AES67's block, but only Dante is selected.
        let mut state = CaptureState::new();
        let mut logger = crate::report::Logger::for_test();
        let group = Ipv4Addr::new(239, 69, 0, 1);
        state.pending_join_groups.push(group);
        let expanded = vec![protocols::ProtocolChoice::Dante];

        let mut mc_sockets = Vec::new();
        let mut mc_joined = HashSet::new();
        let mut live = LiveConfig {
            iface_ip: Ipv4Addr::new(127, 0, 0, 1),
            duration_secs: None,
            mc_sockets: &mut mc_sockets,
            mc_joined: &mut mc_joined,
        };

        drain_pending_joins(&mut state, Some(&mut live), &expanded, &mut logger);

        assert!(mc_joined.is_empty(), "AES67 group must not be joined when only Dante is selected");
        assert!(state.joined_multicast.is_empty());
        assert!(mc_sockets.is_empty());
    }

    // ── ts_refclk_alerts — SDP-claimed vs. wire PTP grandmaster cross-check ──

    fn sdp_with_ts_refclk(port: u16, ts_refclk: &str) -> crate::protocols::SdpSession {
        crate::protocols::SdpSession {
            session_id: "1".to_string(),
            session_name: "Test Mix".to_string(),
            info: String::new(),
            media: vec![crate::protocols::SdpMedia {
                media_type: "audio".to_string(),
                port,
                payload_types: vec![96],
                connection: String::new(),
                rtpmap: "L24/48000/2".to_string(),
                clock_hz: 48_000.0,
                channels: 2,
                ptime_ms: 1.0,
                ts_refclk: ts_refclk.to_string(),
                mediaclk: String::new(),
            }],
        }
    }

    fn active_aes67_stream(port: u16) -> crate::stats::StreamStats {
        let mut s = crate::stats::StreamStats::new_with_info(
            "AES67", 48_000.0, true, Ipv4Addr::new(239, 69, 0, 1), port);
        s.packets = 10;
        s
    }

    #[test]
    fn ts_refclk_alerts_warns_when_claimed_domain_has_no_ptp_traffic() {
        let mut state = CaptureState::new();
        state.streams.insert("s1".into(), active_aes67_stream(5004));
        state.sdp_cache.insert("1".into(),
            sdp_with_ts_refclk(5004, "ptp=IEEE1588-2008:00-1a-e5-ff-fe-12-34-56:0"));
        // No entry in state.ptp.domains for domain 0 at all.

        let alerts = ts_refclk_alerts(&state);

        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].message.contains("no PTP traffic detected"), "got {}", alerts[0].message);
    }

    #[test]
    fn ts_refclk_alerts_silent_when_active_grandmaster_matches_claim() {
        let mut state = CaptureState::new();
        state.streams.insert("s1".into(), active_aes67_stream(5004));
        state.sdp_cache.insert("1".into(),
            sdp_with_ts_refclk(5004, "ptp=IEEE1588-2008:00-1a-e5-ff-fe-12-34-56:0"));

        let mut ptp = crate::stats::PtpStats::new(0, protocols::PTP_VERSION_V2);
        ptp.clock_valid = true;
        ptp.last_grandmaster = Some("00:1a:e5:ff:fe:12:34:56".to_string());
        state.ptp.domains.insert((0, protocols::PTP_VERSION_V2), ptp);

        let alerts = ts_refclk_alerts(&state);

        assert!(alerts.is_empty(), "matching grandmaster must not alert, got {:?}",
            alerts.iter().map(|a| &a.message).collect::<Vec<_>>());
    }

    #[test]
    fn ts_refclk_alerts_warns_on_grandmaster_mismatch() {
        let mut state = CaptureState::new();
        state.streams.insert("s1".into(), active_aes67_stream(5004));
        state.sdp_cache.insert("1".into(),
            sdp_with_ts_refclk(5004, "ptp=IEEE1588-2008:00-1a-e5-ff-fe-12-34-56:0"));

        let mut ptp = crate::stats::PtpStats::new(0, protocols::PTP_VERSION_V2);
        ptp.clock_valid = true;
        ptp.last_grandmaster = Some("aa:bb:cc:dd:ee:ff:00:11".to_string());
        state.ptp.domains.insert((0, protocols::PTP_VERSION_V2), ptp);

        let alerts = ts_refclk_alerts(&state);

        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].message.contains("grandmaster mismatch"), "got {}", alerts[0].message);
    }

    #[test]
    fn ts_refclk_alerts_silent_when_session_not_active() {
        // No stream references this SDP's port at all — session_active is false,
        // so the ts-refclk cross-check must not fire even with a domain mismatch.
        let mut state = CaptureState::new();
        state.sdp_cache.insert("1".into(),
            sdp_with_ts_refclk(5004, "ptp=IEEE1588-2008:00-1a-e5-ff-fe-12-34-56:0"));

        let alerts = ts_refclk_alerts(&state);

        assert!(alerts.is_empty());
    }
}

