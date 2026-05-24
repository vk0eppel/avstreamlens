// AVStreamLens — src/capture.rs
//
// Per-loop capture state and per-protocol handlers. The capture loop in main.rs
// is a thin driver that calls `dispatch()` on each parsed packet; handlers
// mutate state and return typed alerts that the dispatch layer formats and
// emits via the Logger.
//
// Design notes:
// - Handlers do not touch IO. They return Vec<Alert>; emission lives in dispatch.
// - Handlers take already-parsed inputs (l2_payload: &[u8], frame_bytes, etc.)
//   so they are unit-testable with hand-built byte slices — no pcap dependency.
// - All per-loop HashMaps live on CaptureState; report.rs reads them by reference.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet_packet::Packet;

use crate::parser::{is_aes67_multicast, is_st2110_multicast, parse_rtp};
use crate::protocols::{
    AvProtocol, DanteKind, FlowControlKind, IgmpType, MsrpDeclType, MsrpDeclaration, NdiKind,
    ProtocolChoice, PtpInfo, SdpSession, St2110Type, DEFAULT_CLOCK_HZ, PTP_VERSION_V2,
    STREAM_TIMEOUT_SECS, avtp_subtype_name,
};
use crate::report::Logger;
use crate::stats::{
    AvtpStreamStats, NetworkHealth, PtpEvent, PtpStats, StreamQuality, StreamStats,
    TcpStreamStats,
};

// IGMP Join dedup entries are pruned after this many seconds without re-seeing
// the join. Well above the IGMPv2 default query interval (125s).
const IGMP_JOIN_DEDUP_TTL_SECS: u64 = 300;

// Streams (RTP/AVTP/TCP) are pruned after this many seconds of silence.
// `STREAM_TIMEOUT_SECS` is the report-time "dead stream" threshold; pruning
// waits longer so an alert is shown at least once before the entry disappears.
const STREAM_PRUNE_SECS: u64 = STREAM_TIMEOUT_SECS * 2;

/// Severity of an alert emitted by a handler. The dispatch layer maps each
/// variant to an ANSI color and logs the plain text.
#[derive(Debug, Clone, PartialEq)]
pub enum AlertLevel {
    /// Plain informational line — discovery events, IGMP Join/Leave, MVRP.
    Info,
    /// Positive state transition — grandmaster detected.
    Good,
    /// Warning — most protocol issues.
    Warn,
    /// Hard failure — clock lost, capture error.
    Error,
}

/// A single user-facing line produced by a handler.
#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    pub level: AlertLevel,
    pub message: String,
}

impl Alert {
    pub fn info(s: impl Into<String>)  -> Self { Self { level: AlertLevel::Info,  message: s.into() } }
    pub fn good(s: impl Into<String>)  -> Self { Self { level: AlertLevel::Good,  message: s.into() } }
    pub fn warn(s: impl Into<String>)  -> Self { Self { level: AlertLevel::Warn,  message: s.into() } }
    pub fn error(s: impl Into<String>) -> Self { Self { level: AlertLevel::Error, message: s.into() } }
}

/// All per-loop state owned by the capture loop. Handlers mutate fields here
/// and return alerts to the dispatch layer.
pub struct CaptureState {
    pub streams:        HashMap<String, StreamStats>,
    pub tcp_streams:    HashMap<String, TcpStreamStats>,
    pub sdp_cache:      HashMap<String, SdpSession>,
    // PTP stats keyed by (domain, version) — separates Dante PTPv1 from AES67/ST2110 PTPv2.
    pub ptp_domains:    HashMap<(u8, u8), PtpStats>,
    pub network_health: NetworkHealth,
    // NDI sender IPs learned from mDNS — used for IP-based stream detection.
    pub ndi_sources:    HashSet<Ipv4Addr>,
    pub ndi_names:      HashMap<Ipv4Addr, String>,
    pub dante_names:    HashMap<Ipv4Addr, String>,
    // Deduplicates IGMP Join console output — cleared on Leave so re-joins print again.
    pub igmp_joins_seen: HashMap<(Ipv4Addr, Ipv4Addr), Instant>,
    pub avtp_streams:   HashMap<[u8; 8], AvtpStreamStats>,
    pub msrp_state:     HashMap<[u8; 8], MsrpDeclaration>,
    pub mvrp_vlans:     HashSet<u16>,
    // EEE detection: (chassis_id, port_id) → (tx_wake_us, rx_wake_us)
    pub eee_ports:      HashMap<(String, String), (u16, u16)>,
    pub bytes_this_window: u64,
    // Link-layer flow-control counters (PAUSE / PFC, EtherType 0x8808).
    // Many NICs strip these at the MAC layer before pcap sees them; when
    // they do reach userspace, any non-zero count indicates upstream
    // congestion that has caused brief tx-side freezes.
    pub pause_frames_this_window: u64,
    pub pfc_frames_this_window:   u64,
}

impl Default for CaptureState {
    fn default() -> Self { Self::new() }
}

impl CaptureState {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            tcp_streams: HashMap::new(),
            sdp_cache: HashMap::new(),
            ptp_domains: HashMap::new(),
            network_health: NetworkHealth::new(),
            ndi_sources: HashSet::new(),
            ndi_names: HashMap::new(),
            dante_names: HashMap::new(),
            igmp_joins_seen: HashMap::new(),
            avtp_streams: HashMap::new(),
            msrp_state: HashMap::new(),
            mvrp_vlans: HashSet::new(),
            eee_ports: HashMap::new(),
            bytes_this_window: 0,
            pause_frames_this_window: 0,
            pfc_frames_this_window:   0,
        }
    }

    /// Reset per-5s-window counters and prune silent streams.
    /// Call after each report is printed.
    pub fn reset_window(&mut self) {
        self.bytes_this_window = 0;
        self.pause_frames_this_window = 0;
        self.pfc_frames_this_window   = 0;
        for s in self.streams.values_mut() {
            s.gap_events      = 0;
            s.max_iat_ms      = 0.0;
            s.pt_mismatches   = 0;
            s.dscp_violations = 0;
            s.ssrc_changes    = 0;
            s.lost_this_window               = 0;
            s.ts_discontinuities_this_window = 0;
            s.reorders_this_window           = 0;
        }
        self.streams.retain(|_, s| {
            s.last_packet_time
                .is_none_or(|t| t.elapsed().as_secs() < STREAM_PRUNE_SECS)
        });
        self.tcp_streams.retain(|_, s| {
            s.last_seen.elapsed().as_secs() < STREAM_PRUNE_SECS
                && !matches!(s.stream_quality, StreamQuality::Terminated)
        });
        self.avtp_streams.retain(|_, s| {
            s.last_seen.elapsed().as_secs() < STREAM_PRUNE_SECS
        });
        // Drop IGMP Join entries from hosts that vanished without sending a Leave.
        self.igmp_joins_seen.retain(|_, t| t.elapsed() < Duration::from_secs(IGMP_JOIN_DEDUP_TTL_SECS));
    }

    // ── Handlers ────────────────────────────────────────────────────────────

    /// SAP/SDP: cache the SDP and enrich any matching streams with metadata.
    pub fn handle_sap(&mut self, sdp: SdpSession) {
        for m in &sdp.media {
            for stats in self.streams.values_mut() {
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
        self.sdp_cache.insert(sdp.session_id.clone(), sdp);
    }

    /// PTP: update the (domain, version) entry, return Detected/Changed alert if any.
    pub fn handle_ptp(&mut self, info: PtpInfo) -> Vec<Alert> {
        let kind = info.protocol_kind.clone();
        let stats = self.ptp_domains
            .entry((info.domain, info.version))
            .or_insert_with(|| PtpStats::new(info.domain, info.version));
        let event = stats.update(&info, &kind);
        match event {
            Some(PtpEvent::GrandmasterDetected) => {
                let gm = stats.last_grandmaster.as_deref().unwrap_or("?");
                vec![Alert::good(format!(
                    "✓  GRANDMASTER DETECTED (Domain {} v{}): {}",
                    stats.domain, stats.version, gm
                ))]
            }
            Some(PtpEvent::GrandmasterChanged { from }) => {
                let gm = stats.last_grandmaster.as_deref().unwrap_or("?");
                vec![Alert::warn(format!(
                    "⚠️  GRANDMASTER CHANGED (Domain {} v{}): {} → {}",
                    stats.domain, stats.version, from, gm
                ))]
            }
            // update() never emits ClockLost — only check_timeout() does.
            Some(PtpEvent::ClockLost) | None => vec![],
        }
    }

    /// AES67 RTP audio.
    pub fn handle_aes67(&mut self, dst: Ipv4Addr, dst_port: u16, payload_type: u8, l2_payload: &[u8]) {
        let key = format!("AES67 {}:{}", dst, dst_port);
        let stats = self.streams.entry(key).or_insert_with(|| {
            let sdp_media = self.sdp_cache.values()
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
            if ip.get_ecn() == 3 { self.network_health.ecn_congestion_marks += 1; }
            if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) {
                if stats.expected_pt.is_some_and(|exp| payload_type != exp) {
                    stats.pt_mismatches += 1;
                }
                stats.update(seq, ts, ssrc, udp.payload().len());
            }
        }
    }

    /// ST 2110 video/audio/ancillary.
    pub fn handle_st2110(&mut self, dst: Ipv4Addr, dst_port: u16, stream_type: St2110Type, l2_payload: &[u8]) {
        let label = match stream_type {
            St2110Type::Video   => "2110-20",
            St2110Type::Audio   => "2110-30",
            St2110Type::Ancdata => "2110-40",
            St2110Type::Unknown => "2110-??",
        };
        let key = format!("ST {} {}:{}", label, dst, dst_port);
        let default_clock = if matches!(stream_type, St2110Type::Video) { 90_000.0 } else { DEFAULT_CLOCK_HZ };
        let stats = self.streams.entry(key).or_insert_with(|| {
            let sdp_media = self.sdp_cache.values()
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
            // ST2110-20 video always uses 90 kHz per spec — enable TS discontinuity
            // detection even without SDP. ST2110-30 audio: default 1 ms ptime.
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
            if ip.get_ecn() == 3 { self.network_health.ecn_congestion_marks += 1; }
            if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) {
                let rtp_pt = udp.payload()[1] & 0x7F;
                if stats.expected_pt.is_some_and(|exp| rtp_pt != exp) {
                    stats.pt_mismatches += 1;
                }
                stats.update(seq, ts, ssrc, udp.payload().len());
            }
        }
    }

    /// Dante: discovery, control (silent), or audio stream.
    pub fn handle_dante(&mut self, kind: DanteKind, src: Ipv4Addr, dst_port: u16, l2_payload: &[u8]) -> Vec<Alert> {
        match kind {
            DanteKind::Discovery { device_name } => {
                if let Some(ref name) = device_name {
                    self.dante_names.insert(src, name.clone());
                }
                let label = device_name.as_deref().unwrap_or("unknown device");
                vec![Alert::info(format!("🔍 Dante discovered: {}  \"{}\"", src, label))]
            }
            DanteKind::Control => vec![],
            DanteKind::AudioStream => {
                let key = format!("Dante {}:{}", src, dst_port);
                let stats = self.streams.entry(key).or_insert_with(|| {
                    let mut s = StreamStats::new("Dante", DEFAULT_CLOCK_HZ);
                    s.ptime_ms = 1.0; // Dante standard: 48 samples @ 48kHz = 1ms
                    s.sdp_name = self.dante_names.get(&src).cloned();
                    s
                });
                if let Some(ip) = pnet_packet::ipv4::Ipv4Packet::new(l2_payload)
                    && let Some(udp) = pnet_packet::udp::UdpPacket::new(ip.payload())
                {
                    // Dante audio requires DSCP EF (46)
                    if ip.get_dscp() != 46 { stats.dscp_violations += 1; }
                    if ip.get_ecn() == 3 { self.network_health.ecn_congestion_marks += 1; }
                    if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) {
                        stats.update(seq, ts, ssrc, udp.payload().len());
                    }
                }
                vec![]
            }
        }
    }

    /// NDI mDNS discovery — registers the source IP and emits a discovery line.
    pub fn handle_ndi_discovery(&mut self, src: Ipv4Addr, source_name: Option<String>) -> Vec<Alert> {
        self.ndi_sources.insert(src);
        if let Some(ref name) = source_name {
            self.ndi_names.insert(src, name.clone());
        }
        let label = source_name.as_deref().unwrap_or("unknown source");
        vec![Alert::info(format!("🔍 NDI source: {}  \"{}\"", src, label))]
    }

    /// AVB AVTP frame — updates the per-subtype aggregate stream and per-stream_id entry.
    pub fn handle_avb(&mut self, subtype: u8, stream_id: Option<[u8; 8]>, frame_bytes: u64, avtp_seq: Option<u8>, now: Instant) {
        let label = avtp_subtype_name(subtype);
        let stats = self.streams.entry(format!("AVB {}", label))
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
            let entry = self.avtp_streams.entry(sid)
                .or_insert_with(|| AvtpStreamStats::new(sid, subtype));
            entry.packets += 1;
            entry.last_seen = now;
            entry.update_bitrate(frame_bytes, now);
            if let Some(seq) = avtp_seq { entry.update_seq(seq); }
        }
    }

    /// MSRP declarations — records all, alerts only on TalkerFailed.
    pub fn handle_msrp(&mut self, declarations: Vec<MsrpDeclaration>) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for decl in declarations {
            if matches!(decl.decl_type, MsrpDeclType::TalkerFailed) {
                let code_str = match decl.failure_code {
                    Some(1) => " (insufficient bandwidth)",
                    Some(2) => " (insufficient bridge resources)",
                    Some(3) => " (insufficient bandwidth for Traffic Class)",
                    Some(_) => " (failure)",
                    None    => "",
                };
                let id = &decl.stream_id;
                alerts.push(Alert::warn(format!(
                    "⚠  MSRP Talker Failed: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:04x}{}",
                    id[0], id[1], id[2], id[3], id[4], id[5],
                    u16::from_be_bytes([id[6], id[7]]),
                    code_str
                )));
            }
            self.msrp_state.insert(decl.stream_id, decl);
        }
        alerts
    }

    /// MVRP — registers VLANs, emits one info line per newly-seen VLAN.
    pub fn handle_mvrp(&mut self, vlan_ids: Vec<u16>) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for vid in vlan_ids {
            if self.mvrp_vlans.insert(vid) {
                alerts.push(Alert::info(format!("🔖 MVRP: VLAN {} registered", vid)));
            }
        }
        alerts
    }

    /// LLDP EEE TLV — alerts only on first detection per port.
    pub fn handle_lldp_eee(&mut self, chassis_id: String, port_id: String, tx_wake_us: u16, rx_wake_us: u16) -> Vec<Alert> {
        let key = (chassis_id.clone(), port_id.clone());
        if self.eee_ports.insert(key, (tx_wake_us, rx_wake_us)).is_none() {
            vec![Alert::warn(format!(
                "⚠  EEE active on switch port \"{}\" (chassis {})  —  Tx wake: {}µs  Rx wake: {}µs  —  disable EEE for AV reliability",
                port_id, chassis_id, tx_wake_us, rx_wake_us
            ))]
        } else {
            vec![]
        }
    }

    /// IGMP: Join (deduped), Leave, Query (tracks interval), Unknown.
    pub fn handle_igmp(&mut self, src: Ipv4Addr, group: Ipv4Addr, igmp_type: IgmpType, now: Instant) -> Vec<Alert> {
        let mut alerts = Vec::new();
        match igmp_type {
            IgmpType::Join => {
                let first_time = !self.igmp_joins_seen.contains_key(&(src, group));
                self.igmp_joins_seen.insert((src, group), now);
                if first_time {
                    alerts.push(Alert::info(format!("➕ IGMP Join: {} → group {}", src, group)));
                }
            }
            IgmpType::Leave => {
                self.igmp_joins_seen.remove(&(src, group));
                alerts.push(Alert::info(format!("➖ IGMP Leave: {} → group {}", src, group)));
                if self.streams.values().any(|s| s.dst_ip == Some(group)) {
                    alerts.push(Alert::warn(format!("    ⚠  IGMP Leave on monitored group {}", group)));
                }
            }
            IgmpType::Query => {
                // Track interval between consecutive queries (RFC 3376 default 125s).
                if let Some(last) = self.network_health.last_igmp_query {
                    self.network_health.igmp_query_interval_secs = Some(last.elapsed().as_secs());
                }
                self.network_health.last_igmp_query = Some(now);
                alerts.push(Alert::info(format!("❓ IGMP Query: {} → group {}", src, group)));
            }
            IgmpType::Unknown(t) => {
                alerts.push(Alert::info(format!("❔ IGMP Unknown(0x{:02x}): {} → group {}", t, src, group)));
            }
        }
        alerts
    }

    /// Link-layer flow control (PAUSE or PFC). Just counts — alert text and
    /// score penalty live in the periodic report.
    pub fn handle_flow_control(&mut self, kind: FlowControlKind) {
        match kind {
            FlowControlKind::Pause                => self.pause_frames_this_window += 1,
            FlowControlKind::PriorityFlowControl  => self.pfc_frames_this_window   += 1,
        }
    }

    /// PTP clock-loss check, called from the periodic report cycle.
    /// Returns one ClockLost alert per domain that transitioned to LOST.
    pub fn check_ptp_timeouts(&mut self) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for stats in self.ptp_domains.values_mut() {
            if let Some(PtpEvent::ClockLost) = stats.check_timeout() {
                alerts.push(Alert::error(format!(
                    "❌ PTP Clock LOST (Domain {} v{}) [{}]",
                    stats.domain,
                    stats.version,
                    stats.protocol_kind.as_deref().unwrap_or("?")
                )));
            }
        }
        alerts
    }

    /// Version-aware PTP clock requirement check.
    ///
    /// A clock family is required only when (a) the user's selection allows it AND
    /// (b) at least one stream of that family has actually been observed. Without
    /// the "observed" gate, picking "All" on a pure-AES67 network would warn about
    /// missing gPTP just because AVB is in the expanded set.
    ///
    ///   AES67/ST2110 require PTPv2 (a PTPv1 clock is not sufficient)
    ///   Dante accepts PTPv1 or PTPv2
    ///   AVB requires L2 gPTP (`protocol_kind = "AVB"`)
    pub fn ptp_requirement_met(&self, expanded: &[ProtocolChoice]) -> bool {
        let needs_ptpv2 = expanded.iter().any(|c| matches!(c, ProtocolChoice::AES67 | ProtocolChoice::ST2110))
            && self.streams.values().any(|s| s.protocol == "AES67" || s.protocol.starts_with("2110-"));
        let needs_ptp_any = expanded.iter().any(|c| matches!(c, ProtocolChoice::Dante))
            && self.streams.values().any(|s| s.protocol == "Dante");
        let needs_gptp = expanded.iter().any(|c| matches!(c, ProtocolChoice::AVB))
            && !self.avtp_streams.is_empty();

        let has_ptpv2 = self.ptp_domains.values().any(|s|
            s.clock_valid && s.version == PTP_VERSION_V2
            && s.protocol_kind.as_deref() != Some("AVB"));
        let has_ptp = self.ptp_domains.values().any(|s| s.clock_valid);
        let has_gptp = self.ptp_domains.values().any(|s|
            s.clock_valid && s.protocol_kind.as_deref() == Some("AVB"));

        (!needs_ptpv2 || has_ptpv2)
        && (!needs_ptp_any || has_ptp)
        && (!needs_gptp || has_gptp)
    }

    /// Re-compute NDI per-stream bitrate by summing matching TCP flows.
    /// Called once per report cycle.
    pub fn aggregate_ndi_bitrate(&mut self) {
        for stream in self.streams.values_mut() {
            if stream.protocol == "NDI"
                && let Some(src_ip) = stream.dst_ip
            {
                stream.bitrate_bps = self.tcp_streams.values()
                    .filter(|t| t.src_ip == src_ip || t.dst_ip == src_ip)
                    .map(|t| t.bitrate_bps)
                    .sum();
            }
        }
    }
}

// ── Emission ─────────────────────────────────────────────────────────────────

/// Map AlertLevel to ANSI color code. Info has no color.
fn ansi_color(level: &AlertLevel) -> Option<&'static str> {
    match level {
        AlertLevel::Info  => None,
        AlertLevel::Good  => Some("32"),
        AlertLevel::Warn  => Some("33"),
        AlertLevel::Error => Some("31"),
    }
}

/// Print + log all alerts. The log file gets the plain text; the console gets
/// the colored variant when a color is defined.
pub fn emit(alerts: &[Alert], logger: &mut Logger) {
    for a in alerts {
        match ansi_color(&a.level) {
            Some(c) => println!("\x1b[{}m{}\x1b[0m", c, a.message),
            None    => println!("{}", a.message),
        }
        logger.log(&a.message);
    }
}

/// Match an AvProtocol variant to its handler, then emit any returned alerts.
/// `l2_payload` is the VLAN-stripped Ethernet payload; `frame_bytes` is the
/// full Ethernet frame size; `avtp_seq` is byte 2 of the AVTP payload (for AVB).
pub fn dispatch(
    state: &mut CaptureState,
    proto: AvProtocol,
    l2_payload: &[u8],
    frame_bytes: u64,
    avtp_seq: Option<u8>,
    now: Instant,
    logger: &mut Logger,
) {
    let alerts = match proto {
        AvProtocol::Sap { src: _, sdp } => {
            state.handle_sap(sdp);
            vec![]
        }
        AvProtocol::Ptp { info } => state.handle_ptp(info),
        AvProtocol::Aes67 { dst, dst_port, payload_type, .. } => {
            state.handle_aes67(dst, dst_port, payload_type, l2_payload);
            vec![]
        }
        AvProtocol::St2110 { dst, dst_port, stream_type, .. } => {
            state.handle_st2110(dst, dst_port, stream_type, l2_payload);
            vec![]
        }
        AvProtocol::Dante { kind, src, dst_port } => {
            state.handle_dante(kind, src, dst_port, l2_payload)
        }
        AvProtocol::Ndi { kind: NdiKind::Discovery { source_name }, src } => {
            state.handle_ndi_discovery(src, source_name)
        }
        AvProtocol::Avb { subtype, stream_id } => {
            state.handle_avb(subtype, stream_id, frame_bytes, avtp_seq, now);
            vec![]
        }
        AvProtocol::Msrp { declarations } => state.handle_msrp(declarations),
        AvProtocol::Mvrp { vlan_ids }     => state.handle_mvrp(vlan_ids),
        AvProtocol::LldpEee { chassis_id, port_id, tx_wake_us, rx_wake_us } => {
            state.handle_lldp_eee(chassis_id, port_id, tx_wake_us, rx_wake_us)
        }
        AvProtocol::Igmp { src, group, igmp_type } => {
            state.handle_igmp(src, group, igmp_type, now)
        }
        AvProtocol::FlowControl { kind } => {
            state.handle_flow_control(kind);
            vec![]
        }
    };
    emit(&alerts, logger);
}

// ═════════════════════════════════════════════════════════════════
// TESTS
// ═════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::{PTP_VERSION_V1, PTP_VERSION_V2, ProtocolChoice, SdpMedia, SdpSession};
    use crate::stats::PtpStats;

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Build an IPv4 + UDP + minimal RTP byte buffer suitable for handlers
    /// that call `Ipv4Packet::new(l2_payload)`.
    /// `dscp_ecn_byte` is the full TOS octet: (dscp << 2) | ecn.
    fn ip_udp_rtp(dscp_ecn_byte: u8, dst_port: u16, pt: u8, seq: u16, ts: u32, ssrc: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 20 + 8 + 12];
        // IPv4 header
        buf[0] = 0x45;                                          // v4, IHL=5
        buf[1] = dscp_ecn_byte;
        let total_len: u16 = (20 + 8 + 12) as u16;
        buf[2..4].copy_from_slice(&total_len.to_be_bytes());
        buf[8] = 64;                                            // TTL
        buf[9] = 0x11;                                          // UDP
        buf[12..16].copy_from_slice(&[192, 168, 1, 10]);        // src
        buf[16..20].copy_from_slice(&[239, 69, 0, 1]);          // dst
        // UDP header at offset 20
        buf[20..22].copy_from_slice(&5004u16.to_be_bytes());    // src port
        buf[22..24].copy_from_slice(&dst_port.to_be_bytes());   // dst port
        buf[24..26].copy_from_slice(&20u16.to_be_bytes());      // length (UDP hdr + RTP)
        // RTP at offset 28
        buf[28] = 0x80;                                         // V=2
        buf[29] = pt & 0x7F;
        buf[30..32].copy_from_slice(&seq.to_be_bytes());
        buf[32..36].copy_from_slice(&ts.to_be_bytes());
        buf[36..40].copy_from_slice(&ssrc.to_be_bytes());
        buf
    }

    fn sdp_for_port(port: u16, pt: u8, clock_hz: f64) -> SdpSession {
        SdpSession {
            session_id: "1".to_string(),
            session_name: "Test Mix".to_string(),
            info: String::new(),
            media: vec![SdpMedia {
                media_type: "audio".to_string(),
                port,
                payload_types: vec![pt],
                connection: String::new(),
                rtpmap: "L24/48000/2".to_string(),
                clock_hz,
                channels: 2,
                ptime_ms: 1.0,
                ts_refclk: String::new(),
                mediaclk: String::new(),
            }],
        }
    }

    // ── AES67 ────────────────────────────────────────────────────────────────

    #[test]
    fn aes67_new_stream_inherits_sdp_when_present() {
        let mut state = CaptureState::new();
        state.sdp_cache.insert("1".to_string(), sdp_for_port(5004, 96, 48_000.0));
        let pkt = ip_udp_rtp(46 << 2, 5004, 96, 0, 0, 0xAAAA);
        state.handle_aes67(Ipv4Addr::new(239, 69, 0, 1), 5004, 96, &pkt);
        let s = state.streams.get("AES67 239.69.0.1:5004").expect("stream created");
        assert_eq!(s.expected_pt, Some(96));
        assert!(s.clock_hz_confirmed, "SAP-confirmed clock should flip the flag");
        assert_eq!(s.sdp_rtpmap.as_deref(), Some("L24/48000/2"));
    }

    #[test]
    fn aes67_dscp_violation_incremented_when_not_ef() {
        let mut state = CaptureState::new();
        let pkt = ip_udp_rtp(0, 5004, 96, 0, 0, 0xAAAA); // DSCP=0
        state.handle_aes67(Ipv4Addr::new(239, 69, 0, 1), 5004, 96, &pkt);
        let s = &state.streams["AES67 239.69.0.1:5004"];
        assert_eq!(s.dscp_violations, 1);
    }

    #[test]
    fn aes67_dscp_ef_does_not_violate() {
        let mut state = CaptureState::new();
        let pkt = ip_udp_rtp(46 << 2, 5004, 96, 0, 0, 0xAAAA);
        state.handle_aes67(Ipv4Addr::new(239, 69, 0, 1), 5004, 96, &pkt);
        let s = &state.streams["AES67 239.69.0.1:5004"];
        assert_eq!(s.dscp_violations, 0);
    }

    #[test]
    fn aes67_pt_mismatch_counted_when_expected_pt_set() {
        let mut state = CaptureState::new();
        state.sdp_cache.insert("1".to_string(), sdp_for_port(5004, 10, 48_000.0));
        // First packet establishes the stream with expected_pt=10
        let pkt0 = ip_udp_rtp(46 << 2, 5004, 11, 0, 0, 0xAAAA); // arrives with PT=11
        state.handle_aes67(Ipv4Addr::new(239, 69, 0, 1), 5004, 11, &pkt0);
        let s = &state.streams["AES67 239.69.0.1:5004"];
        assert_eq!(s.pt_mismatches, 1);
        assert_eq!(s.expected_pt, Some(10));
    }

    #[test]
    fn aes67_ecn_ce_increments_network_health() {
        let mut state = CaptureState::new();
        let pkt = ip_udp_rtp((46 << 2) | 0b11, 5004, 96, 0, 0, 0xAAAA); // ECN=3 (CE)
        state.handle_aes67(Ipv4Addr::new(239, 69, 0, 1), 5004, 96, &pkt);
        assert_eq!(state.network_health.ecn_congestion_marks, 1);
    }

    // ── ST 2110 ──────────────────────────────────────────────────────────────

    #[test]
    fn st2110_video_dscp_cs5_accepted() {
        let mut state = CaptureState::new();
        // CS5 = 40
        let pkt = ip_udp_rtp(40 << 2, 5004, 96, 0, 0, 0xAAAA);
        state.handle_st2110(Ipv4Addr::new(239, 1, 2, 3), 5004, St2110Type::Video, &pkt);
        let s = state.streams.values().find(|s| s.protocol == "2110-20").expect("video stream");
        assert_eq!(s.dscp_violations, 0, "CS5 is valid for ST2110-20 video");
    }

    #[test]
    fn st2110_audio_dscp_cs5_rejected() {
        let mut state = CaptureState::new();
        let pkt = ip_udp_rtp(40 << 2, 5004, 96, 0, 0, 0xAAAA);
        state.handle_st2110(Ipv4Addr::new(239, 1, 2, 3), 5004, St2110Type::Audio, &pkt);
        let s = state.streams.values().find(|s| s.protocol == "2110-30").expect("audio stream");
        assert_eq!(s.dscp_violations, 1, "audio requires EF only");
    }

    #[test]
    fn st2110_video_clock_confirmed_without_sdp() {
        let mut state = CaptureState::new();
        let pkt = ip_udp_rtp(46 << 2, 5004, 96, 0, 0, 0xAAAA);
        state.handle_st2110(Ipv4Addr::new(239, 1, 2, 3), 5004, St2110Type::Video, &pkt);
        let s = state.streams.values().find(|s| s.protocol == "2110-20").unwrap();
        assert!(s.clock_hz_confirmed, "video uses 90 kHz by spec, no SDP needed");
    }

    // ── Dante ────────────────────────────────────────────────────────────────

    #[test]
    fn dante_audio_stream_picks_up_name_from_mdns_cache() {
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(192, 168, 1, 50);
        state.dante_names.insert(src, "Stage Box".to_string());
        // empty l2_payload — name pickup happens before IP parse
        let alerts = state.handle_dante(DanteKind::AudioStream, src, 5004, &[]);
        assert!(alerts.is_empty());
        let s = state.streams.get("Dante 192.168.1.50:5004").expect("audio stream entry");
        assert_eq!(s.sdp_name.as_deref(), Some("Stage Box"));
    }

    #[test]
    fn dante_discovery_records_name_and_emits_info() {
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(192, 168, 1, 50);
        let alerts = state.handle_dante(
            DanteKind::Discovery { device_name: Some("Stage Box".to_string()) },
            src, 0, &[],
        );
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].level, AlertLevel::Info);
        assert!(alerts[0].message.contains("Stage Box"));
        assert_eq!(state.dante_names.get(&src).map(|s| s.as_str()), Some("Stage Box"));
    }

    // ── NDI ──────────────────────────────────────────────────────────────────

    #[test]
    fn ndi_discovery_stores_source_name() {
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(192, 168, 1, 60);
        let alerts = state.handle_ndi_discovery(src, Some("Studio Cam".to_string()));
        assert_eq!(alerts.len(), 1);
        assert!(state.ndi_sources.contains(&src));
        assert_eq!(state.ndi_names.get(&src).map(|s| s.as_str()), Some("Studio Cam"));
    }

    // ── IGMP ─────────────────────────────────────────────────────────────────

    #[test]
    fn igmp_join_deduplicated() {
        let mut state = CaptureState::new();
        let src   = Ipv4Addr::new(192, 168, 1, 10);
        let group = Ipv4Addr::new(239, 69, 0, 1);
        let a1 = state.handle_igmp(src, group, IgmpType::Join, Instant::now());
        let a2 = state.handle_igmp(src, group, IgmpType::Join, Instant::now());
        assert_eq!(a1.len(), 1, "first Join emits");
        assert_eq!(a2.len(), 0, "second Join is deduped");
    }

    #[test]
    fn igmp_leave_clears_dedup_entry() {
        let mut state = CaptureState::new();
        let src   = Ipv4Addr::new(192, 168, 1, 10);
        let group = Ipv4Addr::new(239, 69, 0, 1);
        state.handle_igmp(src, group, IgmpType::Join,  Instant::now());
        state.handle_igmp(src, group, IgmpType::Leave, Instant::now());
        let a3 = state.handle_igmp(src, group, IgmpType::Join, Instant::now());
        assert_eq!(a3.len(), 1, "Join after Leave is no longer deduped");
    }

    // ── LLDP / EEE ───────────────────────────────────────────────────────────

    #[test]
    fn lldp_eee_alert_fires_only_on_first_detection() {
        let mut state = CaptureState::new();
        let a1 = state.handle_lldp_eee("chassis-A".into(), "Gi0/1".into(), 16, 16);
        let a2 = state.handle_lldp_eee("chassis-A".into(), "Gi0/1".into(), 16, 16);
        assert_eq!(a1.len(), 1);
        assert_eq!(a2.len(), 0, "second detection on same port is silent");
        assert_eq!(state.eee_ports.len(), 1);
    }

    // ── MVRP ─────────────────────────────────────────────────────────────────

    #[test]
    fn mvrp_first_vlan_alerts_then_dedup() {
        let mut state = CaptureState::new();
        let a1 = state.handle_mvrp(vec![100, 100, 200]);
        let a2 = state.handle_mvrp(vec![100, 200]);
        assert_eq!(a1.len(), 2, "two distinct VLANs, duplicates within batch deduped");
        assert_eq!(a2.len(), 0, "already-registered VLANs are silent");
    }

    // ── MSRP ─────────────────────────────────────────────────────────────────

    // ── ptp_requirement_met ─────────────────────────────────────────────────

    /// Build a PtpStats record as if a grandmaster had been observed.
    fn valid_ptp_stats(version: u8, kind: &str) -> PtpStats {
        let mut s = PtpStats::new(0, version);
        s.clock_valid = true;
        s.protocol_kind = Some(kind.to_string());
        s.last_grandmaster = Some("test".to_string());
        s
    }

    /// Drop an AES67 stream entry into state so the "observed" gate fires.
    fn seed_aes67_stream(state: &mut CaptureState) {
        let pkt = ip_udp_rtp(46 << 2, 5004, 96, 0, 0, 0xAAAA);
        state.handle_aes67(Ipv4Addr::new(239, 69, 0, 1), 5004, 96, &pkt);
    }

    #[test]
    fn ptp_ok_when_no_streams_observed_regardless_of_selection() {
        // Empty state on "All" — nothing to check yet. No streams means no
        // clock requirement; the "no streams detected" status line is the
        // right signal at this point, not a PTP warning.
        let state = CaptureState::new();
        let expanded = ProtocolChoice::All.includes();
        assert!(state.ptp_requirement_met(&expanded));
    }

    #[test]
    fn ptp_ok_when_aes67_stream_and_ptpv2_clock_present() {
        let mut state = CaptureState::new();
        seed_aes67_stream(&mut state);
        state.ptp_domains.insert((0, PTP_VERSION_V2), valid_ptp_stats(PTP_VERSION_V2, "PTPv2"));
        assert!(state.ptp_requirement_met(&[ProtocolChoice::AES67]));
    }

    #[test]
    fn ptp_fails_when_aes67_stream_but_no_ptp() {
        let mut state = CaptureState::new();
        seed_aes67_stream(&mut state);
        assert!(!state.ptp_requirement_met(&[ProtocolChoice::AES67]));
    }

    #[test]
    fn ptp_fails_when_aes67_stream_has_only_ptpv1() {
        // AES67 requires PTPv2 — a PTPv1 clock is not sufficient.
        let mut state = CaptureState::new();
        seed_aes67_stream(&mut state);
        state.ptp_domains.insert((0, PTP_VERSION_V1), valid_ptp_stats(PTP_VERSION_V1, "PTPv1"));
        assert!(!state.ptp_requirement_met(&[ProtocolChoice::AES67]));
    }

    #[test]
    fn ptp_ok_for_dante_with_ptpv1_clock() {
        // Dante accepts either PTPv1 or PTPv2.
        let mut state = CaptureState::new();
        state.handle_dante(DanteKind::AudioStream, Ipv4Addr::new(192,168,1,10), 5004, &[]);
        state.ptp_domains.insert((0, PTP_VERSION_V1), valid_ptp_stats(PTP_VERSION_V1, "PTPv1"));
        assert!(state.ptp_requirement_met(&[ProtocolChoice::Dante]));
    }

    #[test]
    fn ptp_ok_for_all_on_pure_aes67_network() {
        // Regression for the reported bug: picking "All" on a network with
        // only AES67 + UDP PTPv2 (no AVB, no gPTP) used to warn "no clock
        // source" because needs_gptp was true based on selection alone.
        let mut state = CaptureState::new();
        seed_aes67_stream(&mut state);
        state.ptp_domains.insert((0, PTP_VERSION_V2), valid_ptp_stats(PTP_VERSION_V2, "PTPv2"));
        let expanded = ProtocolChoice::All.includes();
        assert!(state.ptp_requirement_met(&expanded));
    }

    #[test]
    fn ptp_fails_for_avb_streams_without_gptp() {
        let mut state = CaptureState::new();
        // Seed an AVTP stream so the "observed" gate fires.
        state.handle_avb(0x00, Some([1,2,3,4,5,6,7,8]), 100, Some(0), Instant::now());
        // UDP PTPv2 is present but L2 gPTP (protocol_kind="AVB") is not.
        state.ptp_domains.insert((0, PTP_VERSION_V2), valid_ptp_stats(PTP_VERSION_V2, "PTPv2"));
        assert!(!state.ptp_requirement_met(&[ProtocolChoice::AVB]));
    }

    #[test]
    fn ptp_ok_for_avb_with_l2_gptp() {
        let mut state = CaptureState::new();
        state.handle_avb(0x00, Some([1,2,3,4,5,6,7,8]), 100, Some(0), Instant::now());
        state.ptp_domains.insert((0, PTP_VERSION_V2), valid_ptp_stats(PTP_VERSION_V2, "AVB"));
        assert!(state.ptp_requirement_met(&[ProtocolChoice::AVB]));
    }

    #[test]
    fn ptp_ok_for_ndi_only_no_clock_required() {
        // NDI is TCP — no PTP at all.
        let mut state = CaptureState::new();
        state.ndi_sources.insert(Ipv4Addr::new(192,168,1,60));
        assert!(state.ptp_requirement_met(&[ProtocolChoice::NDI]));
    }

    // ── Flow control (PAUSE / PFC) ──────────────────────────────────────────

    #[test]
    fn pause_frames_counted_separately_from_pfc() {
        let mut state = CaptureState::new();
        state.handle_flow_control(FlowControlKind::Pause);
        state.handle_flow_control(FlowControlKind::Pause);
        state.handle_flow_control(FlowControlKind::PriorityFlowControl);
        assert_eq!(state.pause_frames_this_window, 2);
        assert_eq!(state.pfc_frames_this_window,   1);
    }

    #[test]
    fn flow_control_counters_clear_on_reset_window() {
        let mut state = CaptureState::new();
        state.handle_flow_control(FlowControlKind::Pause);
        state.handle_flow_control(FlowControlKind::PriorityFlowControl);
        state.reset_window();
        assert_eq!(state.pause_frames_this_window, 0);
        assert_eq!(state.pfc_frames_this_window,   0);
    }

    // ── PTP path-delay tracking ────────────────────────────────────────────

    fn delay_resp(domain: u8, path_delay_ns: i64) -> crate::protocols::PtpInfo {
        crate::protocols::PtpInfo {
            version: PTP_VERSION_V2,
            message_type: 0x09, // Delay_Resp
            domain,
            clock_id: None,
            grandmaster_id: None,
            clock_quality: None,
            correction_ns: Some(path_delay_ns),
            path_delay_ns: Some(path_delay_ns),
            origin_timestamp_ns: None,
            message_name: "Delay_Resp".to_string(),
            port_id: None,
            sequence_id: 0,
            log_sync_interval: 0,
            log_min_pdelay_req_interval: 0,
            protocol_kind: Some("PTPv2".to_string()),
            src_ip: None,
        }
    }

    #[test]
    fn ptp_path_delay_min_max_track_observed_range() {
        let mut state = CaptureState::new();
        state.handle_ptp(delay_resp(0, 500));
        state.handle_ptp(delay_resp(0, 1200));
        state.handle_ptp(delay_resp(0, 800));
        let stats = state.ptp_domains.get(&(0, PTP_VERSION_V2)).expect("entry created");
        assert_eq!(stats.min_path_delay_ns, Some(500));
        assert_eq!(stats.max_path_delay_ns, Some(1200));
    }

    #[test]
    fn ptp_path_delay_resets_on_grandmaster_change() {
        let mut state = CaptureState::new();
        state.handle_ptp(delay_resp(0, 1000));
        // Inject an Announce-like update that establishes a grandmaster, then
        // a second Announce with a different grandmaster to trigger reset.
        let mut announce = delay_resp(0, 500);
        announce.message_type = 0x0B; // Announce
        announce.grandmaster_id = Some("gm-A".to_string());
        announce.path_delay_ns = None; // Announce doesn't carry path delay
        state.handle_ptp(announce.clone());
        // Sanity: path delay still set from the earlier Delay_Resp.
        assert!(state.ptp_domains.get(&(0, PTP_VERSION_V2)).unwrap().min_path_delay_ns.is_some());

        announce.grandmaster_id = Some("gm-B".to_string());
        state.handle_ptp(announce);
        let stats = state.ptp_domains.get(&(0, PTP_VERSION_V2)).unwrap();
        assert_eq!(stats.min_path_delay_ns, None, "GM change should clear path-delay history");
        assert_eq!(stats.max_path_delay_ns, None);
    }

    #[test]
    fn msrp_talker_failed_emits_warn_alert() {
        let mut state = CaptureState::new();
        let decl = MsrpDeclaration {
            decl_type: MsrpDeclType::TalkerFailed,
            stream_id: [0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x01],
            dest_mac: None,
            vlan_id: None,
            max_frame_size: None,
            max_interval_frames: None,
            priority: None,
            failure_code: Some(1),
            listener_state: None,
        };
        let alerts = state.handle_msrp(vec![decl]);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].level, AlertLevel::Warn);
        assert!(alerts[0].message.contains("insufficient bandwidth"));
        assert!(state.msrp_state.contains_key(&[0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x01]));
    }
}

