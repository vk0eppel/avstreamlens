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
    AvProtocol, AvdeccAdp, DanteKind, FlowControlKind, IgmpType, MsrpDeclType, MsrpDeclaration,
    NdiKind, ProtocolChoice, PtpInfo, SdpSession, St2110Type, DEFAULT_CLOCK_HZ, PTP_VERSION_V2,
    STREAM_TIMEOUT_SECS, avtp_subtype_name, msrp_failure_reason,
};
use crate::report::Logger;
use crate::stats::{
    AvdeccEntity, AvtpStreamStats, ConmonDevice, NetworkHealth, PtpEvent, PtpStats, StreamQuality,
    StreamStats, TcpStreamStats,
};

// IGMP Join dedup entries are pruned after this many seconds without re-seeing
// the join. Well above the IGMPv2 default query interval (125s).
const IGMP_JOIN_DEDUP_TTL_SECS: u64 = 300;

// Streams (RTP/AVTP/TCP) are pruned after this many seconds of silence.
// `STREAM_TIMEOUT_SECS` is the report-time "dead stream" threshold; pruning
// waits longer so an alert is shown at least once before the entry disappears.
const STREAM_PRUNE_SECS: u64 = STREAM_TIMEOUT_SECS * 2;

// ConMon devices are pruned after this many seconds of silence. ConMon metering
// runs at ~33 packets/s per device, so 60 s of silence means the device is gone
// (powered off or unplugged) — generous against transient capture stalls.
const CONMON_PRUNE_SECS: u64 = 60;

/// Which clock type a protocol family is missing.
#[derive(Debug, Clone, PartialEq)]
pub enum MissingClockKind {
    Ptpv2,  // needed by AES67 and ST2110 (PTPv1 is not sufficient)
    Ptp,    // needed by Dante — PTPv1 or PTPv2 both acceptable
    Gptp,   // needed by AVB — L2 gPTP only
}

/// A clock requirement that is not satisfied: names the missing clock type
/// and the protocol families currently affected. Built by
/// `CaptureState::missing_ptp_clocks` and consumed by the report layer.
#[derive(Debug, Clone, PartialEq)]
pub struct MissingClock {
    pub kind: MissingClockKind,
    pub affected: Vec<&'static str>,
}

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
    // Dante sender IPs learned from mDNS or ConMon — tracked regardless of whether a name is known.
    pub dante_sources:  HashSet<Ipv4Addr>,
    pub dante_names:    HashMap<Ipv4Addr, String>,
    // Live Dante devices observed via ConMon multicast (224.0.0.230-233:8700-8708).
    // Link-local multicast — never IGMP-snooped, so this is a continuous liveness
    // signal from any port even when all audio flows are unicast (no SPAN).
    pub dante_conmon:   HashMap<Ipv4Addr, ConmonDevice>,
    // Deduplicates IGMP Join console output — cleared on Leave so re-joins print again.
    pub igmp_joins_seen: HashMap<(Ipv4Addr, Ipv4Addr), Instant>,
    pub avtp_streams:    HashMap<[u8; 8], AvtpStreamStats>,
    pub msrp_state:      HashMap<[u8; 8], MsrpDeclaration>,
    pub mvrp_vlans:      HashSet<u16>,
    // AVDECC entities discovered via ADP (IEEE 1722.1) — keyed by entity_id EUI-64.
    pub avdecc_entities: HashMap<[u8; 8], AvdeccEntity>,
    // EEE detection: (chassis_id, port_id) → (tx_wake_us, rx_wake_us)
    pub eee_ports:      HashMap<(String, String), (u16, u16)>,
    pub bytes_this_window: u64,
    // Link-layer flow-control counters (PAUSE / PFC, EtherType 0x8808).
    // Many NICs strip these at the MAC layer before pcap sees them; when
    // they do reach userspace, any non-zero count indicates upstream
    // congestion that has caused brief tx-side freezes.
    pub pause_frames_this_window: u64,
    pub pfc_frames_this_window:   u64,
    pub packets_dispatched: u64,
    // Dynamic IGMP multicast join support — handlers push new 239.x.x.x group
    // addresses here; main.rs drains this after each dispatch and joins them.
    // `joined_multicast` is populated by main.rs after a successful join so
    // handlers can avoid pushing the same group more than once.
    pub pending_join_groups: Vec<Ipv4Addr>,
    pub joined_multicast:    HashSet<Ipv4Addr>,
    // Rolling history of total stream counts (RTP + TCP + AVTP) at the end of
    // each 5s window, used to detect sudden flood-style anomalies. Capped at 3
    // entries; the oldest is dropped when a fourth would be added.
    stream_count_history: Vec<usize>,
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
            dante_sources: HashSet::new(),
            dante_names: HashMap::new(),
            dante_conmon: HashMap::new(),
            igmp_joins_seen: HashMap::new(),
            avtp_streams:    HashMap::new(),
            msrp_state:      HashMap::new(),
            mvrp_vlans:      HashSet::new(),
            avdecc_entities: HashMap::new(),
            eee_ports: HashMap::new(),
            bytes_this_window: 0,
            pause_frames_this_window: 0,
            pfc_frames_this_window:   0,
            packets_dispatched: 0,
            pending_join_groups: Vec::new(),
            joined_multicast:    HashSet::new(),
            stream_count_history: Vec::new(),
        }
    }

    /// Reset per-5s-window counters and prune silent streams.
    /// Call after each report is printed.
    pub fn reset_window(&mut self) {
        self.bytes_this_window = 0;
        self.pause_frames_this_window = 0;
        self.pfc_frames_this_window   = 0;
        self.packets_dispatched = 0;
        self.network_health.ecn_congestion_marks = 0;
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
        // Prune MSRP reservation state for stream IDs whose AVTP stream was
        // just pruned — a gone stream has no active reservation to display.
        self.msrp_state.retain(|sid, _| self.avtp_streams.contains_key(sid));
        // Clear MVRP VLAN registrations when there are no active AVTP streams.
        // MVRP is periodic — when AVB is active, the switch re-registers VLANs
        // within a few seconds, so clearing here causes no lasting data loss.
        if self.avtp_streams.is_empty() {
            self.mvrp_vlans.clear();
        }
        // Drop ConMon devices that stopped announcing (metering is ~33 Hz, so
        // a minute of silence means the device left the network).
        self.dante_conmon.retain(|_, d| d.last_seen.elapsed().as_secs() < CONMON_PRUNE_SECS);
        // Drop IGMP Join entries from hosts that vanished without sending a Leave.
        self.igmp_joins_seen.retain(|_, t| t.elapsed() < Duration::from_secs(IGMP_JOIN_DEDUP_TTL_SECS));
        // Prune AVDECC entities whose ADP announcement has expired (valid_time + 10s grace).
        self.avdecc_entities.retain(|_, e| {
            e.last_seen.elapsed().as_secs() < e.valid_time_secs.max(10) + 10
        });
    }

    // ── Handlers ────────────────────────────────────────────────────────────

    /// SAP/SDP: cache the SDP and enrich any matching streams with metadata.
    ///
    /// Technical fields (clock_hz, ptime_ms, expected_pt, codec) are always
    /// re-applied so a mid-run codec change is picked up immediately. The
    /// session name is only written once — subsequent re-announcements with the
    /// same or different name do not overwrite a name already shown to the user.
    pub fn handle_sap(&mut self, sdp: SdpSession) {
        for m in &sdp.media {
            for stats in self.streams.values_mut() {
                if stats.dst_port == m.port {
                    // Name: set on first announcement only.
                    if stats.sdp_name.is_none() {
                        stats.sdp_name = Some(sdp.session_name.clone());
                    }
                    // Technical fields: always refresh so mid-run codec changes
                    // (sample rate, ptime, payload type) are reflected immediately.
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
        // Queue any multicast stream addresses for dynamic IGMP joining.
        // SDP connection field is "IN IP4 <addr>[/ttl]"; extract the IP.
        for m in &sdp.media {
            let conn = m.connection.trim();
            if let Some(addr_part) = conn.strip_prefix("IN IP4 ") {
                let ip_str = addr_part.split('/').next().unwrap_or("").trim();
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>()
                    && ip.octets()[0] == 239 && !self.joined_multicast.contains(&ip) {
                    self.pending_join_groups.push(ip);
                }
            }
        }
        self.sdp_cache.insert(sdp.session_id.clone(), sdp);
    }

    /// AVDECC ADP: update or insert entity discovery state; emit an alert on first
    /// detection and on state change (available_index increment). ENTITY_DEPARTING
    /// (message_type 1) removes the entity immediately.
    pub fn handle_avdecc_adp(&mut self, adp: AvdeccAdp, now: Instant) -> Vec<Alert> {
        use crate::parser::{fmt_eui64, media_type_summary, sr_class_str};

        // ENTITY_DEPARTING — device is leaving the network.
        if adp.message_type == 1 {
            if self.avdecc_entities.remove(&adp.entity_id).is_some() {
                return vec![Alert::info(format!(
                    "➖ AVDECC entity departed: {}", fmt_eui64(&adp.entity_id)
                ))];
            }
            return vec![];
        }

        // ENTITY_DISCOVER — a query, not an announcement; nothing to store.
        if adp.message_type == 2 { return vec![]; }

        // ENTITY_AVAILABLE (0) — upsert.
        let eui = fmt_eui64(&adp.entity_id);
        let entry = self.avdecc_entities.get(&adp.entity_id);

        let is_new     = entry.is_none();
        let state_changed = entry.is_some_and(|e| e.available_index != adp.available_index);

        self.avdecc_entities.insert(adp.entity_id, AvdeccEntity {
            entity_id:             adp.entity_id,
            entity_model_id:       adp.entity_model_id,
            entity_capabilities:   adp.entity_capabilities,
            talker_stream_sources: adp.talker_stream_sources,
            talker_capabilities:   adp.talker_capabilities,
            listener_stream_sinks: adp.listener_stream_sinks,
            listener_capabilities: adp.listener_capabilities,
            gptp_grandmaster_id:   adp.gptp_grandmaster_id,
            gptp_domain_number:    adp.gptp_domain_number,
            valid_time_secs:       adp.valid_time_secs,
            available_index:       adp.available_index,
            last_seen:             now,
        });

        if is_new {
            let talker_desc = if adp.talker_stream_sources > 0 {
                format!("T:{} ({})", adp.talker_stream_sources,
                    media_type_summary(adp.talker_capabilities))
            } else { String::new() };
            let listener_desc = if adp.listener_stream_sinks > 0 {
                format!("L:{} ({})", adp.listener_stream_sinks,
                    media_type_summary(adp.listener_capabilities))
            } else { String::new() };
            let role = [talker_desc, listener_desc]
                .into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join("  ");
            let class = sr_class_str(adp.entity_capabilities);
            let aem   = if adp.entity_capabilities & 0x08 != 0 { "  AEM" } else { "" };
            return vec![Alert::info(format!(
                "📡 AVDECC entity discovered: {}  {}  {}{}",
                eui, role, class, aem
            ))];
        }

        if state_changed {
            return vec![Alert::info(format!(
                "ℹ AVDECC entity state changed: {} (index {})", eui, adp.available_index
            ))];
        }

        vec![]
    }

    /// PTP: update the (domain, version) entry, return Detected/Changed alert if any.
    pub fn handle_ptp(&mut self, info: PtpInfo) -> Vec<Alert> {
        let kind   = info.protocol_kind.clone();
        let src_ip = info.src_ip;
        let stats  = self.ptp_domains
            .entry((info.domain, info.version))
            .or_insert_with(|| PtpStats::new(info.domain, info.version));
        let event  = stats.update(&info, &kind);
        let ip_str = src_ip.map(|ip| format!("  ({})", ip)).unwrap_or_default();
        match event {
            Some(PtpEvent::GrandmasterDetected) => {
                let gm = stats.last_grandmaster.as_deref().unwrap_or("?");
                vec![Alert::good(format!(
                    "✓  GRANDMASTER DETECTED (Domain {} v{}): {}{}",
                    stats.domain, stats.version, gm, ip_str
                ))]
            }
            Some(PtpEvent::GrandmasterChanged { from }) => {
                let gm = stats.last_grandmaster.as_deref().unwrap_or("?");
                vec![Alert::warn(format!(
                    "⚠️  GRANDMASTER CHANGED (Domain {} v{}): {} → {}{}",
                    stats.domain, stats.version, from, gm, ip_str
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
            let (clock, rtpmap, exp_pt, channels, confirmed) = sdp_media
                .map(|m| (m.clock_hz, Some(m.rtpmap.clone()), m.payload_types.first().copied(),
                          if m.channels > 0 { m.channels } else { 1 }, m.clock_hz > 0.0))
                .unwrap_or((DEFAULT_CLOCK_HZ, None, None, 1, false));
            let mut s = StreamStats::new_with_info("AES67", clock, is_aes67_multicast(dst), dst, dst_port);
            s.sdp_rtpmap = rtpmap;
            s.media_type = "audio".to_string();
            s.channels = channels;
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

    /// Dante: discovery, control (silent), ConMon liveness, or audio stream.
    pub fn handle_dante(&mut self, kind: DanteKind, src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16, l2_payload: &[u8], now: Instant) -> Vec<Alert> {
        match kind {
            DanteKind::Discovery { device_name } => {
                let is_new = !self.dante_sources.contains(&src);
                self.dante_sources.insert(src);
                if let Some(ref name) = device_name {
                    self.dante_names.insert(src, name.clone());
                    // Retroactive naming: a stream observed before this device's
                    // mDNS announcement was created nameless — backfill it now.
                    // Name is written once (same rule as SAP session names) so
                    // later re-announcements don't flicker the display.
                    for s in self.streams.values_mut() {
                        if s.protocol == "Dante" && s.src_ip == Some(src) && s.sdp_name.is_none() {
                            s.sdp_name = Some(name.clone());
                        }
                    }
                }
                if is_new {
                    let label = device_name.as_deref().unwrap_or("unknown device");
                    vec![Alert::info(format!("🔍 Dante discovered: {}  \"{}\"", src, label))]
                } else {
                    vec![]
                }
            }
            DanteKind::Control => vec![],
            DanteKind::ConMon { device_mac, channels } => {
                let is_new = !self.dante_conmon.contains_key(&src);
                let entry = self.dante_conmon.entry(src).or_insert_with(|| ConmonDevice {
                    mac: device_mac, channels: None, packets: 0, last_seen: now,
                });
                entry.packets += 1;
                entry.last_seen = now;
                entry.mac = device_mac;
                // Channel count only rides metering frames — keep the last known
                // value when other ConMon message types arrive.
                if channels.is_some() { entry.channels = channels; }
                // ConMon proves a live Dante device even before (or without) mDNS —
                // count it as a discovered source so the device list includes it.
                self.dante_sources.insert(src);
                if is_new {
                    let mac = device_mac;
                    let mac_str = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                    let name = self.dante_names.get(&src)
                        .map(|n| format!("  \"{}\"", n)).unwrap_or_default();
                    let ch = channels.map(|c| format!("  {} ch", c)).unwrap_or_default();
                    vec![Alert::info(format!(
                        "🔍 Dante device live (ConMon): {}{}  [{}]{}", src, name, mac_str, ch
                    ))]
                } else {
                    vec![]
                }
            }
            DanteKind::AudioStream => {
                let is_mc = crate::parser::is_multicast(dst);
                // Key on src AND dst: one device can transmit several flows from
                // the same source port to different destinations (e.g. multiple
                // multicast groups) — keying on src:port alone merged them,
                // interleaving their sequence numbers into false loss.
                let key = format!("Dante {} → {}:{}", src, dst, dst_port);
                let stats = self.streams.entry(key).or_insert_with(|| {
                    let mut s = StreamStats::new_with_info("Dante", DEFAULT_CLOCK_HZ, is_mc, dst, dst_port);
                    s.ptime_ms = 1.0; // Dante standard: 48 samples @ 48kHz = 1ms
                    s.src_ip = Some(src);
                    s.sdp_name = self.dante_names.get(&src).cloned();
                    s
                });
                if let Some(ip) = pnet_packet::ipv4::Ipv4Packet::new(l2_payload)
                    && let Some(udp) = pnet_packet::udp::UdpPacket::new(ip.payload())
                {
                    // Dante audio requires DSCP EF (46)
                    if ip.get_dscp() != 46 { stats.dscp_violations += 1; }
                    if ip.get_ecn() == 3 { self.network_health.ecn_congestion_marks += 1; }
                    match parse_rtp(udp.payload()) {
                        Some((seq, ts, ssrc)) => stats.update(seq, ts, ssrc, udp.payload().len()),
                        // ATP framing (official ports 4321 / 14336–15359) is not RTP —
                        // track presence and bitrate; loss/jitter need RTP fields.
                        None => stats.update_non_rtp(udp.payload().len(), now),
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
        // sv=0 AVTP control/discovery frames (AVDECC ADP/ACMP, MAAP) carry no stream
        // id — they are not media streams. Skip them so they don't inflate the AVB
        // stream count, create a phantom dead-stream entry, or diverge from the
        // per-stream-id avtp_streams map the Streams list and clock gate both read.
        // (Their bytes still count toward bandwidth via bytes_this_window in main.rs.)
        let Some(sid) = stream_id else { return; };

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

        let entry = self.avtp_streams.entry(sid)
            .or_insert_with(|| AvtpStreamStats::new(sid, subtype));
        entry.packets += 1;
        entry.last_seen = now;
        entry.update_bitrate(frame_bytes, now);
        if let Some(seq) = avtp_seq { entry.update_seq(seq); }
    }

    /// MSRP declarations — records all, alerts only on TalkerFailed.
    pub fn handle_msrp(&mut self, declarations: Vec<MsrpDeclaration>) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for decl in declarations {
            if matches!(decl.decl_type, MsrpDeclType::TalkerFailed) {
                let code_str = match decl.failure_code {
                    Some(code) => format!(" (code {}: {})", code, msrp_failure_reason(code)),
                    None       => String::new(),
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
            IgmpType::MembershipReportV3 { groups } => {
                // Queue new 239.x.x.x groups for dynamic joining so IGMP-snooping
                // switches deliver those streams to our capture port.
                for group in groups {
                    if group.octets()[0] == 239 && !self.joined_multicast.contains(&group) {
                        self.pending_join_groups.push(group);
                    }
                }
                // No console output — infrastructure detail, not user-visible.
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

    /// Stream-count anomaly detection, called from the periodic report cycle
    /// **before** `reset_window` so the count reflects streams active this window.
    ///
    /// Fires when the current total stream count is more than 2× the rolling
    /// average of the last 3 windows — the fingerprint of a runaway device
    /// flooding new multicast groups. Requires a full 3-window baseline before
    /// alerting so normal startup growth doesn't trigger a false positive.
    pub fn check_stream_count_anomaly(&mut self) -> Vec<Alert> {
        let current = self.streams.len() + self.tcp_streams.len() + self.avtp_streams.len();

        let mut alerts = Vec::new();
        if self.stream_count_history.len() == 3 {
            let avg: usize = self.stream_count_history.iter().sum::<usize>() / 3;
            if avg > 0 && current > avg * 2 {
                alerts.push(Alert::warn(format!(
                    "⚠ Stream count spike: {} streams (avg last 3 windows: {}) — possible runaway multicast flood",
                    current, avg,
                )));
            }
        }

        // Maintain a rolling 3-entry history: drop the oldest when full.
        if self.stream_count_history.len() == 3 {
            self.stream_count_history.remove(0);
        }
        self.stream_count_history.push(current);

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
    /// Returns a per-family list of clock requirements that are not satisfied.
    /// Each entry names *which* clock is missing and *which* protocol(s) are
    /// affected — so the report layer can say "no PTPv2 clock — AES67 streams
    /// may lose sync" instead of a generic "no clock source".
    pub fn missing_ptp_clocks(&self, expanded: &[ProtocolChoice]) -> Vec<MissingClock> {
        let mut missing = Vec::new();

        // ── PTPv2 (AES67, ST2110) ────────────────────────────────────────────
        let aes67_active  = expanded.iter().any(|c| matches!(c, ProtocolChoice::AES67))
            && self.streams.values().any(|s| s.protocol == "AES67");
        let st2110_active = expanded.iter().any(|c| matches!(c, ProtocolChoice::ST2110))
            && self.streams.values().any(|s| s.protocol.starts_with("2110-"));
        let has_ptpv2 = self.ptp_domains.values().any(|s|
            s.clock_valid && s.version == PTP_VERSION_V2
            && s.protocol_kind.as_deref() != Some("AVB"));
        if (aes67_active || st2110_active) && !has_ptpv2 {
            let mut affected = Vec::new();
            if aes67_active  { affected.push("AES67"); }
            if st2110_active { affected.push("ST2110"); }
            missing.push(MissingClock { kind: MissingClockKind::Ptpv2, affected });
        }

        // ── PTPv1 or PTPv2 (Dante) ───────────────────────────────────────────
        let dante_active = expanded.iter().any(|c| matches!(c, ProtocolChoice::Dante))
            && self.streams.values().any(|s| s.protocol == "Dante");
        // Dante needs PTPv1/PTPv2 on the IP network — an L2 gPTP (AVB) clock does
        // not satisfy it, so exclude AVB domains just like the PTPv2 check above.
        let has_ptp = self.ptp_domains.values().any(|s|
            s.clock_valid && s.protocol_kind.as_deref() != Some("AVB"));
        if dante_active && !has_ptp {
            missing.push(MissingClock { kind: MissingClockKind::Ptp, affected: vec!["Dante"] });
        }

        // ── L2 gPTP (AVB) ────────────────────────────────────────────────────
        let avb_active = expanded.iter().any(|c| matches!(c, ProtocolChoice::AVB))
            && !self.avtp_streams.is_empty();
        let has_gptp = self.ptp_domains.values().any(|s|
            s.clock_valid && s.protocol_kind.as_deref() == Some("AVB"));
        if avb_active && !has_gptp {
            missing.push(MissingClock { kind: MissingClockKind::Gptp, affected: vec!["AVB"] });
        }

        missing
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
            Some(c) if crate::color_enabled() => println!("\x1b[{}m{}\x1b[0m", c, a.message),
            _ => println!("{}", a.message),
        }
        logger.log(&a.message);
    }
}

/// Match an AvProtocol variant to its handler, then emit any returned alerts.
/// `l2_payload` is the VLAN-stripped Ethernet payload; `frame_bytes` is the
/// full Ethernet frame size. The AVTP sequence counter is carried in the
/// `Avb` variant itself (extracted from the unwrapped payload in `detect_protocol`).
pub fn dispatch(
    state: &mut CaptureState,
    proto: AvProtocol,
    l2_payload: &[u8],
    frame_bytes: u64,
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
        AvProtocol::Dante { kind, src, dst, dst_port } => {
            state.handle_dante(kind, src, dst, dst_port, l2_payload, now)
        }
        AvProtocol::Ndi { kind: NdiKind::Discovery { source_name }, src } => {
            state.handle_ndi_discovery(src, source_name)
        }
        AvProtocol::AvdeccAdp(adp) => state.handle_avdecc_adp(adp, now),
        AvProtocol::Avb { subtype, stream_id, seq } => {
            state.handle_avb(subtype, stream_id, frame_bytes, seq, now);
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

    /// SAP re-announcement with changed technical fields (e.g. payload type) must
    /// update the stream even when a name was already set by a prior announcement.
    ///
    /// Real-world order of events:
    ///   1. RTP stream observed → stream entry created (sdp_name = None)
    ///   2. First SAP → name + technical fields written
    ///   3. Second SAP with different codec → technical fields must update; name must not
    #[test]
    fn sap_reenrichment_updates_technical_fields_when_name_already_set() {
        let mut state = CaptureState::new();

        // Step 1: stream observed before any SAP arrives (no sdp_cache entry yet).
        let pkt = ip_udp_rtp(46 << 2, 5004, 96, 0, 0, 0xAAAA);
        state.handle_aes67(Ipv4Addr::new(239, 69, 0, 1), 5004, 96, &pkt);
        assert_eq!(state.streams["AES67 239.69.0.1:5004"].sdp_name, None);

        // Step 2: first SAP — sets name AND technical fields.
        state.handle_sap(sdp_for_port(5004, 96, 48_000.0));
        {
            let s = &state.streams["AES67 239.69.0.1:5004"];
            assert_eq!(s.sdp_name.as_deref(), Some("Test Mix"));
            assert_eq!(s.expected_pt, Some(96));
            assert_eq!(s.clock_hz as u32, 48_000);
        }

        // Step 3: second SAP — encoder changed to PT=97 / 96 kHz.
        // Technical fields must update; name must stay "Test Mix".
        let updated_sdp = SdpSession {
            session_id: "1".to_string(),
            session_name: "Updated Mix".to_string(),
            info: String::new(),
            media: vec![SdpMedia {
                media_type: "audio".to_string(),
                port: 5004,
                payload_types: vec![97],
                connection: String::new(),
                rtpmap: "L24/96000/2".to_string(),
                clock_hz: 96_000.0,
                channels: 2,
                ptime_ms: 1.0,
                ts_refclk: String::new(),
                mediaclk: String::new(),
            }],
        };
        state.handle_sap(updated_sdp);
        let s = &state.streams["AES67 239.69.0.1:5004"];
        assert_eq!(s.expected_pt, Some(97),              "payload type must update");
        assert_eq!(s.clock_hz as u32, 96_000,            "clock rate must update");
        assert_eq!(s.sdp_rtpmap.as_deref(), Some("L24/96000/2"), "rtpmap must update");
        assert_eq!(s.sdp_name.as_deref(), Some("Test Mix"),      "name must not be overwritten");
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
        let alerts = state.handle_dante(DanteKind::AudioStream, src, Ipv4Addr::new(192,168,1,60), 5004, &[], Instant::now());
        assert!(alerts.is_empty());
        let s = state.streams.get("Dante 192.168.1.50 → 192.168.1.60:5004").expect("audio stream entry");
        assert_eq!(s.sdp_name.as_deref(), Some("Stage Box"));
    }

    #[test]
    fn dante_name_backfilled_when_discovery_arrives_after_stream() {
        // Audio observed first (no name yet), mDNS announcement second — the
        // existing stream entry must pick up the device name retroactively.
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(192, 168, 1, 50);
        state.handle_dante(DanteKind::AudioStream, src, Ipv4Addr::new(192,168,1,60), 5004, &[], Instant::now());
        assert_eq!(state.streams["Dante 192.168.1.50 → 192.168.1.60:5004"].sdp_name, None);

        state.handle_dante(
            DanteKind::Discovery { device_name: Some("Stage Box".to_string()) },
            src, Ipv4Addr::new(224,0,0,251), 0, &[], Instant::now(),
        );
        assert_eq!(
            state.streams["Dante 192.168.1.50 → 192.168.1.60:5004"].sdp_name.as_deref(),
            Some("Stage Box"),
            "discovery must backfill the name on already-created streams"
        );
    }

    #[test]
    fn dante_flows_to_different_destinations_tracked_separately() {
        // One device transmitting from the same source port to two multicast
        // groups = two distinct flows. Keying on src:port alone merged them,
        // interleaving sequence numbers into false loss.
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(169, 254, 81, 11);
        state.handle_dante(DanteKind::AudioStream, src, Ipv4Addr::new(239,255,10,1), 4321, &[], Instant::now());
        state.handle_dante(DanteKind::AudioStream, src, Ipv4Addr::new(239,255,10,2), 4321, &[], Instant::now());
        let dante_streams = state.streams.keys().filter(|k| k.starts_with("Dante ")).count();
        assert_eq!(dante_streams, 2, "flows to different destinations must not merge");
    }

    #[test]
    fn dante_discovery_records_name_and_emits_info() {
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(192, 168, 1, 50);
        let alerts = state.handle_dante(
            DanteKind::Discovery { device_name: Some("Stage Box".to_string()) },
            src, Ipv4Addr::new(224,0,0,251), 0, &[], Instant::now(),
        );
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].level, AlertLevel::Info);
        assert!(alerts[0].message.contains("Stage Box"));
        assert!(state.dante_sources.contains(&src));
        assert_eq!(state.dante_names.get(&src).map(|s| s.as_str()), Some("Stage Box"));
    }

    #[test]
    fn dante_discovery_unknown_name_populates_sources() {
        // When name extraction fails (device_name: None), the IP must still be tracked in
        // dante_sources so the periodic 📇 section shows the correct device count.
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(169, 254, 133, 58);
        let alerts = state.handle_dante(
            DanteKind::Discovery { device_name: None },
            src, Ipv4Addr::new(224,0,0,251), 0, &[], Instant::now(),
        );
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].message.contains("unknown device"));
        assert!(state.dante_sources.contains(&src));
        assert!(!state.dante_names.contains_key(&src), "dante_names should stay empty for unknown device");
    }

    #[test]
    fn dante_discovery_deduplicates_alert() {
        // Repeated mDNS packets from the same IP must emit the alert exactly once.
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(169, 254, 133, 58);
        let first = state.handle_dante(
            DanteKind::Discovery { device_name: None },
            src, Ipv4Addr::new(224,0,0,251), 0, &[], Instant::now(),
        );
        let second = state.handle_dante(
            DanteKind::Discovery { device_name: None },
            src, Ipv4Addr::new(224,0,0,251), 0, &[], Instant::now(),
        );
        assert_eq!(first.len(), 1, "first discovery should emit alert");
        assert_eq!(second.len(), 0, "duplicate discovery should emit no alert");
        assert_eq!(state.dante_sources.len(), 1);
    }

    // ── Dante ConMon ─────────────────────────────────────────────────────────

    #[test]
    fn conmon_first_detection_alerts_then_dedup_and_tracks_liveness() {
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(169, 254, 81, 11);
        let mac = [0x00, 0x1d, 0xc1, 0x19, 0x86, 0x2a];
        let first = state.handle_dante(
            DanteKind::ConMon { device_mac: mac, channels: Some(32) },
            src, Ipv4Addr::new(224, 0, 0, 232), 8705, &[], Instant::now(),
        );
        let second = state.handle_dante(
            DanteKind::ConMon { device_mac: mac, channels: Some(32) },
            src, Ipv4Addr::new(224, 0, 0, 232), 8705, &[], Instant::now(),
        );
        assert_eq!(first.len(), 1, "first ConMon sighting emits an info alert");
        assert!(first[0].message.contains("32 ch"));
        assert_eq!(second.len(), 0, "repeat sightings are silent");
        let dev = state.dante_conmon.get(&src).expect("device tracked");
        assert_eq!(dev.mac, mac);
        assert_eq!(dev.channels, Some(32));
        assert_eq!(dev.packets, 2);
        assert!(state.dante_sources.contains(&src),
            "ConMon device counts as a discovered Dante source");
    }

    #[test]
    fn conmon_channel_count_survives_non_metering_frames() {
        // A status frame (channels: None) after a metering frame must not erase
        // the channel count already learned.
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(169, 254, 81, 11);
        let mac = [0x00, 0x1d, 0xc1, 0x19, 0x86, 0x2a];
        state.handle_dante(DanteKind::ConMon { device_mac: mac, channels: Some(32) },
            src, Ipv4Addr::new(224, 0, 0, 232), 8705, &[], Instant::now());
        state.handle_dante(DanteKind::ConMon { device_mac: mac, channels: None },
            src, Ipv4Addr::new(224, 0, 0, 233), 8708, &[], Instant::now());
        assert_eq!(state.dante_conmon[&src].channels, Some(32));
    }

    // ── Dante ATP (non-RTP) audio ────────────────────────────────────────────

    /// Build an IPv4 + UDP buffer whose UDP payload is NOT RTP (ATP-style).
    fn ip_udp_non_rtp(dst: [u8; 4], dst_port: u16, payload_len: usize) -> Vec<u8> {
        let udp_len = (8 + payload_len) as u16;
        let mut buf = vec![0u8; 20 + 8 + payload_len];
        buf[0] = 0x45;
        buf[1] = 46 << 2; // DSCP EF
        let total = (20 + udp_len) as u16;
        buf[2..4].copy_from_slice(&total.to_be_bytes());
        buf[8] = 64;
        buf[9] = 0x11;
        buf[12..16].copy_from_slice(&[169, 254, 81, 11]);
        buf[16..20].copy_from_slice(&dst);
        buf[20..22].copy_from_slice(&14400u16.to_be_bytes());
        buf[22..24].copy_from_slice(&dst_port.to_be_bytes());
        buf[24..26].copy_from_slice(&udp_len.to_be_bytes());
        // payload stays zeroed — first byte 0x00 fails the RTP version check
        buf
    }

    #[test]
    fn dante_atp_stream_tracked_without_rtp_metrics() {
        // A non-RTP ATP flow (official multicast port 4321) must create a stream
        // entry with packet/byte counts, but rtp_seen stays false so the report
        // doesn't render fake 0% loss / 0 ms jitter as measured values.
        let mut state = CaptureState::new();
        let pkt = ip_udp_non_rtp([239, 255, 10, 1], 4321, 64);
        state.handle_dante(DanteKind::AudioStream,
            Ipv4Addr::new(169, 254, 81, 11), Ipv4Addr::new(239, 255, 10, 1), 4321, &pkt, Instant::now());
        let s = state.streams.get("Dante 169.254.81.11 → 239.255.10.1:4321").expect("stream created");
        assert_eq!(s.packets, 1);
        assert!(!s.rtp_seen, "ATP payload must not set rtp_seen");
        assert!(s.last_packet_time.is_some(), "presence tracked for dead-stream detection");
        assert!(s.bytes_total > 0, "bytes tracked for bitrate");
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
        assert!(state.missing_ptp_clocks(&expanded).is_empty());
    }

    #[test]
    fn ptp_ok_when_aes67_stream_and_ptpv2_clock_present() {
        let mut state = CaptureState::new();
        seed_aes67_stream(&mut state);
        state.ptp_domains.insert((0, PTP_VERSION_V2), valid_ptp_stats(PTP_VERSION_V2, "PTPv2"));
        assert!(state.missing_ptp_clocks(&[ProtocolChoice::AES67]).is_empty());
    }

    #[test]
    fn ptp_fails_when_aes67_stream_but_no_ptp() {
        let mut state = CaptureState::new();
        seed_aes67_stream(&mut state);
        assert!(!state.missing_ptp_clocks(&[ProtocolChoice::AES67]).is_empty());
    }

    #[test]
    fn ptp_fails_when_aes67_stream_has_only_ptpv1() {
        // AES67 requires PTPv2 — a PTPv1 clock is not sufficient.
        let mut state = CaptureState::new();
        seed_aes67_stream(&mut state);
        state.ptp_domains.insert((0, PTP_VERSION_V1), valid_ptp_stats(PTP_VERSION_V1, "PTPv1"));
        assert!(!state.missing_ptp_clocks(&[ProtocolChoice::AES67]).is_empty());
    }

    #[test]
    fn ptp_ok_for_dante_with_ptpv1_clock() {
        // Dante accepts either PTPv1 or PTPv2.
        let mut state = CaptureState::new();
        state.handle_dante(DanteKind::AudioStream, Ipv4Addr::new(192,168,1,10), Ipv4Addr::new(192,168,1,60), 5004, &[], Instant::now());
        state.ptp_domains.insert((0, PTP_VERSION_V1), valid_ptp_stats(PTP_VERSION_V1, "PTPv1"));
        assert!(state.missing_ptp_clocks(&[ProtocolChoice::Dante]).is_empty());
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
        assert!(state.missing_ptp_clocks(&expanded).is_empty());
    }

    #[test]
    fn ptp_fails_for_avb_streams_without_gptp() {
        let mut state = CaptureState::new();
        // Seed an AVTP stream so the "observed" gate fires.
        state.handle_avb(0x00, Some([1,2,3,4,5,6,7,8]), 100, Some(0), Instant::now());
        // UDP PTPv2 is present but L2 gPTP (protocol_kind="AVB") is not.
        state.ptp_domains.insert((0, PTP_VERSION_V2), valid_ptp_stats(PTP_VERSION_V2, "PTPv2"));
        assert!(!state.missing_ptp_clocks(&[ProtocolChoice::AVB]).is_empty());
    }

    #[test]
    fn ptp_ok_for_avb_with_l2_gptp() {
        let mut state = CaptureState::new();
        state.handle_avb(0x00, Some([1,2,3,4,5,6,7,8]), 100, Some(0), Instant::now());
        state.ptp_domains.insert((0, PTP_VERSION_V2), valid_ptp_stats(PTP_VERSION_V2, "AVB"));
        assert!(state.missing_ptp_clocks(&[ProtocolChoice::AVB]).is_empty());
    }

    #[test]
    fn ptp_ok_for_ndi_only_no_clock_required() {
        // NDI is TCP — no PTP at all.
        let mut state = CaptureState::new();
        state.ndi_sources.insert(Ipv4Addr::new(192,168,1,60));
        assert!(state.missing_ptp_clocks(&[ProtocolChoice::NDI]).is_empty());
    }

    // ── missing_ptp_clocks — per-family identification ──────────────────────

    #[test]
    fn missing_clock_for_aes67_identifies_ptpv2_and_aes67() {
        let mut state = CaptureState::new();
        seed_aes67_stream(&mut state);
        let missing = state.missing_ptp_clocks(&[ProtocolChoice::AES67]);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].kind, MissingClockKind::Ptpv2);
        assert_eq!(missing[0].affected, vec!["AES67"]);
    }

    #[test]
    fn missing_clock_groups_aes67_and_st2110_under_same_ptpv2_entry() {
        // Both protocols need PTPv2; report should produce ONE missing entry
        // listing both affected protocols, not two separate entries.
        let mut state = CaptureState::new();
        seed_aes67_stream(&mut state);
        // Seed an ST2110 stream too.
        let pkt = ip_udp_rtp(46 << 2, 5006, 96, 0, 0, 0xBBBB);
        state.handle_st2110(Ipv4Addr::new(239, 1, 2, 3), 5006, St2110Type::Audio, &pkt);
        let missing = state.missing_ptp_clocks(&[ProtocolChoice::AES67, ProtocolChoice::ST2110]);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].kind, MissingClockKind::Ptpv2);
        assert_eq!(missing[0].affected, vec!["AES67", "ST2110"]);
    }

    #[test]
    fn missing_clock_separates_ptpv2_and_dante_when_both_lack_their_clock() {
        let mut state = CaptureState::new();
        seed_aes67_stream(&mut state);
        state.handle_dante(DanteKind::AudioStream, Ipv4Addr::new(192,168,1,50), Ipv4Addr::new(192,168,1,60), 5004, &[], Instant::now());
        let missing = state.missing_ptp_clocks(&[ProtocolChoice::AES67, ProtocolChoice::Dante]);
        assert_eq!(missing.len(), 2);
        assert!(missing.iter().any(|m| m.kind == MissingClockKind::Ptpv2 && m.affected == vec!["AES67"]));
        assert!(missing.iter().any(|m| m.kind == MissingClockKind::Ptp   && m.affected == vec!["Dante"]));
    }

    #[test]
    fn dante_clock_not_satisfied_by_avb_gptp() {
        // A Dante stream plus only an L2 gPTP (AVB) clock — Dante still needs
        // PTPv1/PTPv2 on the IP network, so the gPTP clock must not satisfy it.
        let mut state = CaptureState::new();
        state.handle_dante(DanteKind::AudioStream, Ipv4Addr::new(192,168,1,50), Ipv4Addr::new(192,168,1,60), 5004, &[], Instant::now());
        state.ptp_domains.insert((0, PTP_VERSION_V2), valid_ptp_stats(PTP_VERSION_V2, "AVB"));
        let missing = state.missing_ptp_clocks(&[ProtocolChoice::Dante]);
        assert!(missing.iter().any(|m| m.kind == MissingClockKind::Ptp && m.affected == vec!["Dante"]),
            "AVB gPTP must not satisfy Dante's clock requirement");
    }

    #[test]
    fn missing_clock_for_avb_identifies_gptp() {
        let mut state = CaptureState::new();
        state.handle_avb(0x00, Some([1,2,3,4,5,6,7,8]), 100, Some(0), Instant::now());
        // UDP PTPv2 present but no L2 gPTP — AVB still affected.
        state.ptp_domains.insert((0, PTP_VERSION_V2), valid_ptp_stats(PTP_VERSION_V2, "PTPv2"));
        let missing = state.missing_ptp_clocks(&[ProtocolChoice::AVB]);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].kind, MissingClockKind::Gptp);
        assert_eq!(missing[0].affected, vec!["AVB"]);
    }

    // ── handle_avb — sv=0 control frames must not become phantom streams ─────

    #[test]
    fn avb_control_frame_without_stream_id_creates_no_stream() {
        // An sv=0 AVTP control/discovery frame (no stream id) must not inflate the
        // AVB count or create a phantom streams entry — both maps stay empty so the
        // overview count, the Streams list, and the gPTP gate all agree.
        let mut state = CaptureState::new();
        state.handle_avb(0x7e, None, 100, None, Instant::now()); // 0x7e = MAAP
        assert!(state.avtp_streams.is_empty());
        assert!(!state.streams.keys().any(|k| k.starts_with("AVB")));
    }

    #[test]
    fn avb_media_frame_with_stream_id_creates_stream() {
        let mut state = CaptureState::new();
        state.handle_avb(0x00, Some([1, 2, 3, 4, 5, 6, 7, 8]), 100, Some(0), Instant::now());
        assert_eq!(state.avtp_streams.len(), 1);
        assert!(state.streams.keys().any(|k| k.starts_with("AVB")));
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

    // ── Stream count anomaly detection ────────────────────────────────────

    fn add_rtp_stream(state: &mut CaptureState, key: &str) {
        state.streams.insert(key.to_string(), StreamStats::new("AES67", 48_000.0));
    }

    #[test]
    fn stream_count_anomaly_no_alert_without_full_baseline() {
        // Fewer than 3 history entries → no alert regardless of current count.
        let mut state = CaptureState::new();
        for i in 0..10 { add_rtp_stream(&mut state, &format!("s{i}")); }
        // First call — history is empty, no alert.
        assert!(state.check_stream_count_anomaly().is_empty());
        // Second call — only 1 history entry, still no alert.
        for i in 10..20 { add_rtp_stream(&mut state, &format!("s{i}")); }
        assert!(state.check_stream_count_anomaly().is_empty());
    }

    #[test]
    fn stream_count_anomaly_fires_after_three_baseline_windows() {
        let mut state = CaptureState::new();
        // Three baseline windows with 2 streams each → avg = 2.
        for w in 0..3 {
            state.streams.clear();
            add_rtp_stream(&mut state, &format!("base{w}a"));
            add_rtp_stream(&mut state, &format!("base{w}b"));
            let alerts = state.check_stream_count_anomaly();
            assert!(alerts.is_empty(), "no alert during baseline build-up");
        }
        // Fourth window: 5 streams > 2 × 2 → alert fires.
        state.streams.clear();
        for i in 0..5 { add_rtp_stream(&mut state, &format!("flood{i}")); }
        let alerts = state.check_stream_count_anomaly();
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].message.contains("Stream count spike"));
    }

    #[test]
    fn stream_count_anomaly_no_false_positive_on_normal_growth() {
        let mut state = CaptureState::new();
        // Baseline: 4 streams per window.
        for w in 0..3 {
            state.streams.clear();
            for i in 0..4 { add_rtp_stream(&mut state, &format!("w{w}s{i}")); }
            state.check_stream_count_anomaly();
        }
        // Modest growth to 7 streams — below 2 × 4 = 8, no alert.
        state.streams.clear();
        for i in 0..7 { add_rtp_stream(&mut state, &format!("grow{i}")); }
        assert!(state.check_stream_count_anomaly().is_empty());
    }

    #[test]
    fn stream_count_history_rolls_after_three_entries() {
        let mut state = CaptureState::new();
        // Fill history with counts 10, 10, 10.
        for w in 0..3 {
            state.streams.clear();
            for i in 0..10 { add_rtp_stream(&mut state, &format!("w{w}s{i}")); }
            state.check_stream_count_anomaly();
        }
        assert_eq!(state.stream_count_history, vec![10, 10, 10]);
        // Next call (current=10) — should roll: drop oldest 10, append 10.
        state.streams.clear();
        for i in 0..10 { add_rtp_stream(&mut state, &format!("r{i}")); }
        state.check_stream_count_anomaly();
        assert_eq!(state.stream_count_history.len(), 3, "history stays capped at 3");
        assert_eq!(state.stream_count_history, vec![10, 10, 10]);
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
            message_name: "Delay_Resp".to_string(),
            port_id: None,
            sequence_id: 0,
            log_sync_interval: 0,
            log_min_pdelay_req_interval: 0,
            protocol_kind: Some("PTPv2".to_string()),
            src_ip: None,
        }
    }

    fn ptp_msg(message_type: u8, clock_id: Option<&str>) -> crate::protocols::PtpInfo {
        crate::protocols::PtpInfo {
            version: PTP_VERSION_V2,
            message_type,
            domain: 0,
            clock_id: clock_id.map(|s| s.to_string()),
            grandmaster_id: None,
            clock_quality: None,
            correction_ns: Some(0),
            path_delay_ns: None,
            message_name: String::new(),
            port_id: None,
            sequence_id: 0,
            log_sync_interval: 0,
            log_min_pdelay_req_interval: 0,
            protocol_kind: Some("AVB".to_string()),
            src_ip: None,
        }
    }

    #[test]
    fn ptp_pdelay_req_only_does_not_set_seen_sync() {
        // An AVB endpoint on a non-gPTP port emits only P_Delay_Req (0x02). It must
        // surface a clock_id but NOT be labelled "Sync seen" — seen_sync gates the
        // report wording that distinguishes a real clock from a Pdelay-only node.
        let mut s = PtpStats::new(0, PTP_VERSION_V2);
        let kind = Some("AVB".to_string());
        s.update(&ptp_msg(0x02, Some("d0:69:9e:ff:fe:11:86:3c")), &kind);
        assert!(s.last_clock_id.is_some());
        assert!(!s.seen_sync, "P_Delay_Req must not count as Sync");

        s.update(&ptp_msg(0x00, Some("d0:69:9e:ff:fe:11:86:3c")), &kind);
        assert!(s.seen_sync, "a real Sync (0x00) sets seen_sync");
    }

    #[test]
    fn ptp_grandmaster_src_ip_is_the_gm_not_a_follower() {
        // The GM IP must come from the message carrying the grandmaster (Sync/Announce),
        // so a follower's Delay_Req can't make us attribute (and mDNS-name) the wrong
        // device. last_src_ip still follows any sender.
        let gm_ip = Ipv4Addr::new(169, 254, 104, 86);
        let follower_ip = Ipv4Addr::new(169, 254, 1, 2);
        let mut s = PtpStats::new(0, PTP_VERSION_V2);
        let kind = Some("PTPv1".to_string());

        let mut gm_sync = ptp_msg(0x00, Some("00:00:00:01:00:1d"));
        gm_sync.grandmaster_id = Some("00:00:00:01:00:1d".to_string());
        gm_sync.src_ip = Some(gm_ip);
        s.update(&gm_sync, &kind);
        assert_eq!(s.grandmaster_src_ip, Some(gm_ip));

        let mut follower = ptp_msg(0x01, Some("00:1d:c1:8e:b1:75"));
        follower.src_ip = Some(follower_ip);
        s.update(&follower, &kind);
        assert_eq!(s.last_src_ip, Some(follower_ip), "last_src_ip follows any sender");
        assert_eq!(s.grandmaster_src_ip, Some(gm_ip), "grandmaster IP stays the GM");
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

