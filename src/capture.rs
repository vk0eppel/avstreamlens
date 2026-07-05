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
    NdiKind, ProtocolChoice, PtpInfo, SdpMedia, SdpSession, St2110Type, TransmitterClass, DEFAULT_CLOCK_HZ,
    PTP_VERSION_V1, PTP_VERSION_V2, STREAM_TIMEOUT_SECS, classify_transmitter, msrp_failure_reason,
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

/// Which Clock Source family a stream's protocol requires, if any. The single
/// source of truth for this rule — previously re-derived independently in
/// `missing_ptp_clocks`, `check_clock_dropout_correlation`, and the report
/// layer's per-stream diagnostic suppression, which could silently drift out
/// of sync with each other. AVB is deliberately not handled here: its gPTP
/// requirement is derived from `avb.avtp_streams` presence, not a `StreamStats`
/// protocol label (AVB frames never populate `CaptureState::streams`).
pub fn stream_clock_kind(protocol: &str) -> Option<MissingClockKind> {
    if protocol == "AES67" || protocol.starts_with("2110-") {
        Some(MissingClockKind::Ptpv2)
    } else if protocol == "Dante" {
        Some(MissingClockKind::Ptp)
    } else {
        None
    }
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

/// Bounded-eviction insert shared by `DanteState::record_source` and
/// `NdiState::record_source`: when `sources` is at `max` and `ip` is new, evicts
/// one existing entry (arbitrary choice — anything but `ip` itself) from
/// `sources` and lets `evict_extra` clear that same IP from the caller's sibling
/// maps (names, transmitter_class, ...). Returns whether `ip` was newly seen.
fn record_bounded_source(
    sources: &mut HashSet<Ipv4Addr>,
    max: usize,
    ip: Ipv4Addr,
    evict_extra: impl FnOnce(Ipv4Addr),
) -> bool {
    let is_new = !sources.contains(&ip);
    if is_new && sources.len() >= max
        && let Some(&victim) = sources.iter().find(|v| **v != ip)
    {
        sources.remove(&victim);
        evict_extra(victim);
    }
    sources.insert(ip);
    is_new
}

/// Dante-specific per-session state. Grouped so that Dante-only methods take
/// a narrow `&mut DanteState` seam rather than all of `CaptureState`.
pub struct DanteState {
    /// Source IPs learned from mDNS or ConMon — tracked regardless of whether a name is known.
    pub sources:  HashSet<Ipv4Addr>,
    pub names:    HashMap<Ipv4Addr, String>,
    /// Live devices observed via ConMon multicast (224.0.0.230-233:8700-8708).
    pub conmon:   HashMap<Ipv4Addr, ConmonDevice>,
    /// Consecutive windows each source IP has been mDNS-only (no ConMon, no active stream).
    pub unverified_windows: HashMap<Ipv4Addr, u32>,
    /// Transmitter Class learned from control-plane traffic. Session-lifetime, never pruned.
    pub transmitter_class: HashMap<Ipv4Addr, TransmitterClass>,
}

impl DanteState {
    pub fn new() -> Self {
        Self {
            sources:           HashSet::new(),
            names:             HashMap::new(),
            conmon:            HashMap::new(),
            unverified_windows: HashMap::new(),
            transmitter_class: HashMap::new(),
        }
    }

    /// Prune stale ConMon entries and update the mDNS-only verification counters.
    /// Must be called after report checks (check_conmon_bridge etc.) but before
    /// the next capture window begins.
    pub fn reset_window(&mut self, streams: &HashMap<String, StreamStats>) {
        self.conmon.retain(|_, d| d.last_seen.elapsed().as_secs() < CONMON_PRUNE_SECS);
        for ip in &self.sources {
            let has_stream = streams.values().any(|s| s.src_ip == Some(*ip));
            let has_conmon = self.conmon.contains_key(ip);
            if has_stream || has_conmon {
                self.unverified_windows.remove(ip);
            } else {
                *self.unverified_windows.entry(*ip).or_insert(0) += 1;
            }
        }
        self.unverified_windows.retain(|ip, _| self.sources.contains(ip));
    }

    /// Consecutive windows of mDNS-only silence before a discovered source is
    /// considered unverified rather than just quiet — see `unverified()`.
    const UNVERIFIED_THRESHOLD: u32 = 3;

    /// Source IPs in `sources` that have gone `UNVERIFIED_THRESHOLD` or more
    /// consecutive windows without ConMon activity or an active stream — likely
    /// a management NIC or non-Dante device that happened to answer a Dante
    /// mDNS query, not a genuine live device. Owns the threshold next to the
    /// counter it judges, so the report layer only renders what this decides.
    pub fn unverified(&self) -> HashSet<Ipv4Addr> {
        self.sources.iter()
            .filter(|ip| self.unverified_windows.get(ip).copied().unwrap_or(0) >= Self::UNVERIFIED_THRESHOLD)
            .copied()
            .collect()
    }

    /// Upper bound on tracked Dante source IPs. These maps are keyed by (spoofable)
    /// source IP and would otherwise grow without bound under an mDNS/ConMon flood,
    /// exhausting memory in a root process. Far above any real deployment's device
    /// count — purely a DoS backstop.
    pub const MAX_SOURCES: usize = 4096;

    /// Record a discovered source IP (and optional device name), keeping the
    /// per-source maps bounded. When at capacity and the IP is new, one existing
    /// entry is evicted first (source, name, and transmitter-class together) so a
    /// flood of spoofed source IPs cannot grow the maps without limit. Returns
    /// whether the IP was newly discovered (drives the discovery alert).
    pub fn record_source(&mut self, ip: Ipv4Addr, name: Option<&str>) -> bool {
        let is_new = record_bounded_source(&mut self.sources, Self::MAX_SOURCES, ip, |victim| {
            self.names.remove(&victim);
            self.transmitter_class.remove(&victim);
        });
        if let Some(n) = name { self.names.insert(ip, n.to_string()); }
        is_new
    }

    /// Record a Transmitter Class learned from control-plane traffic.
    /// DVS/Via are more specific than Hardware and overwrite it; Hardware never
    /// downgrades an existing DVS/Via verdict.
    pub fn record_tx_class(&mut self, src: Ipv4Addr, class: TransmitterClass) {
        match class {
            TransmitterClass::Hardware => { self.transmitter_class.entry(src).or_insert(class); }
            _ => { self.transmitter_class.insert(src, class); }
        }
    }

    /// Detect accidental bridging of Dante primary and secondary networks.
    /// Two distinct source IPs sharing the same ConMon MAC means both NICs of
    /// the same device are visible — the redundancy networks are connected.
    pub fn check_conmon_bridge(&self) -> Vec<Alert> {
        let mut mac_to_ips: HashMap<[u8; 6], Vec<Ipv4Addr>> = HashMap::new();
        for (src_ip, device) in &self.conmon {
            mac_to_ips.entry(device.mac).or_default().push(*src_ip);
        }
        let mut alerts = Vec::new();
        for (mac, ips) in &mac_to_ips {
            if ips.len() < 2 { continue; }
            let mac_str = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            let mut ip_strs: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
            ip_strs.sort();
            let name = ips.iter().find_map(|ip| self.names.get(ip))
                .map(|n| format!("  \"{}\"", n)).unwrap_or_default();
            alerts.push(Alert::error(format!(
                "❌ Dante redundancy bridged: MAC {}{}  seen from {} IPs ({}) — primary and secondary networks are connected",
                mac_str, name, ips.len(), ip_strs.join(", "),
            )));
        }
        alerts
    }

    pub fn check_ip_config(&self) -> Vec<Alert> {
        if self.sources.len() < 2 {
            return vec![];
        }
        let mut alerts = Vec::new();
        let is_link_local = |ip: &Ipv4Addr| {
            let o = ip.octets();
            (o[0] == 169 && o[1] == 254) || (o[0] == 172 && o[1] == 31)
        };
        let link_local: Vec<Ipv4Addr> = self.sources.iter().filter(|ip| is_link_local(ip)).copied().collect();
        let routable:   Vec<Ipv4Addr> = self.sources.iter().filter(|ip| !is_link_local(ip)).copied().collect();
        if !link_local.is_empty() && !routable.is_empty() {
            let mut sorted = link_local.clone();
            sorted.sort();
            for ip in sorted {
                let name = self.names.get(&ip)
                    .map(|n| format!("\"{}\" ", n))
                    .unwrap_or_default();
                alerts.push(Alert::error(format!(
                    "❌ Dante device {}({}) has no DHCP address — subscriptions to/from this device will fail",
                    name, ip,
                )));
            }
        }
        if routable.len() >= 2 {
            let mut subnets: std::collections::HashSet<[u8; 3]> = std::collections::HashSet::new();
            for ip in &routable {
                let o = ip.octets();
                subnets.insert([o[0], o[1], o[2]]);
            }
            if subnets.len() > 1 {
                let mut labels: Vec<String> = subnets.iter()
                    .map(|s| format!("{}.{}.{}.0/24", s[0], s[1], s[2]))
                    .collect();
                labels.sort();
                alerts.push(Alert::warn(format!(
                    "⚠ Dante devices span {} subnets ({}) — mDNS discovery and PTP sync are multicast-only and cannot cross subnet boundaries; use Dante Domain Manager (DDM) or Dante Director for cross-subnet operation",
                    subnets.len(), labels.join(", "),
                )));
            }
        }
        alerts
    }

    /// Alert when fewer Dante devices than expected are sending PTPv1 Delay_Req.
    pub fn check_follower_census(&self, ptp: &PtpState) -> Vec<Alert> {
        let total   = self.sources.len();
        let syncing = ptp.v1_followers.len();
        let has_ptpv1 = ptp.domains.keys().any(|(_, v)| *v == crate::protocols::PTP_VERSION_V1);
        if !has_ptpv1 || total < 2 || syncing == 0 {
            return vec![];
        }
        let gm_ip: Option<Ipv4Addr> = ptp.domains.iter()
            .filter(|((_, v), _)| *v == crate::protocols::PTP_VERSION_V1)
            .filter_map(|(_, stats)| stats.grandmaster_src_ip)
            .next();
        let mut candidates: Vec<Ipv4Addr> = self.sources.iter()
            .filter(|ip| !ptp.v1_followers.contains_key(ip))
            .copied()
            .collect();
        candidates.sort();
        let missing: Vec<Ipv4Addr> = match gm_ip {
            Some(gm) => candidates.into_iter().filter(|ip| *ip != gm).collect(),
            None     => if candidates.len() <= 1 { vec![] } else { candidates },
        };
        if missing.is_empty() {
            return vec![];
        }
        let labels: Vec<String> = missing.iter().map(|ip| {
            match self.names.get(ip) {
                Some(name) => format!("\"{}\" ({})", name, ip),
                None       => ip.to_string(),
            }
        }).collect();
        vec![Alert::warn(format!(
            "⚠ {} Dante device{} not syncing to clock: {}",
            missing.len(),
            if missing.len() == 1 { "" } else { "s" },
            labels.join(", "),
        ))]
    }
}

impl Default for DanteState {
    fn default() -> Self { Self::new() }
}

/// NDI-specific substate: sender IPs and names learned from `_ndi._tcp` mDNS.
/// Both maps are session-lifetime (never pruned) — an NDI source that goes
/// quiet keeps its name so a later TCP flow is still attributable. Grouped for
/// symmetry with the other protocol-family substates; carries no per-window
/// logic of its own. Bitrate aggregation lives on `CaptureState` because it
/// reads the shared `streams`/`tcp_streams` maps, not these fields.
pub struct NdiState {
    pub sources: HashSet<Ipv4Addr>,
    pub names:   HashMap<Ipv4Addr, String>,
}

impl NdiState {
    pub fn new() -> Self {
        Self { sources: HashSet::new(), names: HashMap::new() }
    }

    /// Upper bound on tracked NDI source IPs — see `DanteState::MAX_SOURCES`.
    pub const MAX_SOURCES: usize = 4096;

    /// Record a discovered NDI source IP (and optional name), keeping the maps
    /// bounded against a spoofed-source-IP flood. Evicts one existing entry when at
    /// capacity and the IP is new. Returns whether the IP was newly discovered.
    pub fn record_source(&mut self, ip: Ipv4Addr, name: Option<&str>) -> bool {
        let is_new = record_bounded_source(&mut self.sources, Self::MAX_SOURCES, ip, |victim| {
            self.names.remove(&victim);
        });
        if let Some(n) = name { self.names.insert(ip, n.to_string()); }
        is_new
    }
}

impl Default for NdiState {
    fn default() -> Self { Self::new() }
}

/// IGMP-specific substate: per-window querier/report tracking plus the Join
/// dedup map. Querier *identity* (IP, MAC, interval) lives on `NetworkHealth`
/// because the score penalty reads it there — so the two `check_*` methods that
/// need that identity take `&mut NetworkHealth` / `&NetworkHealth` as a param
/// (interim signature, same shape as `DanteState::check_follower_census`).
pub struct IgmpState {
    /// Deduplicates IGMP Join console output — cleared on Leave so re-joins print again.
    pub joins_seen: HashMap<(Ipv4Addr, Ipv4Addr), Instant>,
    /// Per-window set of source IPs that sent an IGMP General Query.
    pub querier_ips_this_window: HashSet<Ipv4Addr>,
    /// Querier version detected from query payload length (2 or 3). Retained
    /// across windows (last known version, not reset per window).
    pub querier_version: Option<u8>,
    /// Set when any IGMPv3 report (type 0x22) is seen this window.
    pub v3_report_seen_this_window: bool,
}

impl IgmpState {
    pub fn new() -> Self {
        Self {
            joins_seen: HashMap::new(),
            querier_ips_this_window: HashSet::new(),
            querier_version: None,
            v3_report_seen_this_window: false,
        }
    }

    /// Reset per-window IGMP tracking and prune the Join dedup map.
    /// Must run AFTER `check_multiple_queriers()` (which reads
    /// `querier_ips_this_window`) and before the next capture window begins.
    pub fn reset_window(&mut self) {
        self.querier_ips_this_window.clear();
        self.v3_report_seen_this_window = false;
        // Drop IGMP Join entries from hosts that vanished without sending a Leave.
        self.joins_seen.retain(|_, t| t.elapsed() < Duration::from_secs(IGMP_JOIN_DEDUP_TTL_SECS));
    }

    /// Multiple IGMP queriers on the same LAN cause multicast group lists to
    /// desync across switches, leading to lost PTP/audio traffic.
    /// Sets `health.multiple_queriers_this_window` for the score penalty.
    ///
    /// Gated on `has_active_multicast` — same rule as the querier-*absent* penalty
    /// (`collect_penalties`): IGMP querier topology only affects the observable AV
    /// delivery path when multicast is actually flowing, so on a network with no
    /// active multicast streams this stays silent (no alert, no score penalty)
    /// rather than docking the score for a condition that harms nothing here.
    /// `querier_ips_this_window` only ever holds General-Query sources (see
    /// `handle_igmp`), so two entries already means two real queriers.
    pub fn check_multiple_queriers(&self, health: &mut NetworkHealth, has_active_multicast: bool) -> Vec<Alert> {
        if !has_active_multicast {
            return vec![];
        }
        let mut sorted: Vec<String> = self.querier_ips_this_window
            .iter().map(|ip| ip.to_string()).collect();
        if sorted.len() < 2 {
            return vec![];
        }
        health.multiple_queriers_this_window = true;
        sorted.sort();
        vec![Alert::error(format!(
            "❌ Multiple IGMP queriers detected: {} — querier conflict causes multicast group desync; disable querier on all but one switch",
            sorted.join(", "),
        ))]
    }

    /// Advisory when an IGMPv2 querier is paired with IGMPv3 hosts.
    /// Mac built-in Ethernet always sends IGMPv3 reports (0x22); some managed
    /// switches only speak IGMPv2 and may silently drop those reports, starving
    /// Mac hosts of Dante/AES67 multicast. Fires when querier version == 2 AND
    /// v3 reports are seen.
    pub fn check_version_mismatch(&self) -> Vec<Alert> {
        if self.querier_version == Some(2) && self.v3_report_seen_this_window {
            return vec![Alert::warn(
                "⚠ IGMPv2 querier with IGMPv3 hosts — Mac built-in Ethernet sends IGMPv3 reports that an IGMPv2 querier may not process; affected Macs may lose Dante/AES67 multicast (workaround: use a USB/Thunderbolt Ethernet adapter)".to_string(),
            )];
        }
        vec![]
    }
}

impl Default for IgmpState {
    fn default() -> Self { Self::new() }
}

/// AVB-specific substate: the four L2 maps with coupled lifecycles — AVTP
/// per-stream stats, MSRP reservations, MVRP VLAN registrations, and
/// ADP-discovered AVDECC entities. Grouped here because their pruning rules
/// reference each other (MSRP pruned to surviving AVTP; MVRP cleared when AVTP
/// is empty) — that interdependency wants to live in one `reset_window`.
pub struct AvbState {
    pub avtp_streams:    HashMap<[u8; 8], AvtpStreamStats>,
    pub msrp_state:      HashMap<[u8; 8], MsrpDeclaration>,
    pub mvrp_vlans:      HashSet<u16>,
    /// AVDECC entities discovered via ADP (IEEE 1722.1) — keyed by entity_id EUI-64.
    pub avdecc_entities: HashMap<[u8; 8], AvdeccEntity>,
}

impl AvbState {
    pub fn new() -> Self {
        Self {
            avtp_streams:    HashMap::new(),
            msrp_state:      HashMap::new(),
            mvrp_vlans:      HashSet::new(),
            avdecc_entities: HashMap::new(),
        }
    }

    /// Prune AVTP streams that have gone silent, then keep the dependent maps in
    /// step: MSRP reservations whose AVTP stream is gone have nothing to display;
    /// MVRP VLAN registrations are cleared when no AVTP stream remains (MVRP is
    /// periodic — the switch re-registers within seconds when AVB resumes); and
    /// AVDECC entities expire once past their advertised valid_time (+10s grace).
    pub fn reset_window(&mut self) {
        self.avtp_streams.retain(|_, s| {
            s.last_seen.elapsed().as_secs() < STREAM_PRUNE_SECS
        });
        self.msrp_state.retain(|sid, _| self.avtp_streams.contains_key(sid));
        if self.avtp_streams.is_empty() {
            self.mvrp_vlans.clear();
        }
        self.avdecc_entities.retain(|_, e| {
            e.last_seen.elapsed().as_secs() < e.valid_time_secs.max(10) + 10
        });
    }
}

impl Default for AvbState {
    fn default() -> Self { Self::new() }
}

/// PTP-specific substate: domains keyed by (domain, version) — separates
/// Dante PTPv1 from AES67/ST2110 PTPv2 on the same domain number — plus the
/// PTPv1 Delay_Req follower census used to detect Dante devices that have
/// stopped syncing.
pub struct PtpState {
    pub domains:     HashMap<(u8, u8), PtpStats>,
    pub v1_followers: HashMap<Ipv4Addr, Instant>,
}

impl PtpState {
    pub fn new() -> Self {
        Self { domains: HashMap::new(), v1_followers: HashMap::new() }
    }

    /// Clear per-window PTPv1 Sync sender census and prune stale followers.
    /// Must run AFTER `check_ptp_sync_conflict()` (called by main.rs before
    /// `reset_window`), which reads `sync_senders_this_window`.
    pub fn reset_window(&mut self) {
        for ptp in self.domains.values_mut() {
            ptp.sync_senders_this_window.clear();
        }
        // PTPv1 followers: Delay_Req rate is ~1/s; prune after 15s to survive
        // inter-cycle gaps without false-positive census drops.
        self.v1_followers.retain(|_, t| t.elapsed().as_secs() < 15);
    }

    /// Periodic clock-loss check, called from the report cycle. Returns
    /// Error alerts for any domain whose PTP clock has timed out.
    pub fn check_ptp_timeouts(&mut self) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for stats in self.domains.values_mut() {
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

    /// PTPv1 multiple-master conflict detection, called from the periodic report cycle
    /// **before** `reset_window` (which clears `sync_senders_this_window`).
    ///
    /// Healthy Dante PTPv1: one device wins BMCA and is the sole Sync sender. Two
    /// devices sending Sync in the same domain signals BMCA election instability.
    /// Two devices both with stratum 0 (Dante "preferred master" setting) is the
    /// common misconfiguration — a second AV engineer set their console's Dante
    /// interface to "preferred master" without realising one was already set.
    pub fn check_ptp_sync_conflict(&self) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for ptp in self.domains.values() {
            if ptp.version != crate::protocols::PTP_VERSION_V1 { continue; }
            let senders = &ptp.sync_senders_this_window;
            if senders.len() <= 1 { continue; }

            let preferred: Vec<_> = senders.iter()
                .filter(|(_, s)| **s == 0)
                .map(|(ip, _)| ip.to_string())
                .collect();

            if preferred.len() >= 2 {
                alerts.push(Alert::error(format!(
                    "❌ Multiple Preferred Leaders in PTP domain {} ({}) — if one device has an external word clock and another is set as Preferred Leader, the word-clock device will lose sync and be muted unless both share the same external reference; disable Preferred Leader on all but one device",
                    ptp.domain,
                    preferred.join(", "),
                )));
            } else {
                let all_ips: Vec<_> = senders.keys().map(|ip| ip.to_string()).collect();
                alerts.push(Alert::warn(format!(
                    "⚠ Multiple PTP Sync senders in domain {} ({}) — possible IGMP snooping partition or 'Sync to External' mismatch; check that only one device is the clock leader",
                    ptp.domain,
                    all_ips.join(", "),
                )));
            }
        }
        alerts
    }
}

impl Default for PtpState {
    fn default() -> Self { Self::new() }
}

/// All per-loop state owned by the capture loop. Handlers mutate fields here
/// and return alerts to the dispatch layer.
pub struct CaptureState {
    pub streams:        HashMap<String, StreamStats>,
    pub tcp_streams:    HashMap<String, TcpStreamStats>,
    pub sdp_cache:      HashMap<String, SdpSession>,
    pub network_health: NetworkHealth,
    // Protocol-family substates — each groups its fields with its own
    // reset_window/check_* methods for locality and independent testability.
    pub dante: DanteState,
    pub ndi:   NdiState,
    pub igmp:  IgmpState,
    pub avb:   AvbState,
    pub ptp:   PtpState,
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
    // Consecutive report cycles where ConMon is active but no mDNS/PTP/streams seen.
    // Resets to 0 when the condition clears.
    pub filter_unregistered_suspect_cycles: u32,
    // Multicast byte count for the current 5s window (for 80 Mbps threshold check).
    pub multicast_bytes_this_window: u64,
    // Rolling history of total stream counts (RTP + TCP + AVTP) at the end of
    // each 5s window, used to detect sudden flood-style anomalies. Capped at 3
    // entries; the oldest is dropped when a fourth would be added.
    stream_count_history: Vec<usize>,
    // IPv4 addresses of the capture interface itself — excluded from device
    // discovery so the tool doesn't report itself as a Dante/NDI device.
    pub local_ips: HashSet<Ipv4Addr>,
    // Set when both a PTP clock is lost AND a stream in the affected protocol
    // family has packet loss in the same 5 s window. Suppresses the individual
    // "no clock" and per-stream loss alerts so the combined dropout alert dominates.
    pub clock_dropout_correlated: bool,
}

impl Default for CaptureState {
    fn default() -> Self { Self::new() }
}

impl CaptureState {
    /// Upper bound on cached SDP sessions. `sdp_cache` is keyed by the SAP-supplied
    /// session ID string (attacker-controlled) and is not otherwise pruned, so this
    /// caps it against a flood of unique-ID announcements. Well above any real
    /// deployment's session count.
    pub const MAX_SDP_SESSIONS: usize = 1024;

    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            tcp_streams: HashMap::new(),
            sdp_cache: HashMap::new(),
            network_health: NetworkHealth::new(),
            dante: DanteState::new(),
            ndi:   NdiState::new(),
            igmp:  IgmpState::new(),
            avb:   AvbState::new(),
            ptp:   PtpState::new(),
            eee_ports: HashMap::new(),
            bytes_this_window: 0,
            pause_frames_this_window: 0,
            pfc_frames_this_window:   0,
            packets_dispatched: 0,
            pending_join_groups: Vec::new(),
            joined_multicast:    HashSet::new(),
            filter_unregistered_suspect_cycles: 0,
            multicast_bytes_this_window: 0,
            stream_count_history: Vec::new(),
            local_ips:           HashSet::new(),
            clock_dropout_correlated: false,
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
        // Window-scoped like ECN: a retransmission burst docks the score for this
        // window only, then recovers. Leaving it cumulative permanently docked.
        self.network_health.tcp_retransmissions = 0;
        for s in self.streams.values_mut() {
            s.gap_events      = 0;
            s.max_iat_ms      = 0.0;
            s.pt_mismatches   = 0;
            s.dscp_violations = 0;
            s.pcp_violations  = 0;
            s.ssrc_changes    = 0;
            s.lost_this_window               = 0;
            s.ts_discontinuities_this_window = 0;
            s.reorders_this_window           = 0;
            s.packets_this_window            = 0;
        }
        self.streams.retain(|_, s| {
            s.last_packet_time
                .is_none_or(|t| t.elapsed().as_secs() < STREAM_PRUNE_SECS)
        });
        self.tcp_streams.retain(|_, s| {
            s.last_seen.elapsed().as_secs() < STREAM_PRUNE_SECS
                && !matches!(s.stream_quality, StreamQuality::Terminated)
        });
        // AVB substate: AVTP prune + dependent MSRP/MVRP/AVDECC pruning.
        self.avb.reset_window();
        // PTP substate: clear per-window Sync sender census + prune stale
        // followers. Must happen AFTER check_ptp_sync_conflict() (called by
        // main.rs before reset_window).
        self.ptp.reset_window();
        // Dante substate: ConMon pruning + unverified-windows update.
        // Must run after check_conmon_bridge / check_follower_census (they read
        // the pre-reset data) and before the next capture window begins.
        self.dante.reset_window(&self.streams);
        // IGMP substate: per-window querier/report reset + Join-dedup pruning.
        // Must run AFTER check_multiple_queriers() (which reads
        // querier_ips_this_window). The network_health flag is reset here
        // because it lives on NetworkHealth, not IgmpState.
        self.igmp.reset_window();
        self.network_health.multiple_queriers_this_window = false;
        self.multicast_bytes_this_window = 0;
        self.clock_dropout_correlated = false;
    }

    // ── Handlers ────────────────────────────────────────────────────────────

    /// Queue `group` for dynamic IGMP join if it's a candidate stream multicast
    /// address (239.x.x.x) not already joined. The single seam for this guard —
    /// previously hand-copied in `handle_sap` and `handle_igmp`'s
    /// `MembershipReportV3` arm, which risked the two diverging on what counts
    /// as a joinable group.
    pub fn queue_multicast_join(&mut self, group: Ipv4Addr) {
        if group.octets()[0] == 239 && !self.joined_multicast.contains(&group) {
            self.pending_join_groups.push(group);
        }
    }

    /// SAP/SDP: cache the SDP and retroactively enrich any existing stream
    /// whose port matches an announced media — see `StreamStats::apply_sdp`
    /// for the field-transfer rules.
    pub fn handle_sap(&mut self, sdp: SdpSession) {
        // Enrich EVERY stream this announcement matches — not just the first. When
        // the media carries a connection IP, require the stream's destination group
        // to match it, so two streams sharing a port (different multicast groups)
        // each get their own session's SDP rather than whichever the map yields
        // first. Port-only fallback when no connection IP is present.
        for m in &sdp.media {
            let conn_ip = m.connection_ip();
            for stats in self.streams.values_mut() {
                if stats.dst_port == m.port
                    && conn_ip.is_none_or(|ip| stats.dst_ip == Some(ip))
                {
                    stats.apply_sdp(m, &sdp.session_name);
                }
            }
        }
        // Queue any multicast stream addresses for dynamic IGMP joining.
        for m in &sdp.media {
            if let Some(ip) = m.connection_ip() {
                self.queue_multicast_join(ip);
            }
        }
        self.cache_sdp(sdp);
    }

    /// Insert an SDP session into `sdp_cache`, keeping it bounded against a flood of
    /// SAP announcements with unique (attacker-controlled) session IDs. When at
    /// capacity and the session is new, evict a **stale** session first — one whose
    /// media ports have no active stream — falling back to an arbitrary entry if all
    /// cached sessions are still live.
    fn cache_sdp(&mut self, sdp: SdpSession) {
        if !self.sdp_cache.contains_key(&sdp.session_id)
            && self.sdp_cache.len() >= Self::MAX_SDP_SESSIONS
        {
            let streams = &self.streams;
            let victim = self.sdp_cache.iter()
                .find(|(_, s)| !s.media.iter().any(|m|
                    streams.values().any(|st| st.dst_port == m.port && st.packets > 0)))
                .map(|(k, _)| k.clone())
                .or_else(|| self.sdp_cache.keys().next().cloned());
            if let Some(k) = victim { self.sdp_cache.remove(&k); }
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
            if self.avb.avdecc_entities.remove(&adp.entity_id).is_some() {
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
        let entry = self.avb.avdecc_entities.get(&adp.entity_id);

        let is_new     = entry.is_none();
        let state_changed = entry.is_some_and(|e| e.available_index != adp.available_index);

        self.avb.avdecc_entities.insert(adp.entity_id, AvdeccEntity {
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
        // PTPv1 Delay_Req (msg 0x01) — sender is a clock follower.
        if info.version == crate::protocols::PTP_VERSION_V1
            && info.message_type == 0x01
            && let Some(ip) = info.src_ip
        {
            self.ptp.v1_followers.insert(ip, Instant::now());
        }

        let kind   = info.protocol_kind.clone();
        let src_ip = info.src_ip;
        let stats  = self.ptp.domains
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

    /// Find the cached Session Announcement (if any) whose media matches a
    /// destination port, paired with its session name. Used at stream creation
    /// to enrich a stream whose SDP was already announced before the first
    /// packet arrived — see `StreamStats::apply_sdp` for what gets transferred.
    fn find_sdp_media(&self, dst: Ipv4Addr, port: u16) -> Option<(&str, &SdpMedia)> {
        self.sdp_cache.values()
            .find_map(|s| s.media.iter()
                .find(|m| m.port == port && m.connection_ip().is_none_or(|ip| ip == dst))
                .map(|m| (s.session_name.as_str(), m)))
    }

    /// AES67 RTP audio.
    pub fn handle_aes67(&mut self, dst: Ipv4Addr, dst_port: u16, payload_type: u8, l2_payload: &[u8], pcp: Option<u8>) {
        let key = format!("AES67 {}:{}", dst, dst_port);
        let sdp_match = self.find_sdp_media(dst, dst_port).map(|(name, m)| (name.to_string(), m.clone()));
        let stats = self.streams.entry(key).or_insert_with(|| {
            let mut s = StreamStats::new_with_info("AES67", DEFAULT_CLOCK_HZ, is_aes67_multicast(dst), dst, dst_port);
            s.media_type = "audio".to_string();
            s.channels = 1;
            if let Some((name, media)) = &sdp_match {
                s.apply_sdp(media, name);
            }
            s
        });
        if let Some(ip) = pnet_packet::ipv4::Ipv4Packet::new(l2_payload)
            && let Some(udp) = pnet_packet::udp::UdpPacket::new(ip.payload())
        {
            // AES67 requires DSCP EF (46) per spec
            if ip.get_dscp() != 46 { stats.dscp_violations += 1; }
            self.network_health.record_ecn_mark_if_congested(ip.get_ecn());
            stats.apply_pcp_advisory(pcp);
            if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) {
                if stats.expected_pt.is_some_and(|exp| payload_type != exp) {
                    stats.pt_mismatches += 1;
                }
                stats.update(seq, ts, ssrc, udp.payload().len());
            }
        }
    }

    /// ST 2110 video/audio/ancillary.
    pub fn handle_st2110(&mut self, dst: Ipv4Addr, dst_port: u16, stream_type: St2110Type, l2_payload: &[u8], pcp: Option<u8>) {
        let label = match stream_type {
            St2110Type::Video   => "2110-20",
            St2110Type::Audio   => "2110-30",
            St2110Type::Ancdata => "2110-40",
            St2110Type::Unknown => "2110-??",
        };
        let key = format!("ST {} {}:{}", label, dst, dst_port);
        let default_clock = if matches!(stream_type, St2110Type::Video) { 90_000.0 } else { DEFAULT_CLOCK_HZ };
        let sdp_match = self.find_sdp_media(dst, dst_port).map(|(name, m)| (name.to_string(), m.clone()));
        let stats = self.streams.entry(key).or_insert_with(|| {
            let mut s = StreamStats::new_with_info(label, default_clock, is_st2110_multicast(dst), dst, dst_port);
            s.media_type = match stream_type {
                St2110Type::Video => "video".to_string(),
                St2110Type::Audio => "audio".to_string(),
                St2110Type::Ancdata => "ancillary".to_string(),
                St2110Type::Unknown => "unknown".to_string(),
            };
            let confirmed = sdp_match.as_ref().is_some_and(|(name, media)| s.apply_sdp(media, name));
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
            self.network_health.record_ecn_mark_if_congested(ip.get_ecn());
            stats.apply_pcp_advisory(pcp);
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
                if self.local_ips.contains(&src) { return vec![]; }
                let is_new = self.dante.record_source(src, device_name.as_deref());
                if let Some(ref name) = device_name {
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
                if self.local_ips.contains(&src) { return vec![]; }
                let _is_new = !self.dante.conmon.contains_key(&src);
                let entry = self.dante.conmon.entry(src).or_insert_with(|| ConmonDevice {
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
                self.dante.record_source(src, None);
                // The "Audinate" ConMon signature is a positive Hardware tell.
                self.dante.record_tx_class(src, TransmitterClass::Hardware);
                vec![]
            }
            DanteKind::ControlPlane { class } => {
                // Product-specific control-plane traffic positively identifies the
                // source's Transmitter Class. Proves a Dante device, like ConMon.
                if !self.local_ips.contains(&src) {
                    self.dante.record_source(src, None);
                    self.dante.record_tx_class(src, class);
                }
                vec![]
            }
            DanteKind::AudioStream => {
                let is_mc = crate::parser::is_multicast(dst);
                let cp_class = self.dante.transmitter_class.get(&src).copied();
                // Key on src AND dst: one device can transmit several flows from
                // the same source port to different destinations (e.g. multiple
                // multicast groups) — keying on src:port alone merged them,
                // interleaving their sequence numbers into false loss.
                let key = format!("Dante {} → {}:{}", src, dst, dst_port);
                let stats = self.streams.entry(key).or_insert_with(|| {
                    let mut s = StreamStats::new_with_info("Dante", DEFAULT_CLOCK_HZ, is_mc, dst, dst_port);
                    s.ptime_ms = 1.0; // Dante standard: 48 samples @ 48kHz = 1ms
                    s.src_ip = Some(src);
                    s.sdp_name = self.dante.names.get(&src).cloned();
                    s
                });
                let mut dscp_seen = None;
                if let Some(ip) = pnet_packet::ipv4::Ipv4Packet::new(l2_payload)
                    && let Some(udp) = pnet_packet::udp::UdpPacket::new(ip.payload())
                {
                    let dscp = ip.get_dscp();
                    if stats.observed_dscp.is_none() { stats.observed_dscp = Some(dscp); }
                    dscp_seen = Some(dscp);
                    self.network_health.record_ecn_mark_if_congested(ip.get_ecn());
                    // TTL routing check: Dante is L2-only; track minimum TTL so the
                    // report can alert when a router decremented it (TTL < 64 from a
                    // Linux/macOS source means ≥ 1 router hop — misconfiguration).
                    let ttl = ip.get_ttl();
                    stats.min_ttl = Some(stats.min_ttl.map_or(ttl, |m| m.min(ttl)));
                    match parse_rtp(udp.payload()) {
                        Some((seq, ts, ssrc)) => stats.update(seq, ts, ssrc, udp.payload().len()),
                        // ATP framing (official ports 4321 / 14336–15359) is not RTP —
                        // track presence and bitrate; loss/jitter need RTP fields.
                        None => stats.update_non_rtp(udp.payload().len(), now),
                    }
                }
                // Transmitter Class verdict — recomputed each packet so an early
                // inference upgrades to a confirmed verdict as signals accumulate.
                let signals = crate::protocols::TransmitterSignals {
                    control_plane: cp_class,
                    metronomic: stats.timing_metronomic(),
                    ttl: stats.min_ttl, // TTL 128 → Windows host → software (corroborating)
                    dscp_zero: stats.observed_dscp == Some(0),
                };
                stats.transmitter = classify_transmitter(&signals);

                if let Some(dscp) = dscp_seen {
                    // Dante hardware audio requires DSCP EF (46). DVS/Via intentionally
                    // send Best Effort (DSCP 0), so DSCP 0 is NOT a violation for a
                    // software source — see `is_software_ignoring_dscp` for why the
                    // gate can't just reuse `stats.transmitter` above.
                    let software = crate::protocols::is_software_ignoring_dscp(&signals);
                    if dscp != 46 && !(dscp == 0 && software) {
                        stats.dscp_violations += 1;
                    }
                }
                vec![]
            }
        }
    }

    /// NDI mDNS discovery — registers the source IP and emits a discovery line.
    pub fn handle_ndi_discovery(&mut self, src: Ipv4Addr, source_name: Option<String>) -> Vec<Alert> {
        if self.local_ips.contains(&src) { return vec![]; }
        self.ndi.record_source(src, source_name.as_deref());
        let label = source_name.as_deref().unwrap_or("unknown source");
        vec![Alert::info(format!("🔍 NDI source: {}  \"{}\"", src, label))]
    }

    /// Any TCP segment — NDI is the only protocol carried over TCP. Narrows to
    /// NDI here (port range, or a source/dest IP already known from mDNS) rather
    /// than in `detect_protocol`, which stays a stateless decode. No-ops for any
    /// TCP traffic that isn't NDI-relevant. Maintains two things every report
    /// window reads: the per-connection quality/retransmission state in
    /// `tcp_streams`, and the `"NDI {ip}"` entry in `streams` (packet count +
    /// liveness) that `aggregate_ndi_bitrate` later sums `tcp_streams` bitrate into.
    pub fn handle_tcp(&mut self, segment: crate::protocols::TcpSegment, frame_bytes: u64, now: Instant) {
        let crate::protocols::TcpSegment { src, dst, src_port, dst_port, seq, ack, has_fin, has_syn, has_rst } = segment;
        let ndi_range = crate::protocols::NDI_PORT_MIN..=crate::protocols::NDI_PORT_MAX;
        let is_ndi = ndi_range.contains(&src_port) || ndi_range.contains(&dst_port)
            || self.ndi.sources.contains(&src) || self.ndi.sources.contains(&dst);
        if !is_ndi { return; }

        let sender = if self.ndi.sources.contains(&src) { Some(src) }
                     else if self.ndi.sources.contains(&dst) { Some(dst) }
                     else { None };
        if let Some(sender_ip) = sender {
            let names = &self.ndi.names;
            let stats = self.streams.entry(format!("NDI {}", sender_ip))
                .or_insert_with(|| {
                    let mut s = StreamStats::new_with_info("NDI", 0.0, false, sender_ip, 0);
                    s.sdp_name = names.get(&sender_ip).cloned();
                    s
                });
            stats.packets += 1;
            stats.last_packet_time = Some(now);
        }

        let key = format!("TCP {}:{} → {}:{}", src, src_port, dst, dst_port);
        let tcp_stat = self.tcp_streams.entry(key)
            .or_insert_with(|| crate::stats::TcpStreamStats::new(src, dst));
        tcp_stat.packets += 1;
        tcp_stat.last_seen = now;
        let estimated_payload = frame_bytes.saturating_sub(40);
        tcp_stat.bytes += estimated_payload;
        if has_fin { tcp_stat.fin_packets += 1; }
        if has_rst {
            tcp_stat.rst_packets += 1;
            self.network_health.tcp_retransmissions += 1;
        }
        if !has_syn
            && let Some(last_seq) = tcp_stat.last_seq
            && (seq.wrapping_sub(last_seq) as i32) < 0
            && tcp_stat.packets > 2
        {
            tcp_stat.retransmissions += 1;
            self.network_health.tcp_retransmissions += 1;
        }
        if let Some(last_seq) = tcp_stat.last_seq {
            if (seq.wrapping_sub(last_seq) as i32) > 0 { tcp_stat.last_seq = Some(seq); }
        } else {
            tcp_stat.last_seq = Some(seq);
        }
        tcp_stat.last_ack = Some(ack);
        tcp_stat.update_bitrate();
        tcp_stat.update_quality();
    }

    /// AVB AVTP frame — updates the per-subtype aggregate stream and per-stream_id entry.
    pub fn handle_avb(&mut self, subtype: u8, stream_id: Option<[u8; 8]>, frame_bytes: u64, avtp_seq: Option<u8>, pcp: Option<u8>, now: Instant) {
        // sv=0 AVTP control/discovery frames (AVDECC ADP/ACMP, MAAP) carry no stream
        // id — they are not media streams. Skip them so they don't inflate the AVB
        // stream count, create a phantom dead-stream entry, or diverge from the
        // per-stream-id avtp_streams map the Streams list and clock gate both read.
        // (Their bytes still count toward bandwidth via bytes_this_window in main.rs.)
        let Some(sid) = stream_id else { return; };

        let entry = self.avb.avtp_streams.entry(sid)
            .or_insert_with(|| AvtpStreamStats::new(sid, subtype));
        entry.packets += 1;
        entry.last_seen = now;
        entry.update_bitrate(frame_bytes, now);
        if let Some(seq) = avtp_seq { entry.update_seq(seq); }

        // PCP mismatch: compare observed outermost VLAN tag PCP against the
        // priority declared in the MSRP TalkerAdvertise for this stream_id.
        // Only fires when both values are known and they differ; untagged frames
        // (pcp = None) produce no alert. Tracked per stream_id on AvtpStreamStats
        // itself — never on a subtype-label-keyed aggregate, so two distinct
        // stream_ids sharing a subtype can't corrupt each other's PCP state.
        if let Some(observed) = pcp
            && let Some(declared) = self.avb.msrp_state.get(&sid).and_then(|d| d.priority)
            && observed != declared
        {
            entry.pcp_violations += 1;
            entry.observed_pcp.get_or_insert(observed);
            entry.msrp_declared_pcp = Some(declared);
        }
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
            self.avb.msrp_state.insert(decl.stream_id, decl);
        }
        alerts
    }

    /// MVRP — registers VLANs, emits one info line per newly-seen VLAN.
    pub fn handle_mvrp(&mut self, vlan_ids: Vec<u16>) -> Vec<Alert> {
        let mut alerts = Vec::new();
        for vid in vlan_ids {
            if self.avb.mvrp_vlans.insert(vid) {
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
    pub fn handle_igmp(&mut self, src: Ipv4Addr, src_mac: [u8; 6], group: Ipv4Addr, igmp_type: IgmpType, now: Instant) -> Vec<Alert> {
        let mut alerts = Vec::new();
        match igmp_type {
            IgmpType::Join => {
                let first_time = !self.igmp.joins_seen.contains_key(&(src, group));
                self.igmp.joins_seen.insert((src, group), now);
                if first_time {
                    alerts.push(Alert::info(format!("➕ IGMP Join: {} → group {}", src, group)));
                }
            }
            IgmpType::Leave => {
                self.igmp.joins_seen.remove(&(src, group));
                alerts.push(Alert::info(format!("➖ IGMP Leave: {} → group {}", src, group)));
                if self.streams.values().any(|s| s.dst_ip == Some(group)) {
                    alerts.push(Alert::warn(format!("    ⚠  IGMP Leave on monitored group {}", group)));
                }
            }
            IgmpType::MembershipReportV3 { groups } => {
                // Queue new 239.x.x.x groups for dynamic joining so IGMP-snooping
                // switches deliver those streams to our capture port.
                for group in groups {
                    self.queue_multicast_join(group);
                }
                self.igmp.v3_report_seen_this_window = true;
                // No console output — infrastructure detail, not user-visible.
            }
            IgmpType::Query { version } => {
                // Only a General Query (dst = all-systems 224.0.0.1) establishes the
                // querier. A Group-Specific Query (dst = the group) is membership
                // verification — IGMP-snooping switches commonly source these from
                // 0.0.0.0 (RFC 4541), which must NOT register as a second querier or
                // reset the interval/silence timers. See [[IGMP_ALL_SYSTEMS]].
                let is_general_query = group == crate::protocols::IGMP_ALL_SYSTEMS;
                if is_general_query {
                    // Track interval between consecutive General Queries (RFC 3376 default 125s).
                    if let Some(last) = self.network_health.last_igmp_query {
                        self.network_health.igmp_query_interval_secs = Some(last.elapsed().as_secs());
                    }
                    self.network_health.last_igmp_query = Some(now);
                    self.network_health.igmp_querier_ip = Some(src);
                    self.network_health.igmp_querier_mac = Some(src_mac);
                    self.igmp.querier_ips_this_window.insert(src);
                    // Track querier version for v2/v3 mismatch detection.
                    self.igmp.querier_version = Some(version);
                    alerts.push(Alert::info(format!("❓ IGMP General Query (v{}): {}", version, src)));
                } else {
                    alerts.push(Alert::info(format!(
                        "❓ IGMP Group-Specific Query (v{}): {} → group {}", version, src, group)));
                }
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

    /// True when at least one multicast stream has carried traffic. Mirrors the
    /// `has_multicast` predicate in `NetworkHealth::collect_penalties` so the
    /// IGMP querier checks (absent / multiple) share one definition of "multicast
    /// is actually in use here."
    pub fn has_active_multicast(&self) -> bool {
        self.streams.values().any(|s| s.is_multicast && s.packets > 0)
    }

    /// Advisory when the IGMP query interval exceeds Audinate's recommended 30s.
    /// Longer intervals slow multicast convergence after a device join.
    /// Only fires once the interval has been measured (two consecutive queries seen).
    pub fn check_igmp_query_interval(&self) -> Vec<Alert> {
        if let Some(interval) = self.network_health.igmp_query_interval_secs
            && interval > 60
        {
            return vec![Alert::info(format!(
                "ℹ IGMP query interval {}s — Audinate recommends 30s for Dante networks; longer intervals slow multicast convergence after device join",
                interval,
            ))];
        }
        vec![]
    }

    /// Alert when ConMon (link-local, always-visible) shows live Dante devices but no
    /// mDNS, PTP, or audio streams are visible — the fingerprint of a switch with
    /// "Filter Unregistered Multicast" (or "Block Unknown Multicast") enabled, which
    /// drops non-link-local multicast while link-local `224.0.0.x` still floods.
    /// Fires after ≥2 consecutive cycles with this condition to avoid false positives
    /// on startup before mDNS/PTP traffic has arrived.
    pub fn check_filter_unregistered_multicast(&mut self) -> Vec<Alert> {
        let conmon_active = !self.dante.conmon.is_empty();
        let no_mdns       = self.dante.names.is_empty();
        let no_ptp        = self.ptp.domains.values().all(|p| p.packets == 0);
        let no_streams    = self.streams.is_empty() && self.avb.avtp_streams.is_empty();

        if conmon_active && no_mdns && no_ptp && no_streams {
            self.filter_unregistered_suspect_cycles += 1;
        } else {
            self.filter_unregistered_suspect_cycles = 0;
        }

        if self.filter_unregistered_suspect_cycles >= 2 {
            return vec![Alert::warn(
                "⚠ Dante devices detected via ConMon but no mDNS, PTP, or streams visible — check switch for \"Filter Unregistered Multicast\" or \"Block Unknown Multicast\" and disable it".to_string(),
            )];
        }
        vec![]
    }

    /// Alert when multicast bandwidth exceeds 80 Mbps without an IGMP querier.
    /// Audinate's threshold: networks above 80 Mbps of multicast traffic require
    /// IGMP snooping to prevent flooding; unmanaged switches are acceptable below it.
    pub fn check_high_multicast_bandwidth(&self) -> Vec<Alert> {
        let mbps = self.multicast_bytes_this_window as f64 * 8.0 / 5.0 / 1_000_000.0;
        if mbps > 80.0 && self.network_health.last_igmp_query.is_none() {
            return vec![Alert::warn(format!(
                "⚠ Multicast bandwidth {:.0} Mbps exceeds 80 Mbps threshold — IGMP snooping required at this traffic level; enable querier on the switch",
                mbps,
            ))];
        }
        vec![]
    }

    /// Alert when Dante devices are discovered via ConMon or mDNS but no PTP traffic
    /// has been seen and no IGMP querier is present — the classic symptom of a snooping
    /// switch blocking PTP multicast (224.0.1.129 / 224.0.0.107) because no host has
    /// joined those groups via IGMP. Not fired in offline mode (pcap can't join groups).
    pub fn check_igmp_snooping_blocking_ptp(&self, is_offline: bool) -> Vec<Alert> {
        if is_offline { return vec![]; }
        let has_dante_devices = !self.dante.sources.is_empty() || !self.dante.conmon.is_empty();
        if !has_dante_devices { return vec![]; }
        let has_ptp = self.ptp.domains.values().any(|p| p.packets > 0);
        if has_ptp { return vec![]; }
        if self.network_health.last_igmp_query.is_some() { return vec![]; }
        vec![Alert::warn(
            "⚠ Dante devices found but no PTP clock and no IGMP querier — a snooping switch may be blocking PTP multicast (224.0.1.129); enable IGMP querier on the switch".to_string(),
        )]
    }

    /// Stream-count anomaly detection, called from the periodic report cycle
    /// **before** `reset_window` so the count reflects streams active this window.
    ///
    /// Fires when the current total stream count is more than 2× the rolling
    /// average of the last 3 windows — the fingerprint of a runaway device
    /// flooding new multicast groups. Requires a full 3-window baseline before
    /// alerting so normal startup growth doesn't trigger a false positive.
    pub fn check_stream_count_anomaly(&mut self) -> Vec<Alert> {
        let current = self.streams.len() + self.tcp_streams.len() + self.avb.avtp_streams.len();

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
        let ptpv2_streams: Vec<&str> = self.streams.values()
            .filter(|s| stream_clock_kind(&s.protocol) == Some(MissingClockKind::Ptpv2))
            .map(|s| s.protocol.as_str())
            .collect();
        let aes67_active  = expanded.iter().any(|c| matches!(c, ProtocolChoice::AES67))
            && ptpv2_streams.contains(&"AES67");
        let st2110_active = expanded.iter().any(|c| matches!(c, ProtocolChoice::ST2110))
            && ptpv2_streams.iter().any(|p| *p != "AES67");
        let has_ptpv2 = self.ptp.domains.values().any(|s|
            s.clock_valid && s.version == PTP_VERSION_V2 && s.is_ip_ptp_domain());
        if (aes67_active || st2110_active) && !has_ptpv2 {
            let mut affected = Vec::new();
            if aes67_active  { affected.push("AES67"); }
            if st2110_active { affected.push("ST2110"); }
            missing.push(MissingClock { kind: MissingClockKind::Ptpv2, affected });
        }

        // ── PTPv1 or PTPv2 (Dante) ───────────────────────────────────────────
        let dante_active = expanded.iter().any(|c| matches!(c, ProtocolChoice::Dante))
            && self.streams.values().any(|s| stream_clock_kind(&s.protocol) == Some(MissingClockKind::Ptp));
        // Dante needs PTPv1/PTPv2 on the IP network — an L2 gPTP (AVB) clock does
        // not satisfy it, so exclude AVB domains just like the PTPv2 check above.
        let has_ptp = self.ptp.domains.values().any(|s| s.clock_valid && s.is_ip_ptp_domain());
        if dante_active && !has_ptp {
            missing.push(MissingClock { kind: MissingClockKind::Ptp, affected: vec!["Dante"] });
        }

        // ── L2 gPTP (AVB) ────────────────────────────────────────────────────
        let avb_active = expanded.iter().any(|c| matches!(c, ProtocolChoice::AVB))
            && !self.avb.avtp_streams.is_empty();
        let has_gptp = self.ptp.domains.values().any(|s| s.clock_valid && s.is_gptp_domain());
        if avb_active && !has_gptp {
            missing.push(MissingClock { kind: MissingClockKind::Gptp, affected: vec!["AVB"] });
        }

        missing
    }

    /// When a PTP clock is confirmed lost AND at least one stream in the affected
    /// protocol family has packet loss in the same 5 s window, return a single
    /// combined alert. The caller suppresses the individual clock-lost and
    /// per-stream loss alerts so this combined alert dominates.
    ///
    /// Call AFTER `ptp.check_ptp_timeouts()` so `protocol_clock_lost` reflects
    /// the current window's state.
    pub fn check_clock_dropout_correlation(&self) -> Option<Alert> {
        let ptpv1_lost = self.ptp.domains.values().any(|s|
            s.protocol_clock_lost && s.version == PTP_VERSION_V1 && s.is_ip_ptp_domain());
        let ptpv2_lost = self.ptp.domains.values().any(|s|
            s.protocol_clock_lost && s.version == PTP_VERSION_V2 && s.is_ip_ptp_domain());

        if !ptpv1_lost && !ptpv2_lost {
            return None;
        }

        let stream_loss = self.streams.values().any(|s| {
            s.lost_this_window > 0 && (
                (ptpv1_lost && stream_clock_kind(&s.protocol) == Some(MissingClockKind::Ptp))
                || (ptpv2_lost && stream_clock_kind(&s.protocol) == Some(MissingClockKind::Ptpv2))
            )
        });

        if stream_loss {
            Some(Alert::error(
                "❌ Clock sync failure — audio dropouts likely (PTP lost + stream loss detected)"
                    .to_string(),
            ))
        } else {
            None
        }
    }

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
    pcp: Option<u8>,
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
            state.handle_aes67(dst, dst_port, payload_type, l2_payload, pcp);
            vec![]
        }
        AvProtocol::St2110 { dst, dst_port, stream_type, .. } => {
            state.handle_st2110(dst, dst_port, stream_type, l2_payload, pcp);
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
            state.handle_avb(subtype, stream_id, frame_bytes, seq, pcp, now);
            vec![]
        }
        AvProtocol::Msrp { declarations } => state.handle_msrp(declarations),
        AvProtocol::Mvrp { vlan_ids }     => state.handle_mvrp(vlan_ids),
        AvProtocol::LldpEee { chassis_id, port_id, tx_wake_us, rx_wake_us } => {
            state.handle_lldp_eee(chassis_id, port_id, tx_wake_us, rx_wake_us)
        }
        AvProtocol::Igmp { src, src_mac, group, igmp_type } => {
            state.handle_igmp(src, src_mac, group, igmp_type, now)
        }
        AvProtocol::FlowControl { kind } => {
            state.handle_flow_control(kind);
            vec![]
        }
        AvProtocol::Tcp(segment) => {
            state.handle_tcp(segment, frame_bytes, now);
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

    /// Insert one active multicast stream so `state.has_active_multicast()` is
    /// true — required for the IGMP querier checks (absent / multiple) to engage.
    fn add_active_multicast_stream(state: &mut CaptureState) {
        let mut s = StreamStats::new_with_info(
            "AES67", 48_000.0, true, Ipv4Addr::new(239, 69, 0, 1), 5004);
        s.packets = 1;
        state.streams.insert("AES67 test-mc".to_string(), s);
    }

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
        state.handle_aes67(Ipv4Addr::new(239, 69, 0, 1), 5004, 96, &pkt, None);
        let s = state.streams.get("AES67 239.69.0.1:5004").expect("stream created");
        assert_eq!(s.expected_pt, Some(96));
        assert!(s.clock_hz_confirmed, "SAP-confirmed clock should flip the flag");
        assert_eq!(s.sdp_rtpmap.as_deref(), Some("L24/48000/2"));
        // Previously missing from the AES67 lazy-enrichment closure — a stream
        // created after its SDP was already cached got no ptime_ms/channels/name
        // until the next re-announcement. apply_sdp closes that gap.
        assert_eq!(s.ptime_ms, 1.0);
        assert_eq!(s.channels, 2);
        assert_eq!(s.sdp_name.as_deref(), Some("Test Mix"));
    }

    #[test]
    fn sap_enriches_each_stream_by_its_connection_group_not_just_the_first() {
        // Two AES67 streams share dst port 5004 but belong to different multicast
        // groups, each announced by its own SAP session. Every stream must receive
        // its OWN session's SDP; the old code enriched only the first stream that
        // matched the port (then `break`) and left the rest nameless.
        let mut state = CaptureState::new();
        let group_a = Ipv4Addr::new(239, 69, 0, 1);
        let group_b = Ipv4Addr::new(239, 69, 0, 2);
        state.streams.insert("AES67 a".into(),
            StreamStats::new_with_info("AES67", 48_000.0, true, group_a, 5004));
        state.streams.insert("AES67 b".into(),
            StreamStats::new_with_info("AES67", 48_000.0, true, group_b, 5004));

        let mut sa = sdp_for_port(5004, 96, 48_000.0);
        sa.session_id = "A".into();
        sa.session_name = "Group A Mix".into();
        sa.media[0].connection = "IN IP4 239.69.0.1".into();
        state.handle_sap(sa);

        let mut sb = sdp_for_port(5004, 96, 48_000.0);
        sb.session_id = "B".into();
        sb.session_name = "Group B Mix".into();
        sb.media[0].connection = "IN IP4 239.69.0.2".into();
        state.handle_sap(sb);

        assert_eq!(state.streams["AES67 a"].sdp_name.as_deref(), Some("Group A Mix"));
        assert_eq!(state.streams["AES67 b"].sdp_name.as_deref(), Some("Group B Mix"));
    }

    // ── queue_multicast_join — single seam for the dynamic-IGMP-join guard ────
    // Previously hand-copied identically in handle_sap and handle_igmp's
    // MembershipReportV3 arm; see CLAUDE.md's documented DSCP/PCP divergence bugs
    // for why a duplicated guard like this is worth naming instead of repeating.

    #[test]
    fn queue_multicast_join_queues_new_239_group() {
        let mut state = CaptureState::new();
        let group = Ipv4Addr::new(239, 1, 2, 3);
        state.queue_multicast_join(group);
        assert_eq!(state.pending_join_groups, vec![group]);
    }

    #[test]
    fn queue_multicast_join_skips_already_joined_group() {
        let mut state = CaptureState::new();
        let group = Ipv4Addr::new(239, 1, 2, 3);
        state.joined_multicast.insert(group);
        state.queue_multicast_join(group);
        assert!(state.pending_join_groups.is_empty());
    }

    #[test]
    fn queue_multicast_join_skips_non_239_group() {
        let mut state = CaptureState::new();
        state.queue_multicast_join(Ipv4Addr::new(224, 0, 0, 1));
        assert!(state.pending_join_groups.is_empty());
    }

    #[test]
    fn handle_sap_queues_multicast_connection_ip_via_queue_multicast_join() {
        let mut state = CaptureState::new();
        let mut sdp = sdp_for_port(5004, 96, 48_000.0);
        sdp.media[0].connection = "IN IP4 239.69.0.1".into();
        state.handle_sap(sdp);
        assert_eq!(state.pending_join_groups, vec![Ipv4Addr::new(239, 69, 0, 1)]);
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
        state.handle_aes67(Ipv4Addr::new(239, 69, 0, 1), 5004, 96, &pkt, None);
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
        state.handle_aes67(Ipv4Addr::new(239, 69, 0, 1), 5004, 96, &pkt, None);
        let s = &state.streams["AES67 239.69.0.1:5004"];
        assert_eq!(s.dscp_violations, 1);
    }

    #[test]
    fn aes67_dscp_ef_does_not_violate() {
        let mut state = CaptureState::new();
        let pkt = ip_udp_rtp(46 << 2, 5004, 96, 0, 0, 0xAAAA);
        state.handle_aes67(Ipv4Addr::new(239, 69, 0, 1), 5004, 96, &pkt, None);
        let s = &state.streams["AES67 239.69.0.1:5004"];
        assert_eq!(s.dscp_violations, 0);
    }

    #[test]
    fn aes67_pt_mismatch_counted_when_expected_pt_set() {
        let mut state = CaptureState::new();
        state.sdp_cache.insert("1".to_string(), sdp_for_port(5004, 10, 48_000.0));
        // First packet establishes the stream with expected_pt=10
        let pkt0 = ip_udp_rtp(46 << 2, 5004, 11, 0, 0, 0xAAAA); // arrives with PT=11
        state.handle_aes67(Ipv4Addr::new(239, 69, 0, 1), 5004, 11, &pkt0, None);
        let s = &state.streams["AES67 239.69.0.1:5004"];
        assert_eq!(s.pt_mismatches, 1);
        assert_eq!(s.expected_pt, Some(10));
    }

    #[test]
    fn aes67_ecn_ce_increments_network_health() {
        let mut state = CaptureState::new();
        let pkt = ip_udp_rtp((46 << 2) | 0b11, 5004, 96, 0, 0, 0xAAAA); // ECN=3 (CE)
        state.handle_aes67(Ipv4Addr::new(239, 69, 0, 1), 5004, 96, &pkt, None);
        assert_eq!(state.network_health.ecn_congestion_marks, 1);
    }

    // ── ST 2110 ──────────────────────────────────────────────────────────────

    #[test]
    fn st2110_video_dscp_cs5_accepted() {
        let mut state = CaptureState::new();
        // CS5 = 40
        let pkt = ip_udp_rtp(40 << 2, 5004, 96, 0, 0, 0xAAAA);
        state.handle_st2110(Ipv4Addr::new(239, 1, 2, 3), 5004, St2110Type::Video, &pkt, None);
        let s = state.streams.values().find(|s| s.protocol == "2110-20").expect("video stream");
        assert_eq!(s.dscp_violations, 0, "CS5 is valid for ST2110-20 video");
    }

    #[test]
    fn st2110_audio_dscp_cs5_rejected() {
        let mut state = CaptureState::new();
        let pkt = ip_udp_rtp(40 << 2, 5004, 96, 0, 0, 0xAAAA);
        state.handle_st2110(Ipv4Addr::new(239, 1, 2, 3), 5004, St2110Type::Audio, &pkt, None);
        let s = state.streams.values().find(|s| s.protocol == "2110-30").expect("audio stream");
        assert_eq!(s.dscp_violations, 1, "audio requires EF only");
    }

    #[test]
    fn st2110_video_clock_confirmed_without_sdp() {
        let mut state = CaptureState::new();
        let pkt = ip_udp_rtp(46 << 2, 5004, 96, 0, 0, 0xAAAA);
        state.handle_st2110(Ipv4Addr::new(239, 1, 2, 3), 5004, St2110Type::Video, &pkt, None);
        let s = state.streams.values().find(|s| s.protocol == "2110-20").unwrap();
        assert!(s.clock_hz_confirmed, "video uses 90 kHz by spec, no SDP needed");
    }

    #[test]
    fn st2110_audio_new_stream_inherits_sdp_when_present() {
        // Previously missing from the ST2110 lazy-enrichment closure — channels
        // wasn't transferred at all, and ptime_ms/name only arrived on the next
        // re-announcement. apply_sdp closes that gap, same as for AES67.
        let mut state = CaptureState::new();
        state.sdp_cache.insert("1".to_string(), sdp_for_port(5004, 96, 48_000.0));
        let pkt = ip_udp_rtp(46 << 2, 5004, 96, 0, 0, 0xAAAA);
        state.handle_st2110(Ipv4Addr::new(239, 1, 2, 3), 5004, St2110Type::Audio, &pkt, None);
        let s = state.streams.values().find(|s| s.protocol == "2110-30").unwrap();
        assert_eq!(s.channels, 2);
        assert_eq!(s.ptime_ms, 1.0);
        assert_eq!(s.sdp_name.as_deref(), Some("Test Mix"));
        assert!(s.clock_hz_confirmed);
    }

    // ── Dante ────────────────────────────────────────────────────────────────

    #[test]
    fn dante_audio_stream_picks_up_name_from_mdns_cache() {
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(192, 168, 1, 50);
        state.dante.names.insert(src, "Stage Box".to_string());
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
    fn control_plane_dvs_sets_confirmed_verdict_on_audio_flow() {
        use crate::protocols::{TransmitterClass, TransmitterConfidence};
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(192, 168, 1, 80);
        // DVS control-plane traffic observed → source recorded as DVS.
        state.handle_dante(
            DanteKind::ControlPlane { class: TransmitterClass::Dvs },
            src, Ipv4Addr::new(192,168,1,81), 38700, &[], Instant::now(),
        );
        assert_eq!(state.dante.transmitter_class.get(&src), Some(&TransmitterClass::Dvs));
        assert!(state.dante.sources.contains(&src));
        // An audio flow from that source now carries a confirmed DVS verdict.
        state.handle_dante(DanteKind::AudioStream, src, Ipv4Addr::new(239,255,1,1), 4321, &[], Instant::now());
        let v = state.streams.values()
            .find(|s| s.src_ip == Some(src)).unwrap()
            .transmitter.unwrap();
        assert_eq!(v.class, TransmitterClass::Dvs);
        assert_eq!(v.confidence, TransmitterConfidence::Confirmed);
    }

    #[test]
    fn conmon_records_hardware_and_dvs_overrides_it() {
        use crate::protocols::TransmitterClass;
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(192, 168, 1, 82);
        // ConMon Audinate signature → Hardware.
        state.handle_dante(
            DanteKind::ConMon { device_mac: [0,1,2,3,4,5], channels: None },
            src, Ipv4Addr::new(224,0,0,232), 8705, &[], Instant::now(),
        );
        assert_eq!(state.dante.transmitter_class.get(&src), Some(&TransmitterClass::Hardware));
        // A later DVS control-plane signal is more specific and overrides Hardware.
        state.handle_dante(
            DanteKind::ControlPlane { class: TransmitterClass::Dvs },
            src, Ipv4Addr::new(192,168,1,83), 38800, &[], Instant::now(),
        );
        assert_eq!(state.dante.transmitter_class.get(&src), Some(&TransmitterClass::Dvs),
            "DVS must override a prior Hardware verdict");
    }

    #[test]
    fn dvs_flow_at_dscp_zero_is_not_a_violation() {
        use crate::protocols::TransmitterClass;
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(192, 168, 1, 90);
        state.handle_dante(
            DanteKind::ControlPlane { class: TransmitterClass::Dvs },
            src, Ipv4Addr::new(192,168,1,91), 38700, &[], Instant::now(),
        );
        let pkt = ip_udp_rtp(0, 5004, 96, 0, 0, 1); // DSCP 0 (Best Effort)
        state.handle_dante(DanteKind::AudioStream, src, Ipv4Addr::new(239,255,1,1), 5004, &pkt, Instant::now());
        let s = state.streams.values().find(|s| s.src_ip == Some(src)).unwrap();
        assert_eq!(s.dscp_violations, 0, "DVS at DSCP 0 is expected, not a violation");
    }

    #[test]
    fn hardware_flow_at_dscp_zero_is_a_violation() {
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(192, 168, 1, 92);
        // ConMon Audinate signature → Hardware.
        state.handle_dante(
            DanteKind::ConMon { device_mac: [0,1,2,3,4,5], channels: None },
            src, Ipv4Addr::new(224,0,0,232), 8705, &[], Instant::now(),
        );
        let pkt = ip_udp_rtp(0, 5004, 96, 0, 0, 1); // DSCP 0 from hardware = misconfig
        state.handle_dante(DanteKind::AudioStream, src, Ipv4Addr::new(239,255,1,2), 5004, &pkt, Instant::now());
        let s = state.streams.values().find(|s| s.src_ip == Some(src)).unwrap();
        assert_eq!(s.dscp_violations, 1, "hardware at DSCP 0 is a genuine misconfiguration");
    }

    #[test]
    fn unclassified_flow_at_dscp_zero_still_violates() {
        // No control-plane and no timing evidence → software cannot be confirmed,
        // so DSCP 0 is still flagged. This is what stops DSCP 0 suppressing its own
        // violation (the gating class is derived without the DSCP signal).
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(192, 168, 1, 94);
        let pkt = ip_udp_rtp(0, 5004, 96, 0, 0, 1);
        state.handle_dante(DanteKind::AudioStream, src, Ipv4Addr::new(239,255,1,3), 5004, &pkt, Instant::now());
        let s = state.streams.values().find(|s| s.src_ip == Some(src)).unwrap();
        assert_eq!(s.dscp_violations, 1);
    }

    #[test]
    fn ttl_only_dvs_at_dscp_zero_is_not_a_violation() {
        // No control-plane signal, no timing evidence (single packet), but a
        // Windows host TTL (128) on its own infers DVS (see ttl_128_alone_infers_dvs
        // in protocols.rs). The DSCP gate must agree with the displayed verdict:
        // before centralizing signal construction, the gating struct silently
        // dropped the TTL field too (not just dscp_zero), so this exact source
        // was displayed as "DVS (likely)" yet still flagged for a DSCP violation.
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(192, 168, 1, 95);
        let mut pkt = ip_udp_rtp(0, 5004, 96, 0, 0, 1); // DSCP 0
        pkt[8] = 128; // TTL 128 — Windows host
        state.handle_dante(DanteKind::AudioStream, src, Ipv4Addr::new(239,255,1,4), 5004, &pkt, Instant::now());
        let s = state.streams.values().find(|s| s.src_ip == Some(src)).unwrap();
        assert_eq!(s.transmitter.map(|v| v.class), Some(TransmitterClass::Dvs),
            "TTL 128 alone should infer DVS");
        assert_eq!(s.dscp_violations, 0,
            "gating must agree with the displayed DVS verdict, not silently drop the TTL signal");
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
        assert!(state.dante.sources.contains(&src));
        assert_eq!(state.dante.names.get(&src).map(|s| s.as_str()), Some("Stage Box"));
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
        assert!(state.dante.sources.contains(&src));
        assert!(!state.dante.names.contains_key(&src), "dante_names should stay empty for unknown device");
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
        assert_eq!(state.dante.sources.len(), 1);
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
        assert_eq!(first.len(), 0, "ConMon sightings are silent — liveness shown in periodic report");
        assert_eq!(second.len(), 0, "repeat sightings are silent");
        let dev = state.dante.conmon.get(&src).expect("device tracked");
        assert_eq!(dev.mac, mac);
        assert_eq!(dev.channels, Some(32));
        assert_eq!(dev.packets, 2);
        assert!(state.dante.sources.contains(&src),
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
        assert_eq!(state.dante.conmon[&src].channels, Some(32));
    }

    // ── Dante ConMon redundancy bridge detection ─────────────────────────────

    #[test]
    fn conmon_bridge_no_alert_when_one_ip_per_mac() {
        let mut state = CaptureState::new();
        let mac = [0x00, 0x1d, 0xc1, 0x19, 0x86, 0x2a];
        state.handle_dante(DanteKind::ConMon { device_mac: mac, channels: None },
            Ipv4Addr::new(169, 254, 81, 11), Ipv4Addr::new(224, 0, 0, 232), 8705, &[], Instant::now());
        assert!(state.dante.check_conmon_bridge().is_empty());
    }

    #[test]
    fn conmon_bridge_detected_when_same_mac_two_ips() {
        let mut state = CaptureState::new();
        let mac = [0x00, 0x1d, 0xc1, 0x19, 0x86, 0x2a];
        // Same device visible from two IPs (primary + secondary interface).
        state.handle_dante(DanteKind::ConMon { device_mac: mac, channels: None },
            Ipv4Addr::new(169, 254, 81, 11), Ipv4Addr::new(224, 0, 0, 232), 8705, &[], Instant::now());
        state.handle_dante(DanteKind::ConMon { device_mac: mac, channels: None },
            Ipv4Addr::new(192, 168, 1, 11), Ipv4Addr::new(224, 0, 0, 232), 8705, &[], Instant::now());
        let alerts = state.dante.check_conmon_bridge();
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].level, AlertLevel::Error));
        assert!(alerts[0].message.contains("00:1d:c1:19:86:2a"));
        assert!(alerts[0].message.contains("169.254.81.11"));
        assert!(alerts[0].message.contains("192.168.1.11"));
    }

    #[test]
    fn conmon_bridge_includes_device_name_when_known() {
        let mut state = CaptureState::new();
        let mac = [0x00, 0x1d, 0xc1, 0x19, 0x86, 0x2a];
        let ip1 = Ipv4Addr::new(169, 254, 81, 11);
        let ip2 = Ipv4Addr::new(192, 168, 1, 11);
        state.dante.names.insert(ip1, "Rio3224-D2".to_string());
        state.handle_dante(DanteKind::ConMon { device_mac: mac, channels: None },
            ip1, Ipv4Addr::new(224, 0, 0, 232), 8705, &[], Instant::now());
        state.handle_dante(DanteKind::ConMon { device_mac: mac, channels: None },
            ip2, Ipv4Addr::new(224, 0, 0, 232), 8705, &[], Instant::now());
        let alerts = state.dante.check_conmon_bridge();
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].message.contains("\"Rio3224-D2\""));
    }

    #[test]
    fn conmon_bridge_two_distinct_devices_no_false_positive() {
        let mut state = CaptureState::new();
        let mac_a = [0x00, 0x1d, 0xc1, 0x19, 0x86, 0x2a];
        let mac_b = [0xac, 0x44, 0xf2, 0x84, 0x1e, 0x60];
        state.handle_dante(DanteKind::ConMon { device_mac: mac_a, channels: None },
            Ipv4Addr::new(169, 254, 81, 11), Ipv4Addr::new(224, 0, 0, 232), 8705, &[], Instant::now());
        state.handle_dante(DanteKind::ConMon { device_mac: mac_b, channels: None },
            Ipv4Addr::new(169, 254, 149, 65), Ipv4Addr::new(224, 0, 0, 232), 8705, &[], Instant::now());
        assert!(state.dante.check_conmon_bridge().is_empty());
    }

    // ── Dante IP misconfiguration detection ──────────────────────────────────

    #[test]
    fn ip_config_no_alert_with_fewer_than_two_devices() {
        let mut state = CaptureState::new();
        state.dante.sources.insert(Ipv4Addr::new(169, 254, 1, 1));
        assert!(state.dante.check_ip_config().is_empty());
    }

    #[test]
    fn ip_config_all_link_local_no_alert() {
        // All-link-local is a valid Dante deployment; no alert should fire.
        let mut state = CaptureState::new();
        state.dante.sources.insert(Ipv4Addr::new(169, 254, 1, 1));
        state.dante.sources.insert(Ipv4Addr::new(169, 254, 1, 2));
        assert!(state.dante.check_ip_config().is_empty());
    }

    #[test]
    fn ip_config_mixed_link_local_and_routable_errors_per_device() {
        let mut state = CaptureState::new();
        let ll = Ipv4Addr::new(169, 254, 1, 5);
        state.dante.sources.insert(ll);
        state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, 10));
        let alerts = state.dante.check_ip_config();
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].level, AlertLevel::Error));
        assert!(alerts[0].message.contains("169.254.1.5"));
    }

    #[test]
    fn ip_config_mixed_includes_device_name() {
        let mut state = CaptureState::new();
        let ll = Ipv4Addr::new(169, 254, 1, 5);
        state.dante.sources.insert(ll);
        state.dante.names.insert(ll, "StageBox".to_string());
        state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, 10));
        let alerts = state.dante.check_ip_config();
        assert!(alerts[0].message.contains("\"StageBox\""));
    }

    #[test]
    fn ip_config_same_subnet_no_alert() {
        let mut state = CaptureState::new();
        state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, 10));
        state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, 20));
        assert!(state.dante.check_ip_config().is_empty());
    }

    #[test]
    fn ip_config_subnet_split_warns() {
        let mut state = CaptureState::new();
        state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, 10));
        state.dante.sources.insert(Ipv4Addr::new(10, 0, 0, 5));
        let alerts = state.dante.check_ip_config();
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].level, AlertLevel::Warn));
        assert!(alerts[0].message.contains("2 subnets"));
        assert!(alerts[0].message.contains("192.168.1.0/24"));
        assert!(alerts[0].message.contains("10.0.0.0/24"));
    }

    #[test]
    fn ip_config_172_31_all_link_local_no_alert() {
        // All 172.31.x.x (Dante link-local fallback) — valid deployment, no alert.
        let mut state = CaptureState::new();
        state.dante.sources.insert(Ipv4Addr::new(172, 31, 0, 1));
        state.dante.sources.insert(Ipv4Addr::new(172, 31, 0, 2));
        assert!(state.dante.check_ip_config().is_empty());
    }

    #[test]
    fn ip_config_172_31_mixed_with_routable_errors() {
        let mut state = CaptureState::new();
        let ll = Ipv4Addr::new(172, 31, 0, 5);
        state.dante.sources.insert(ll);
        state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, 10));
        let alerts = state.dante.check_ip_config();
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].level, AlertLevel::Error));
        assert!(alerts[0].message.contains("172.31.0.5"));
    }

    #[test]
    fn ip_config_subnet_split_warns_ddm() {
        let mut state = CaptureState::new();
        state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, 10));
        state.dante.sources.insert(Ipv4Addr::new(10, 0, 0, 5));
        let alerts = state.dante.check_ip_config();
        assert!(alerts[0].message.contains("Domain Manager"));
    }

    // ── DanteState::unverified (mDNS-only device flagging) ───────────────────

    #[test]
    fn unverified_empty_below_threshold() {
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(192, 168, 1, 50);
        state.dante.sources.insert(src);
        // Two silent windows — one below the 3-window threshold.
        state.dante.reset_window(&state.streams);
        state.dante.reset_window(&state.streams);
        assert!(state.dante.unverified().is_empty());
    }

    #[test]
    fn unverified_flags_source_at_threshold() {
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(192, 168, 1, 50);
        state.dante.sources.insert(src);
        for _ in 0..3 {
            state.dante.reset_window(&state.streams);
        }
        assert!(state.dante.unverified().contains(&src));
    }

    #[test]
    fn unverified_resets_when_stream_appears() {
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(192, 168, 1, 50);
        state.dante.sources.insert(src);
        state.dante.reset_window(&state.streams);
        state.dante.reset_window(&state.streams);
        // A stream from this source appears before the third silent window —
        // the counter must clear, not just stop incrementing.
        let mut s = StreamStats::new_with_info("Dante", 48_000.0, false, Ipv4Addr::new(239,255,1,1), 5004);
        s.src_ip = Some(src);
        state.streams.insert("Dante test".to_string(), s);
        state.dante.reset_window(&state.streams);
        assert!(state.dante.unverified().is_empty());
    }

    // ── IGMP interval advisory and multiple-querier detection ────────────────

    #[test]
    fn igmp_query_interval_advisory_fires_above_60s() {
        let mut state = CaptureState::new();
        state.network_health.igmp_query_interval_secs = Some(125);
        let alerts = state.check_igmp_query_interval();
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].message.contains("125s"));
        assert!(alerts[0].message.contains("30s"));
    }

    #[test]
    fn igmp_query_interval_advisory_silent_at_30s() {
        let mut state = CaptureState::new();
        state.network_health.igmp_query_interval_secs = Some(30);
        assert!(state.check_igmp_query_interval().is_empty());
    }

    #[test]
    fn igmp_multiple_queriers_fires_error_and_sets_flag() {
        let mut state = CaptureState::new();
        add_active_multicast_stream(&mut state);
        state.igmp.querier_ips_this_window.insert(Ipv4Addr::new(10, 0, 0, 1));
        state.igmp.querier_ips_this_window.insert(Ipv4Addr::new(10, 0, 0, 2));
        let mc = state.has_active_multicast();
        let alerts = state.igmp.check_multiple_queriers(&mut state.network_health, mc);
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].level, AlertLevel::Error));
        assert!(alerts[0].message.contains("10.0.0.1"));
        assert!(alerts[0].message.contains("10.0.0.2"));
        assert!(state.network_health.multiple_queriers_this_window);
    }

    #[test]
    fn igmp_single_querier_no_alert() {
        let mut state = CaptureState::new();
        add_active_multicast_stream(&mut state);
        state.igmp.querier_ips_this_window.insert(Ipv4Addr::new(10, 0, 0, 1));
        let mc = state.has_active_multicast();
        assert!(state.igmp.check_multiple_queriers(&mut state.network_health, mc).is_empty());
        assert!(!state.network_health.multiple_queriers_this_window);
    }

    #[test]
    fn igmp_multiple_queriers_silent_without_active_multicast() {
        // Two real queriers but no multicast flowing — IGMP topology can't harm an
        // observable AV path that doesn't exist, so no alert and no score penalty.
        let mut state = CaptureState::new();
        state.igmp.querier_ips_this_window.insert(Ipv4Addr::new(10, 0, 0, 1));
        state.igmp.querier_ips_this_window.insert(Ipv4Addr::new(10, 0, 0, 2));
        let mc = state.has_active_multicast();
        assert!(!mc);
        assert!(state.igmp.check_multiple_queriers(&mut state.network_health, mc).is_empty());
        assert!(!state.network_health.multiple_queriers_this_window);
    }

    #[test]
    fn igmp_multiple_querier_flag_clears_on_reset_window() {
        let mut state = CaptureState::new();
        add_active_multicast_stream(&mut state);
        state.igmp.querier_ips_this_window.insert(Ipv4Addr::new(10, 0, 0, 1));
        state.igmp.querier_ips_this_window.insert(Ipv4Addr::new(10, 0, 0, 2));
        let mc = state.has_active_multicast();
        state.igmp.check_multiple_queriers(&mut state.network_health, mc);
        assert!(state.network_health.multiple_queriers_this_window);
        state.reset_window();
        assert!(!state.network_health.multiple_queriers_this_window);
        assert!(state.igmp.querier_ips_this_window.is_empty());
    }

    // ── Querier election: General vs Group-Specific Query ────────────────────

    #[test]
    fn igmp_general_query_registers_querier() {
        // A query to the all-systems group (224.0.0.1) is the General Query that
        // establishes the querier — it records identity and counts toward election.
        let mut state = CaptureState::new();
        let querier = Ipv4Addr::new(10, 244, 70, 241);
        let mac = [0xd0, 0x69, 0x9e, 0x10, 0x10, 0xe4];
        state.handle_igmp(querier, mac, crate::protocols::IGMP_ALL_SYSTEMS,
                          IgmpType::Query { version: 3 }, Instant::now());
        assert_eq!(state.network_health.igmp_querier_ip, Some(querier));
        assert_eq!(state.network_health.igmp_querier_mac, Some(mac));
        assert!(state.igmp.querier_ips_this_window.contains(&querier));
    }

    #[test]
    fn igmp_group_specific_query_does_not_register_querier() {
        // A Group-Specific Query (dst = the group, not 224.0.0.1) is membership
        // verification, not querier election. An IGMP-snooping switch commonly
        // sources these from 0.0.0.0 (RFC 4541); that must not become a querier.
        let mut state = CaptureState::new();
        state.handle_igmp(Ipv4Addr::UNSPECIFIED, [0u8; 6], Ipv4Addr::new(224, 0, 1, 129),
                          IgmpType::Query { version: 3 }, Instant::now());
        assert_eq!(state.network_health.igmp_querier_ip, None);
        assert!(state.igmp.querier_ips_this_window.is_empty());
        assert!(state.network_health.last_igmp_query.is_none(),
                "group-specific query must not start the querier silence timer");
    }

    #[test]
    fn igmp_group_specific_query_does_not_create_phantom_second_querier() {
        // Regression: one real General Query querier plus a switch's 0.0.0.0
        // group-specific verification queries must NOT trip the multiple-queriers
        // conflict alert.
        let mut state = CaptureState::new();
        let querier = Ipv4Addr::new(10, 244, 70, 241);
        state.handle_igmp(querier, [0xd0, 0x69, 0x9e, 0x10, 0x10, 0xe4],
                          crate::protocols::IGMP_ALL_SYSTEMS,
                          IgmpType::Query { version: 3 }, Instant::now());
        for g in [(224, 0, 1, 129), (224, 0, 1, 130), (224, 0, 1, 131)] {
            state.handle_igmp(Ipv4Addr::UNSPECIFIED, [0u8; 6],
                              Ipv4Addr::new(g.0, g.1, g.2, g.3),
                              IgmpType::Query { version: 3 }, Instant::now());
        }
        assert_eq!(state.igmp.querier_ips_this_window.len(), 1);
        // With active multicast present, an empty result proves only one querier
        // was counted (not that the check was gated out).
        add_active_multicast_stream(&mut state);
        let mc = state.has_active_multicast();
        assert!(state.igmp.check_multiple_queriers(&mut state.network_health, mc).is_empty());
        assert!(!state.network_health.multiple_queriers_this_window);
    }

    // ── IGMPv2/v3 mismatch, filter-unregistered-multicast, snooping-blocking-ptp ──

    #[test]
    fn igmp_version_mismatch_fires_warn_when_v2_querier_and_v3_report() {
        let mut state = CaptureState::new();
        state.igmp.querier_version = Some(2);
        state.igmp.v3_report_seen_this_window = true;
        let alerts = state.igmp.check_version_mismatch();
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].level, AlertLevel::Warn));
        assert!(alerts[0].message.contains("IGMPv2"));
    }

    #[test]
    fn igmp_version_mismatch_silent_when_v3_querier() {
        let mut state = CaptureState::new();
        state.igmp.querier_version = Some(3);
        state.igmp.v3_report_seen_this_window = true;
        assert!(state.igmp.check_version_mismatch().is_empty());
    }

    #[test]
    fn igmp_version_mismatch_silent_without_v3_reports() {
        let mut state = CaptureState::new();
        state.igmp.querier_version = Some(2);
        assert!(state.igmp.check_version_mismatch().is_empty());
    }

    // ── Protocol-family substate isolation tests ─────────────────────────────
    // These exercise the substate through its own interface — no surrounding
    // CaptureState needed — which is the point of grouping the fields.

    #[test]
    fn igmp_state_reset_clears_window_fields_but_keeps_version() {
        let mut igmp = IgmpState::new();
        igmp.querier_ips_this_window.insert(Ipv4Addr::new(10, 0, 0, 1));
        igmp.v3_report_seen_this_window = true;
        igmp.querier_version = Some(3); // retained across windows
        igmp.reset_window();
        assert!(igmp.querier_ips_this_window.is_empty());
        assert!(!igmp.v3_report_seen_this_window);
        assert_eq!(igmp.querier_version, Some(3));
    }

    #[test]
    fn avb_state_reset_clears_mvrp_when_no_avtp_streams() {
        let mut avb = AvbState::new();
        avb.mvrp_vlans.insert(2);
        // No AVTP streams present — MVRP registrations are cleared on reset.
        avb.reset_window();
        assert!(avb.mvrp_vlans.is_empty());
    }

    #[test]
    fn avb_state_reset_prunes_msrp_to_surviving_avtp() {
        let mut avb = AvbState::new();
        let sid = [1, 2, 3, 4, 5, 6, 7, 8];
        // An MSRP reservation whose AVTP stream is absent has nothing to display.
        avb.msrp_state.insert(sid, MsrpDeclaration {
            decl_type:           MsrpDeclType::TalkerAdvertise,
            stream_id:           sid,
            dest_mac:            None,
            vlan_id:             None,
            max_frame_size:      None,
            max_interval_frames: None,
            priority:            None,
            failure_code:        None,
            listener_state:      None,
        });
        avb.reset_window();
        assert!(avb.msrp_state.is_empty());
    }

    #[test]
    fn filter_unregistered_multicast_fires_after_two_cycles() {
        let mut state = CaptureState::new();
        // Populate ConMon to simulate device presence.
        state.dante.conmon.insert(Ipv4Addr::new(192, 168, 1, 1), ConmonDevice {
            mac: [0, 0, 0, 0, 0, 0],
            channels: None,
            packets: 0,
            last_seen: std::time::Instant::now(),
        });
        // First cycle: no alert yet.
        assert!(state.check_filter_unregistered_multicast().is_empty());
        assert_eq!(state.filter_unregistered_suspect_cycles, 1);
        // Second cycle: alert fires.
        let alerts = state.check_filter_unregistered_multicast();
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].level, AlertLevel::Warn));
        assert!(alerts[0].message.contains("Filter Unregistered Multicast"));
    }

    #[test]
    fn filter_unregistered_multicast_clears_when_streams_appear() {
        let mut state = CaptureState::new();
        state.dante.conmon.insert(Ipv4Addr::new(192, 168, 1, 1), ConmonDevice {
            mac: [0, 0, 0, 0, 0, 0],
            channels: None,
            packets: 0,
            last_seen: std::time::Instant::now(),
        });
        state.check_filter_unregistered_multicast(); // cycle 1
        assert_eq!(state.filter_unregistered_suspect_cycles, 1);
        // A stream appears — condition clears.
        state.streams.insert("test".to_string(), StreamStats::new("Dante", 1.0));
        state.check_filter_unregistered_multicast();
        assert_eq!(state.filter_unregistered_suspect_cycles, 0);
    }

    #[test]
    fn igmp_snooping_blocking_ptp_fires_when_dante_found_but_no_ptp_no_querier() {
        let mut state = CaptureState::new();
        state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, 10));
        let alerts = state.check_igmp_snooping_blocking_ptp(false);
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].level, AlertLevel::Warn));
    }

    #[test]
    fn igmp_snooping_blocking_ptp_silent_in_offline_mode() {
        let mut state = CaptureState::new();
        state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, 10));
        assert!(state.check_igmp_snooping_blocking_ptp(true).is_empty());
    }

    #[test]
    fn igmp_snooping_blocking_ptp_silent_when_querier_present() {
        let mut state = CaptureState::new();
        state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, 10));
        state.network_health.last_igmp_query = Some(std::time::Instant::now());
        assert!(state.check_igmp_snooping_blocking_ptp(false).is_empty());
    }

    #[test]
    fn high_multicast_bandwidth_fires_when_above_threshold_without_querier() {
        let mut state = CaptureState::new();
        // 80 Mbps over 5s = 80_000_000 / 8 * 5 = 50_000_000 bytes. Use 51MB to exceed.
        state.multicast_bytes_this_window = 51_000_000;
        let alerts = state.check_high_multicast_bandwidth();
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].level, AlertLevel::Warn));
        assert!(alerts[0].message.contains("80 Mbps"));
    }

    #[test]
    fn high_multicast_bandwidth_silent_when_querier_present() {
        let mut state = CaptureState::new();
        state.multicast_bytes_this_window = 51_000_000;
        state.network_health.last_igmp_query = Some(std::time::Instant::now());
        assert!(state.check_high_multicast_bandwidth().is_empty());
    }

    #[test]
    fn high_multicast_bandwidth_silent_below_threshold() {
        let mut state = CaptureState::new();
        state.multicast_bytes_this_window = 1_000_000;
        assert!(state.check_high_multicast_bandwidth().is_empty());
    }

    // ── Dante PTPv1 follower census ──────────────────────────────────────────

    fn make_ptpv1_domain(state: &mut CaptureState) {
        use crate::protocols::PTP_VERSION_V1;
        state.ptp.domains.insert((0, PTP_VERSION_V1), {
            let mut s = crate::stats::PtpStats::new(0, PTP_VERSION_V1);
            s.clock_valid = true;
            s
        });
    }

    #[test]
    fn follower_census_no_alert_without_ptpv1_domain() {
        let mut state = CaptureState::new();
        state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, 1));
        state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, 2));
        state.ptp.v1_followers.insert(Ipv4Addr::new(192, 168, 1, 2), Instant::now());
        assert!(state.dante.check_follower_census(&state.ptp).is_empty());
    }

    #[test]
    fn follower_census_no_alert_when_no_followers_seen_yet() {
        let mut state = CaptureState::new();
        make_ptpv1_domain(&mut state);
        state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, 1));
        state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, 2));
        // No Delay_Req seen yet — startup grace, no alert.
        assert!(state.dante.check_follower_census(&state.ptp).is_empty());
    }

    #[test]
    fn follower_census_no_alert_when_all_accounted_for() {
        let mut state = CaptureState::new();
        make_ptpv1_domain(&mut state);
        // 3 devices: 1 GM + 2 followers — healthy.
        state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, 1));
        state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, 2));
        state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, 3));
        state.ptp.v1_followers.insert(Ipv4Addr::new(192, 168, 1, 2), Instant::now());
        state.ptp.v1_followers.insert(Ipv4Addr::new(192, 168, 1, 3), Instant::now());
        assert!(state.dante.check_follower_census(&state.ptp).is_empty());
    }

    #[test]
    fn follower_census_alerts_when_device_not_syncing() {
        let mut state = CaptureState::new();
        make_ptpv1_domain(&mut state);
        // 4 devices: GM (.1) + 2 followers (.2, .3) + 1 not syncing (.4).
        for i in 1..=4 { state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, i)); }
        // Set the grandmaster IP on the domain so the GM is excluded from missing.
        state.ptp.domains.values_mut()
            .find(|s| s.version == crate::protocols::PTP_VERSION_V1)
            .unwrap()
            .grandmaster_src_ip = Some(Ipv4Addr::new(192, 168, 1, 1));
        state.ptp.v1_followers.insert(Ipv4Addr::new(192, 168, 1, 2), Instant::now());
        state.ptp.v1_followers.insert(Ipv4Addr::new(192, 168, 1, 3), Instant::now());
        let alerts = state.dante.check_follower_census(&state.ptp);
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].level, AlertLevel::Warn));
        assert!(alerts[0].message.contains("192.168.1.4"));
        assert!(alerts[0].message.contains("1 Dante device"));
    }

    #[test]
    fn follower_census_alert_includes_device_name() {
        let mut state = CaptureState::new();
        make_ptpv1_domain(&mut state);
        let gm = Ipv4Addr::new(192, 168, 1, 1);
        let missing = Ipv4Addr::new(192, 168, 1, 4);
        for i in 1..=4 { state.dante.sources.insert(Ipv4Addr::new(192, 168, 1, i)); }
        state.ptp.domains.values_mut()
            .find(|s| s.version == crate::protocols::PTP_VERSION_V1)
            .unwrap()
            .grandmaster_src_ip = Some(gm);
        state.dante.names.insert(missing, "StageBox".to_string());
        state.ptp.v1_followers.insert(Ipv4Addr::new(192, 168, 1, 2), Instant::now());
        state.ptp.v1_followers.insert(Ipv4Addr::new(192, 168, 1, 3), Instant::now());
        let alerts = state.dante.check_follower_census(&state.ptp);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].message.contains("\"StageBox\""));
        assert!(alerts[0].message.contains("192.168.1.4"));
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
        assert!(state.ndi.sources.contains(&src));
        assert_eq!(state.ndi.names.get(&src).map(|s| s.as_str()), Some("Studio Cam"));
    }

    // ── aggregate_ndi_bitrate — flagged by TODO.md as an open risk area ──────
    // ("verify it doesn't double-count" across multiple tcp_streams per source).

    #[test]
    fn aggregate_ndi_bitrate_sums_multiple_tcp_streams_for_one_source() {
        let mut state = CaptureState::new();
        let ndi_ip = Ipv4Addr::new(192, 168, 1, 60);
        let other_host = Ipv4Addr::new(192, 168, 1, 5);
        state.streams.insert("NDI a".into(),
            StreamStats::new_with_info("NDI", 0.0, false, ndi_ip, 0));

        let mut t1 = crate::stats::TcpStreamStats::new(ndi_ip, other_host);
        t1.bitrate_bps = 1_000_000;
        state.tcp_streams.insert("t1".into(), t1);

        let mut t2 = crate::stats::TcpStreamStats::new(other_host, ndi_ip);
        t2.bitrate_bps = 2_500_000;
        state.tcp_streams.insert("t2".into(), t2);

        state.aggregate_ndi_bitrate();

        assert_eq!(state.streams["NDI a"].bitrate_bps, 3_500_000,
            "must sum every tcp_streams entry touching the NDI source, not just one");
    }

    #[test]
    fn aggregate_ndi_bitrate_ignores_tcp_streams_for_other_ips() {
        let mut state = CaptureState::new();
        let ndi_ip = Ipv4Addr::new(192, 168, 1, 60);
        let unrelated_a = Ipv4Addr::new(192, 168, 1, 5);
        let unrelated_b = Ipv4Addr::new(192, 168, 1, 6);
        state.streams.insert("NDI a".into(),
            StreamStats::new_with_info("NDI", 0.0, false, ndi_ip, 0));

        let mut unrelated = crate::stats::TcpStreamStats::new(unrelated_a, unrelated_b);
        unrelated.bitrate_bps = 9_999_999;
        state.tcp_streams.insert("unrelated".into(), unrelated);

        state.aggregate_ndi_bitrate();

        assert_eq!(state.streams["NDI a"].bitrate_bps, 0,
            "a tcp_streams entry not touching the NDI source IP must not contribute");
    }

    #[test]
    fn aggregate_ndi_bitrate_is_a_noop_with_no_matching_tcp_streams() {
        let mut state = CaptureState::new();
        let ndi_ip = Ipv4Addr::new(192, 168, 1, 60);
        state.streams.insert("NDI a".into(),
            StreamStats::new_with_info("NDI", 0.0, false, ndi_ip, 0));

        state.aggregate_ndi_bitrate();

        assert_eq!(state.streams["NDI a"].bitrate_bps, 0);
    }

    fn tcp_segment(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16, seq: u32) -> crate::protocols::TcpSegment {
        crate::protocols::TcpSegment {
            src, dst, src_port, dst_port, seq, ack: 0,
            has_fin: false, has_syn: false, has_rst: false,
        }
    }

    #[test]
    fn tcp_to_known_ndi_source_tracked() {
        let mut state = CaptureState::new();
        let cam = Ipv4Addr::new(192, 168, 1, 60);
        let viewer = Ipv4Addr::new(192, 168, 1, 100);
        state.handle_ndi_discovery(cam, Some("Studio Cam".to_string()));

        state.handle_tcp(tcp_segment(cam, viewer, 6000, 51000, 1000), 1200, Instant::now());

        let stream = state.streams.get("NDI 192.168.1.60").expect("NDI stream entry created");
        assert_eq!(stream.packets, 1);
        assert_eq!(stream.sdp_name.as_deref(), Some("Studio Cam"));
        assert!(state.tcp_streams.contains_key("TCP 192.168.1.60:6000 → 192.168.1.100:51000"));
    }

    #[test]
    fn tcp_in_ndi_port_range_tracked_even_without_discovery() {
        // Port-range match alone is enough to track the TCP connection, but the
        // "NDI {ip}" display entry additionally requires a known source/dest —
        // mirrors the pre-refactor behavior in main.rs.
        let mut state = CaptureState::new();
        let a = Ipv4Addr::new(10, 0, 0, 1);
        let b = Ipv4Addr::new(10, 0, 0, 2);

        state.handle_tcp(tcp_segment(a, b, 5965, 51000, 1), 1000, Instant::now());

        assert!(state.tcp_streams.contains_key("TCP 10.0.0.1:5965 → 10.0.0.2:51000"));
        assert!(state.streams.is_empty());
    }

    #[test]
    fn tcp_outside_ndi_range_and_unknown_source_ignored() {
        let mut state = CaptureState::new();
        let a = Ipv4Addr::new(10, 0, 0, 1);
        let b = Ipv4Addr::new(10, 0, 0, 2);

        state.handle_tcp(tcp_segment(a, b, 443, 51000, 1), 1000, Instant::now());

        assert!(state.tcp_streams.is_empty());
        assert!(state.streams.is_empty());
    }

    #[test]
    fn tcp_backward_seq_counted_as_retransmission() {
        let mut state = CaptureState::new();
        let cam = Ipv4Addr::new(192, 168, 1, 60);
        let viewer = Ipv4Addr::new(192, 168, 1, 100);
        state.handle_ndi_discovery(cam, None);

        state.handle_tcp(tcp_segment(cam, viewer, 6000, 51000, 1000), 100, Instant::now());
        state.handle_tcp(tcp_segment(cam, viewer, 6000, 51000, 2000), 100, Instant::now());
        state.handle_tcp(tcp_segment(cam, viewer, 6000, 51000, 1500), 100, Instant::now());

        let tcp_stat = state.tcp_streams.get("TCP 192.168.1.60:6000 → 192.168.1.100:51000").unwrap();
        assert_eq!(tcp_stat.retransmissions, 1);
        assert_eq!(state.network_health.tcp_retransmissions, 1);
    }

    #[test]
    fn tcp_retransmission_penalty_is_window_scoped() {
        // A retransmission burst docks the score this window, but the next clean
        // window must recover it — same rule as ECN marks. Previously the counter
        // feeding this penalty was cumulative and never reset, so one burst
        // permanently docked the score for the rest of the run.
        let mut state = CaptureState::new();
        state.network_health.tcp_retransmissions = 20;

        state.network_health.calculate_score(
            &state.streams, &state.tcp_streams, &state.ptp.domains,
            &state.avb.msrp_state, &state.eee_ports, &state.avb.avtp_streams);
        assert!(state.network_health.network_score < 100.0,
            "retransmissions should dock the score this window");

        state.reset_window();
        state.network_health.calculate_score(
            &state.streams, &state.tcp_streams, &state.ptp.domains,
            &state.avb.msrp_state, &state.eee_ports, &state.avb.avtp_streams);
        assert_eq!(state.network_health.network_score, 100.0,
            "score must recover after a clean window");
    }

    // ── IGMP ─────────────────────────────────────────────────────────────────

    // ── State-map bounds (memory-exhaustion DoS hardening) ───────────────────

    #[test]
    fn dante_sources_bounded_under_spoofed_ip_flood() {
        let mut d = DanteState::new();
        let cap = DanteState::MAX_SOURCES;
        for i in 0..(cap as u32 + 50) {
            d.record_source(Ipv4Addr::from(i), Some("nm"));
        }
        assert!(d.sources.len() <= cap, "sources bounded, got {}", d.sources.len());
        assert!(d.names.len() <= cap, "names bounded, got {}", d.names.len());
        let newest = Ipv4Addr::from(cap as u32 + 49);
        assert!(d.sources.contains(&newest), "newest entry must be retained");
    }

    #[test]
    fn dante_sources_eviction_also_clears_transmitter_class() {
        // transmitter_class is DanteState's one field NdiState doesn't have —
        // eviction must clear it too, or a stale verdict would survive under
        // a recycled IP once MAX_SOURCES forces an eviction.
        let mut d = DanteState::new();
        let cap = DanteState::MAX_SOURCES;
        let victim_candidate = Ipv4Addr::from(0u32);
        d.record_source(victim_candidate, Some("nm"));
        d.record_tx_class(victim_candidate, crate::protocols::TransmitterClass::Dvs);
        for i in 1..(cap as u32 + 50) {
            d.record_source(Ipv4Addr::from(i), Some("nm"));
        }
        assert!(
            !d.sources.contains(&victim_candidate) || d.transmitter_class.contains_key(&victim_candidate),
            "if the original source survived eviction its transmitter_class must too; \
             if it was evicted, transmitter_class must not leak a stale verdict"
        );
        assert!(d.transmitter_class.len() <= cap, "transmitter_class bounded, got {}", d.transmitter_class.len());
    }

    #[test]
    fn ndi_sources_bounded_under_spoofed_ip_flood() {
        let mut n = NdiState::new();
        let cap = NdiState::MAX_SOURCES;
        for i in 0..(cap as u32 + 50) {
            n.record_source(Ipv4Addr::from(i), Some("nm"));
        }
        assert!(n.sources.len() <= cap, "sources bounded, got {}", n.sources.len());
        assert!(n.names.len() <= cap);
        assert!(n.sources.contains(&Ipv4Addr::from(cap as u32 + 49)));
    }

    #[test]
    fn sdp_cache_bounded_under_session_id_flood() {
        let mut state = CaptureState::new();
        let cap = CaptureState::MAX_SDP_SESSIONS;
        for i in 0..(cap + 50) {
            let mut sdp = sdp_for_port(5004, 96, 48_000.0);
            sdp.session_id = format!("sess-{i}");
            state.handle_sap(sdp);
        }
        assert!(state.sdp_cache.len() <= cap, "sdp_cache bounded, got {}", state.sdp_cache.len());
    }

    #[test]
    fn igmp_join_deduplicated() {
        let mut state = CaptureState::new();
        let src   = Ipv4Addr::new(192, 168, 1, 10);
        let group = Ipv4Addr::new(239, 69, 0, 1);
        let a1 = state.handle_igmp(src, [0u8; 6], group, IgmpType::Join, Instant::now());
        let a2 = state.handle_igmp(src, [0u8; 6], group, IgmpType::Join, Instant::now());
        assert_eq!(a1.len(), 1, "first Join emits");
        assert_eq!(a2.len(), 0, "second Join is deduped");
    }

    #[test]
    fn igmp_leave_clears_dedup_entry() {
        let mut state = CaptureState::new();
        let src   = Ipv4Addr::new(192, 168, 1, 10);
        let group = Ipv4Addr::new(239, 69, 0, 1);
        state.handle_igmp(src, [0u8; 6], group, IgmpType::Join,  Instant::now());
        state.handle_igmp(src, [0u8; 6], group, IgmpType::Leave, Instant::now());
        let a3 = state.handle_igmp(src, [0u8; 6], group, IgmpType::Join, Instant::now());
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
        state.handle_aes67(Ipv4Addr::new(239, 69, 0, 1), 5004, 96, &pkt, None);
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
        state.ptp.domains.insert((0, PTP_VERSION_V2), valid_ptp_stats(PTP_VERSION_V2, "PTPv2"));
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
        state.ptp.domains.insert((0, PTP_VERSION_V1), valid_ptp_stats(PTP_VERSION_V1, "PTPv1"));
        assert!(!state.missing_ptp_clocks(&[ProtocolChoice::AES67]).is_empty());
    }

    #[test]
    fn ptp_ok_for_dante_with_ptpv1_clock() {
        // Dante accepts either PTPv1 or PTPv2.
        let mut state = CaptureState::new();
        state.handle_dante(DanteKind::AudioStream, Ipv4Addr::new(192,168,1,10), Ipv4Addr::new(192,168,1,60), 5004, &[], Instant::now());
        state.ptp.domains.insert((0, PTP_VERSION_V1), valid_ptp_stats(PTP_VERSION_V1, "PTPv1"));
        assert!(state.missing_ptp_clocks(&[ProtocolChoice::Dante]).is_empty());
    }

    #[test]
    fn ptp_ok_for_all_on_pure_aes67_network() {
        // Regression for the reported bug: picking "All" on a network with
        // only AES67 + UDP PTPv2 (no AVB, no gPTP) used to warn "no clock
        // source" because needs_gptp was true based on selection alone.
        let mut state = CaptureState::new();
        seed_aes67_stream(&mut state);
        state.ptp.domains.insert((0, PTP_VERSION_V2), valid_ptp_stats(PTP_VERSION_V2, "PTPv2"));
        let expanded = ProtocolChoice::All.includes();
        assert!(state.missing_ptp_clocks(&expanded).is_empty());
    }

    #[test]
    fn ptp_fails_for_avb_streams_without_gptp() {
        let mut state = CaptureState::new();
        // Seed an AVTP stream so the "observed" gate fires.
        state.handle_avb(0x00, Some([1,2,3,4,5,6,7,8]), 100, Some(0), None, Instant::now());
        // UDP PTPv2 is present but L2 gPTP (protocol_kind="AVB") is not.
        state.ptp.domains.insert((0, PTP_VERSION_V2), valid_ptp_stats(PTP_VERSION_V2, "PTPv2"));
        assert!(!state.missing_ptp_clocks(&[ProtocolChoice::AVB]).is_empty());
    }

    #[test]
    fn ptp_ok_for_avb_with_l2_gptp() {
        let mut state = CaptureState::new();
        state.handle_avb(0x00, Some([1,2,3,4,5,6,7,8]), 100, Some(0), None, Instant::now());
        state.ptp.domains.insert((0, PTP_VERSION_V2), valid_ptp_stats(PTP_VERSION_V2, "AVB"));
        assert!(state.missing_ptp_clocks(&[ProtocolChoice::AVB]).is_empty());
    }

    #[test]
    fn ptp_ok_for_ndi_only_no_clock_required() {
        // NDI is TCP — no PTP at all.
        let mut state = CaptureState::new();
        state.ndi.sources.insert(Ipv4Addr::new(192,168,1,60));
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
        state.handle_st2110(Ipv4Addr::new(239, 1, 2, 3), 5006, St2110Type::Audio, &pkt, None);
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
        state.ptp.domains.insert((0, PTP_VERSION_V2), valid_ptp_stats(PTP_VERSION_V2, "AVB"));
        let missing = state.missing_ptp_clocks(&[ProtocolChoice::Dante]);
        assert!(missing.iter().any(|m| m.kind == MissingClockKind::Ptp && m.affected == vec!["Dante"]),
            "AVB gPTP must not satisfy Dante's clock requirement");
    }

    #[test]
    fn missing_clock_for_avb_identifies_gptp() {
        let mut state = CaptureState::new();
        state.handle_avb(0x00, Some([1,2,3,4,5,6,7,8]), 100, Some(0), None, Instant::now());
        // UDP PTPv2 present but no L2 gPTP — AVB still affected.
        state.ptp.domains.insert((0, PTP_VERSION_V2), valid_ptp_stats(PTP_VERSION_V2, "PTPv2"));
        let missing = state.missing_ptp_clocks(&[ProtocolChoice::AVB]);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].kind, MissingClockKind::Gptp);
        assert_eq!(missing[0].affected, vec!["AVB"]);
    }

    // ── stream_clock_kind — single source of truth for Clock Source family ───

    #[test]
    fn stream_clock_kind_matches_protocol_family() {
        assert_eq!(stream_clock_kind("AES67"), Some(MissingClockKind::Ptpv2));
        assert_eq!(stream_clock_kind("2110-20"), Some(MissingClockKind::Ptpv2));
        assert_eq!(stream_clock_kind("2110-30"), Some(MissingClockKind::Ptpv2));
        assert_eq!(stream_clock_kind("Dante"), Some(MissingClockKind::Ptp));
        assert_eq!(stream_clock_kind("NDI"), None);
        // AVB's gPTP requirement is derived from avtp_streams presence, not a
        // StreamStats protocol label — AVB frames never populate `self.streams`.
        assert_eq!(stream_clock_kind("AVB"), None);
    }

    // ── handle_avb — sv=0 control frames must not become phantom streams ─────

    #[test]
    fn avb_control_frame_without_stream_id_creates_no_stream() {
        // An sv=0 AVTP control/discovery frame (no stream id) must not inflate the
        // AVB count — avtp_streams stays empty so the overview count, the Streams
        // list, and the gPTP gate all agree. AVB media never touches the generic
        // `streams` map at all (see avb_media_never_creates_generic_stream_entry).
        let mut state = CaptureState::new();
        state.handle_avb(0x7e, None, 100, None, None, Instant::now()); // 0x7e = MAAP
        assert!(state.avb.avtp_streams.is_empty());
    }

    #[test]
    fn avb_media_frame_with_stream_id_creates_stream() {
        let mut state = CaptureState::new();
        state.handle_avb(0x00, Some([1, 2, 3, 4, 5, 6, 7, 8]), 100, Some(0), None, Instant::now());
        assert_eq!(state.avb.avtp_streams.len(), 1);
    }

    #[test]
    fn avb_media_never_creates_generic_stream_entry() {
        // AVB media is tracked solely on avtp_streams (keyed by stream_id) — it must
        // never also populate the generic `streams` map, which used to hold a
        // subtype-label-keyed StreamStats aggregate that the report layer silently
        // skipped rendering (report.rs used to `continue` past "AVB "-prefixed keys).
        let mut state = CaptureState::new();
        state.handle_avb(0x00, Some([1, 2, 3, 4, 5, 6, 7, 8]), 100, Some(0), None, Instant::now());
        assert!(state.streams.is_empty());
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
            protocol_kind: Some("PTPv2".to_string()),
            src_ip: None,
            stratum: None,
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
            protocol_kind: Some("AVB".to_string()),
            src_ip: None,
            stratum: None,
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
        let stats = state.ptp.domains.get(&(0, PTP_VERSION_V2)).expect("entry created");
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
        assert!(state.ptp.domains.get(&(0, PTP_VERSION_V2)).unwrap().min_path_delay_ns.is_some());

        announce.grandmaster_id = Some("gm-B".to_string());
        state.handle_ptp(announce);
        let stats = state.ptp.domains.get(&(0, PTP_VERSION_V2)).unwrap();
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
        assert!(state.avb.msrp_state.contains_key(&[0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x01]));
    }

    // ── PTPv1 sync-sender / multiple-master tests ────────────────────────────

    /// Build a minimal PTPv1 Sync PtpInfo with src_ip and stratum set,
    /// as handle_ptp receives it from detect_protocol/parse_ptp.
    fn ptpv1_sync(src: Ipv4Addr, stratum: u8, domain: u8) -> crate::protocols::PtpInfo {
        crate::protocols::PtpInfo {
            version:                     PTP_VERSION_V1,
            message_type:                0x00, // Sync
            domain,
            clock_id:                    Some(format!("{:?}", src)),
            grandmaster_id:              Some(format!("{:?}", src)),
            clock_quality:               Some("Preferred grandmaster".to_string()),
            correction_ns:               None,
            path_delay_ns:               None,
            message_name:                "Sync".to_string(),
            port_id:                     Some(1),
            sequence_id:                 1,
            log_sync_interval:           0,
            protocol_kind:               Some("PTPv1".to_string()),
            src_ip:                      Some(src),
            stratum:                     Some(stratum),
        }
    }

    #[test]
    fn single_ptp_sync_sender_no_conflict_alert() {
        let mut state = CaptureState::new();
        let info = ptpv1_sync(Ipv4Addr::new(192, 168, 1, 10), 0, 0);
        state.handle_ptp(info);
        let alerts = state.ptp.check_ptp_sync_conflict();
        assert!(alerts.is_empty(), "single Sync sender should produce no alert");
    }

    #[test]
    fn two_ptpv1_sync_senders_emits_warn() {
        let mut state = CaptureState::new();
        // Two devices, stratum 1 each — competing but neither is "preferred master"
        state.handle_ptp(ptpv1_sync(Ipv4Addr::new(192, 168, 1, 10), 1, 0));
        state.handle_ptp(ptpv1_sync(Ipv4Addr::new(192, 168, 1, 20), 1, 0));
        let alerts = state.ptp.check_ptp_sync_conflict();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].level, AlertLevel::Warn);
        assert!(alerts[0].message.contains("Multiple PTP Sync senders in domain"));
    }

    #[test]
    fn two_preferred_masters_emits_error() {
        let mut state = CaptureState::new();
        // Two devices with stratum 0 = "preferred master" in Dante — misconfiguration
        state.handle_ptp(ptpv1_sync(Ipv4Addr::new(192, 168, 1, 10), 0, 0));
        state.handle_ptp(ptpv1_sync(Ipv4Addr::new(192, 168, 1, 20), 0, 0));
        let alerts = state.ptp.check_ptp_sync_conflict();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].level, AlertLevel::Error);
        assert!(alerts[0].message.contains("Multiple Preferred Leaders"));
    }

    #[test]
    fn sync_conflict_clears_after_reset_window() {
        let mut state = CaptureState::new();
        state.handle_ptp(ptpv1_sync(Ipv4Addr::new(192, 168, 1, 10), 0, 0));
        state.handle_ptp(ptpv1_sync(Ipv4Addr::new(192, 168, 1, 20), 0, 0));
        assert!(!state.ptp.check_ptp_sync_conflict().is_empty());
        state.reset_window();
        // After reset, no senders recorded → no conflict
        assert!(state.ptp.check_ptp_sync_conflict().is_empty(), "conflict must clear after reset_window");
    }

    // ── Dante TTL routing detection ──────────────────────────────────────────

    /// Build an IP+UDP+RTP buffer with a configurable TTL, src and dst IPs.
    fn ip_udp_rtp_with_ttl(ttl: u8, src_ip: [u8;4], dst_ip: [u8;4], dst_port: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 20 + 8 + 12];
        buf[0] = 0x45;
        buf[1] = (46 << 2) | 0; // DSCP EF, ECN 0
        let total_len: u16 = (20 + 8 + 12) as u16;
        buf[2..4].copy_from_slice(&total_len.to_be_bytes());
        buf[8]  = ttl;
        buf[9]  = 0x11; // UDP
        buf[12..16].copy_from_slice(&src_ip);
        buf[16..20].copy_from_slice(&dst_ip);
        buf[20..22].copy_from_slice(&5100u16.to_be_bytes()); // src port (even, in Dante range)
        buf[22..24].copy_from_slice(&dst_port.to_be_bytes());
        let udp_len: u16 = (8 + 12) as u16;
        buf[24..26].copy_from_slice(&udp_len.to_be_bytes());
        buf[28] = 0x80; // RTP V=2
        buf[29] = 96;
        buf
    }

    #[test]
    fn dante_ttl64_no_routing_alert() {
        let mut state = CaptureState::new();
        let pkt = ip_udp_rtp_with_ttl(64, [192,168,1,50], [192,168,1,60], 5100);
        state.handle_dante(
            DanteKind::AudioStream,
            Ipv4Addr::new(192,168,1,50),
            Ipv4Addr::new(192,168,1,60),
            5100, &pkt, Instant::now(),
        );
        let key = "Dante 192.168.1.50 → 192.168.1.60:5100";
        assert_eq!(state.streams[key].min_ttl, Some(64), "TTL 64 should be stored");
    }

    #[test]
    fn dante_ttl63_records_min_ttl() {
        let mut state = CaptureState::new();
        // TTL = 63 means a Linux/macOS source went through 1 router hop
        let pkt = ip_udp_rtp_with_ttl(63, [192,168,1,50], [192,168,1,60], 5100);
        state.handle_dante(
            DanteKind::AudioStream,
            Ipv4Addr::new(192,168,1,50),
            Ipv4Addr::new(192,168,1,60),
            5100, &pkt, Instant::now(),
        );
        let key = "Dante 192.168.1.50 → 192.168.1.60:5100";
        assert_eq!(state.streams[key].min_ttl, Some(63), "routed TTL should be stored");
    }

    #[test]
    fn dante_min_ttl_tracks_minimum_over_packets() {
        let mut state = CaptureState::new();
        let src = Ipv4Addr::new(192,168,1,50);
        let dst = Ipv4Addr::new(192,168,1,60);
        let pkt64 = ip_udp_rtp_with_ttl(64, [192,168,1,50], [192,168,1,60], 5100);
        let pkt60 = ip_udp_rtp_with_ttl(60, [192,168,1,50], [192,168,1,60], 5100);
        state.handle_dante(DanteKind::AudioStream, src, dst, 5100, &pkt64, Instant::now());
        state.handle_dante(DanteKind::AudioStream, src, dst, 5100, &pkt60, Instant::now());
        let key = "Dante 192.168.1.50 → 192.168.1.60:5100";
        assert_eq!(state.streams[key].min_ttl, Some(60), "should track minimum over all packets");
    }

    // ── check_clock_dropout_correlation ────────────────────────────────────────

    fn lost_ptpv1_state() -> PtpState {
        let mut ps = PtpState::new();
        let mut stats = PtpStats::new(0, PTP_VERSION_V1);
        stats.protocol_clock_lost = true;
        stats.protocol_kind = Some("PTPv1".to_string());
        ps.domains.insert((0, PTP_VERSION_V1), stats);
        ps
    }

    fn lost_ptpv2_state() -> PtpState {
        let mut ps = PtpState::new();
        let mut stats = PtpStats::new(0, PTP_VERSION_V2);
        stats.protocol_clock_lost = true;
        stats.protocol_kind = Some("PTPv2".to_string());
        ps.domains.insert((0, PTP_VERSION_V2), stats);
        ps
    }

    fn dante_stream_with_loss() -> StreamStats {
        let mut s = StreamStats::new("Dante", crate::protocols::DEFAULT_CLOCK_HZ);
        s.lost_this_window = 1;
        s
    }

    fn aes67_stream_with_loss() -> StreamStats {
        let mut s = StreamStats::new("AES67", 48_000.0);
        s.lost_this_window = 1;
        s
    }

    #[test]
    fn clock_dropout_combined_fires_when_ptpv1_lost_and_dante_has_loss() {
        let mut state = CaptureState::new();
        state.ptp = lost_ptpv1_state();
        state.streams.insert("Dante 1.2.3.4 → 5.6.7.8:5000".to_string(), dante_stream_with_loss());
        assert!(state.check_clock_dropout_correlation().is_some());
    }

    #[test]
    fn clock_dropout_combined_fires_when_ptpv2_lost_and_aes67_has_loss() {
        let mut state = CaptureState::new();
        state.ptp = lost_ptpv2_state();
        state.streams.insert("AES67 239.69.0.1:5004".to_string(), aes67_stream_with_loss());
        assert!(state.check_clock_dropout_correlation().is_some());
    }

    #[test]
    fn clock_dropout_none_when_ptpv1_lost_but_no_stream_loss() {
        let mut state = CaptureState::new();
        state.ptp = lost_ptpv1_state();
        let mut s = StreamStats::new("Dante", crate::protocols::DEFAULT_CLOCK_HZ);
        s.lost_this_window = 0;
        state.streams.insert("Dante 1.2.3.4 → 5.6.7.8:5000".to_string(), s);
        assert!(state.check_clock_dropout_correlation().is_none());
    }

    #[test]
    fn clock_dropout_none_when_stream_loss_but_clock_healthy() {
        let mut state = CaptureState::new();
        let mut stats = PtpStats::new(0, PTP_VERSION_V1);
        stats.clock_valid = true;
        stats.protocol_clock_lost = false;
        state.ptp.domains.insert((0, PTP_VERSION_V1), stats);
        state.streams.insert("Dante 1.2.3.4 → 5.6.7.8:5000".to_string(), dante_stream_with_loss());
        assert!(state.check_clock_dropout_correlation().is_none());
    }

    #[test]
    fn clock_dropout_none_when_wrong_protocol_family_has_loss() {
        // PTPv2 lost but only a Dante stream has loss — no correlation
        let mut state = CaptureState::new();
        state.ptp = lost_ptpv2_state();
        state.streams.insert("Dante 1.2.3.4 → 5.6.7.8:5000".to_string(), dante_stream_with_loss());
        assert!(state.check_clock_dropout_correlation().is_none());
    }

    // ── PCP mismatch (Issue #26 — AVB) / advisory (Issue #27 — AES67/ST2110) ──

    fn avb_stream_with_msrp(priority: u8) -> CaptureState {
        let mut state = CaptureState::new();
        let sid = [1u8, 2, 3, 4, 5, 6, 7, 8];
        state.avb.msrp_state.insert(sid, crate::protocols::MsrpDeclaration {
            stream_id: sid,
            decl_type: crate::protocols::MsrpDeclType::TalkerAdvertise,
            dest_mac: None,
            vlan_id: Some(2),
            max_frame_size: None,
            max_interval_frames: None,
            priority: Some(priority),
            failure_code: None,
            listener_state: None,
        });
        state
    }

    #[test]
    fn pcp_violation_tracked_per_stream_id_not_shared_by_subtype_label() {
        // Two distinct AVB streams sharing the same subtype (0x00 = IEC 61883) must
        // not share PCP violation state just because they'd render under the same
        // "AVB {label}" grouping — each stream_id gets its own AvtpStreamStats entry.
        let mut state = CaptureState::new();
        let sid_a = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let sid_b = [9u8, 9, 9, 9, 9, 9, 9, 9];
        for (sid, priority) in [(sid_a, 3u8), (sid_b, 3u8)] {
            state.avb.msrp_state.insert(sid, crate::protocols::MsrpDeclaration {
                stream_id: sid,
                decl_type: crate::protocols::MsrpDeclType::TalkerAdvertise,
                dest_mac: None,
                vlan_id: Some(2),
                max_frame_size: None,
                max_interval_frames: None,
                priority: Some(priority),
                failure_code: None,
                listener_state: None,
            });
        }
        state.handle_avb(0x00, Some(sid_a), 100, Some(0), Some(2), Instant::now()); // mismatch
        state.handle_avb(0x00, Some(sid_b), 100, Some(0), Some(3), Instant::now()); // matches

        let a = &state.avb.avtp_streams[&sid_a];
        let b = &state.avb.avtp_streams[&sid_b];
        assert_eq!(a.pcp_violations, 1);
        assert_eq!(a.observed_pcp, Some(2));
        assert_eq!(a.msrp_declared_pcp, Some(3));
        assert_eq!(b.pcp_violations, 0);
    }

    #[test]
    fn pcp_mismatch_fires_when_pcp_differs_from_msrp() {
        let mut state = avb_stream_with_msrp(3);
        // AVTP frame arriving with PCP=2 (wrong — MSRP declared 3)
        state.handle_avb(0x00, Some([1,2,3,4,5,6,7,8]), 100, Some(0), Some(2), Instant::now());
        let s = &state.avb.avtp_streams[&[1,2,3,4,5,6,7,8]];
        assert_eq!(s.pcp_violations, 1);
        assert_eq!(s.observed_pcp, Some(2));
        assert_eq!(s.msrp_declared_pcp, Some(3));
    }

    #[test]
    fn pcp_no_mismatch_when_pcp_matches_msrp() {
        let mut state = avb_stream_with_msrp(3);
        state.handle_avb(0x00, Some([1,2,3,4,5,6,7,8]), 100, Some(0), Some(3), Instant::now());
        let s = &state.avb.avtp_streams[&[1,2,3,4,5,6,7,8]];
        assert_eq!(s.pcp_violations, 0);
    }

    #[test]
    fn pcp_no_alert_without_vlan_tag() {
        let mut state = avb_stream_with_msrp(3);
        state.handle_avb(0x00, Some([1,2,3,4,5,6,7,8]), 100, Some(0), None, Instant::now());
        let s = &state.avb.avtp_streams[&[1,2,3,4,5,6,7,8]];
        assert_eq!(s.pcp_violations, 0);
    }

    #[test]
    fn pcp_no_alert_without_talker_advertise() {
        let mut state = CaptureState::new();
        // No MSRP entry for this stream_id
        state.handle_avb(0x00, Some([1,2,3,4,5,6,7,8]), 100, Some(0), Some(2), Instant::now());
        let s = &state.avb.avtp_streams[&[1,2,3,4,5,6,7,8]];
        assert_eq!(s.pcp_violations, 0);
    }

    #[test]
    fn pcp_advisory_fires_for_aes67_with_wrong_pcp() {
        let mut state = CaptureState::new();
        let pkt = ip_udp_rtp(46 << 2, 5004, 96, 0, 0, 0xAAAA);
        state.handle_aes67(Ipv4Addr::new(239, 69, 0, 1), 5004, 96, &pkt, Some(0));
        let s = &state.streams["AES67 239.69.0.1:5004"];
        assert_eq!(s.pcp_violations, 1);
        assert_eq!(s.observed_pcp, Some(0));
    }

    #[test]
    fn pcp_no_advisory_for_aes67_with_pcp6() {
        let mut state = CaptureState::new();
        let pkt = ip_udp_rtp(46 << 2, 5004, 96, 0, 0, 0xAAAA);
        state.handle_aes67(Ipv4Addr::new(239, 69, 0, 1), 5004, 96, &pkt, Some(6));
        let s = &state.streams["AES67 239.69.0.1:5004"];
        assert_eq!(s.pcp_violations, 0);
    }

    #[test]
    fn pcp_advisory_fires_for_st2110_with_wrong_pcp() {
        let mut state = CaptureState::new();
        let pkt = ip_udp_rtp(46 << 2, 5004, 96, 0, 0, 0xAAAA);
        state.handle_st2110(Ipv4Addr::new(239, 1, 2, 3), 5004, St2110Type::Audio, &pkt, Some(3));
        let s = state.streams.values().find(|s| s.protocol == "2110-30").expect("stream");
        assert_eq!(s.pcp_violations, 1);
        assert_eq!(s.observed_pcp, Some(3));
    }

    #[test]
    fn pcp_no_advisory_for_untagged_aes67() {
        let mut state = CaptureState::new();
        let pkt = ip_udp_rtp(46 << 2, 5004, 96, 0, 0, 0xAAAA);
        state.handle_aes67(Ipv4Addr::new(239, 69, 0, 1), 5004, 96, &pkt, None);
        let s = &state.streams["AES67 239.69.0.1:5004"];
        assert_eq!(s.pcp_violations, 0);
    }
}

