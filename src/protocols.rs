// AVStreamLens — src/protocols.rs
// Network protocol definitions, enums, and constants

use std::net::Ipv4Addr;

// ════ Network Constants ════

// Port numbers and UDP/TCP ports
pub const SAP_PORT:          u16 = 9875;   // SAP/SDP metadata
pub const MDNS_PORT:         u16 = 5353;   // mDNS discovery (Dante)
pub const PTP_EVENT_PORT:    u16 = 319;    // PTP event port (Sync, Delay_Req, P_Delay_Req)
pub const PTP_GENERAL_PORT:  u16 = 320;    // PTP general port (Announce, Follow_Up, Management)

// EtherType values for PTP and AVB
pub const ETHERTYPE_AVTP:    u16 = 0x22F0; // AVTP (AVB)
pub const ETHERTYPE_PTP:     u16 = 0x88F7; // PTP (IEEE 1588)
pub const ETHERTYPE_MSRP:    u16 = 0x22EA; // MSRP — IEEE 802.1Qat stream reservation
pub const ETHERTYPE_MVRP:    u16 = 0x88F5; // MVRP — IEEE 802.1Q VLAN registration
pub const ETHERTYPE_LLDP:    u16 = 0x88CC; // LLDP — IEEE 802.1AB link layer discovery
pub const ETHERTYPE_FLOW_CTRL: u16 = 0x8808; // IEEE 802.3x PAUSE / 802.1Qbb PFC

// IGMP protocol number
pub const IP_PROTO_IGMP:     u8  = 0x02;

// IGMP "all-systems" group (224.0.0.1). A Membership Query sent to this address
// is a General Query — the message that establishes the querier and its interval.
// A query sent to a specific group address is a Group-Specific Query (membership
// verification, e.g. after a Leave or by an IGMP-snooping switch per RFC 4541),
// and must NOT be treated as querier election: snooping switches commonly source
// these from 0.0.0.0, which would otherwise register as a phantom second querier.
pub const IGMP_ALL_SYSTEMS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);

// Timeout for "dead stream" detection (seconds)
pub const STREAM_TIMEOUT_SECS: u64 = 10;

// Default RTP clock frequency
pub const DEFAULT_CLOCK_HZ: f64 = 48_000.0;

// PTP versions (RFC 6188)
// Note: Both PTPv1 and PTPv2 are valid; we use the version field in the message
pub const PTP_VERSION_V1: u8 = 1;  // IEEE 1588-2002 wire value (high nibble of byte 0)
pub const PTP_VERSION_V2: u8 = 2;  // IEEE 1588-2008 wire value (low nibble of byte 1)

// Dante control ports
pub const DANTE_CTRL_PORTS: &[u16] = &[4440, 4455, 8700, 8800];

// NDI default port range
pub const NDI_PORT_MIN:      u16 = 5960;
pub const NDI_PORT_MAX:      u16 = 5980;

// ════ Protocol Detection ════

#[derive(Debug, Clone, PartialEq)]
pub enum AvProtocol {
    Aes67  { src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16, payload_type: u8 },
    St2110 { src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16, stream_type: St2110Type },
    Dante  { kind: DanteKind, src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16 },
    Ndi    { kind: NdiKind,   src: Ipv4Addr },
    Avb    { subtype: u8, stream_id: Option<[u8; 8]>, seq: Option<u8> },
    Msrp   { declarations: Vec<MsrpDeclaration> },
    Mvrp   { vlan_ids: Vec<u16> },
    Sap    { src: Ipv4Addr, sdp: SdpSession },
    AvdeccAdp(AvdeccAdp),
    Ptp    { info: PtpInfo },
    Igmp   { src: Ipv4Addr, src_mac: [u8; 6], group: Ipv4Addr, igmp_type: IgmpType },
    LldpEee { chassis_id: String, port_id: String, tx_wake_us: u16, rx_wake_us: u16 },
    FlowControl { kind: FlowControlKind },
    /// Any IPv4 TCP segment. NDI is the only protocol carried over TCP, so
    /// `is_selected` gates this on NDI — but detection itself stays a plain
    /// decode with no knowledge of NDI or `ndi.sources`. The is-this-actually-NDI
    /// judgment (port range, or a source IP already known from mDNS) happens in
    /// `handle_tcp`, the same place every other protocol's state-dependent
    /// narrowing happens.
    Tcp(TcpSegment),
}

/// A decoded TCP segment, independent of any protocol riding on top of it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TcpSegment {
    pub src:      Ipv4Addr,
    pub dst:      Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq:      u32,
    pub ack:      u32,
    pub has_fin:  bool,
    pub has_syn:  bool,
    pub has_rst:  bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FlowControlKind {
    Pause,                   // 802.3x global pause
    PriorityFlowControl,     // 802.1Qbb per-priority pause
}

#[derive(Debug, Clone, PartialEq)]
pub enum IgmpType {
    Join,                                        // IGMPv2 Membership Report (0x16)
    Leave,                                       // Leave Group (0x17)
    Query { version: u8 },                       // Membership Query (0x11); v2 payload=8B, v3 payload≥12B
    MembershipReportV3 { groups: Vec<Ipv4Addr> }, // IGMPv3 Report (0x22) — multiple Group Records
    Unknown(u8),
}

#[derive(Debug, Clone, PartialEq)]
pub struct PtpInfo {
    pub version:           u8,                      // wire value: PTPv1=1, PTPv2=2
    pub message_type:      u8,
    pub domain:            u8,
    pub clock_id:          Option<String>,
    pub grandmaster_id:    Option<String>,
    pub clock_quality:     Option<String>,
    pub correction_ns:     Option<i64>,
    pub path_delay_ns:     Option<i64>,
    // PTP message parsing improvements
    pub message_name:      String,                  // "Sync", "Follow_Up", "Delay_Req", "Delay_Resp", etc.
    pub port_id:           Option<u16>,
    pub sequence_id:       u16,
    pub log_sync_interval: i8,
    pub log_min_pdelay_req_interval: i8,
    // Protocol association
    pub protocol_kind:     Option<String>,           // Parent AV protocol name (AES67, ST2110, Dante, AVB)
    pub src_ip:            Option<std::net::Ipv4Addr>, // Source IP (UDP PTP); None for L2 gPTP
    // PTPv1 Sync only: raw grandmaster stratum (0=preferred master, 1=primary reference, …)
    pub stratum:           Option<u8>,
}

// Protocol choice enumeration
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolChoice {
    All,    // Monitor all standard AV protocols (PTP/IGMP always active)
    AES67,  // Audio over RTP
    Audio,  // Audio streams (AES67 + Dante + AVB)
    Video,  // Video streams (ST2110 + NDI)
    ST2110, // SMPTE ST 2110
    Dante,  // Dante digital audio
    NDI,    // NDI (NewTek/Vizrt)
    AVB,    // Audio Video Bridging
}

impl ProtocolChoice {
    /// Human-readable name for protocol choice
    pub fn name(&self) -> &'static str {
        match self {
            ProtocolChoice::All    => "All",
            ProtocolChoice::AES67  => "AES67",
            ProtocolChoice::Audio  => "Audio (AES67 + Dante + AVB)",
            ProtocolChoice::Video  => "Video (ST2110 + NDI)",
            ProtocolChoice::ST2110 => "ST2110",
            ProtocolChoice::Dante  => "Dante",
            ProtocolChoice::NDI    => "NDI",
            ProtocolChoice::AVB    => "AVB",
        }
    }

    /// Does this protocol require UDP packets?
    pub fn needs_udp(&self) -> bool {
        matches!(self, ProtocolChoice::AES67 | ProtocolChoice::Audio | ProtocolChoice::Video
            | ProtocolChoice::ST2110 | ProtocolChoice::Dante | ProtocolChoice::NDI)
    }

    /// Does this protocol require TCP packets?
    pub fn needs_tcp(&self) -> bool {
        matches!(self, ProtocolChoice::NDI)
    }

    /// Does this protocol require AVB (Ethernet AV) filtering?
    pub fn needs_avb(&self) -> bool {
        matches!(self, ProtocolChoice::AVB)
    }

    // All available protocol choices (LLDP/EEE always active; PTP/IGMP/SAP gated per protocol)
    pub fn all_choices() -> Vec<ProtocolChoice> {
        vec![
            ProtocolChoice::Audio,
            ProtocolChoice::Video,
            ProtocolChoice::AES67,
            ProtocolChoice::AVB,
            ProtocolChoice::Dante,
            ProtocolChoice::NDI,
            ProtocolChoice::ST2110,
        ]
    }

    /// Return list of protocols included in this choice
    pub fn includes(&self) -> Vec<ProtocolChoice> {
        match self {
            // All expands to every concrete protocol — without this expansion the
            // per-protocol gating in is_selected / PTP requirement checks falls
            // through to vacuously-true and silently disables alerts.
            ProtocolChoice::All => vec![
                ProtocolChoice::AES67,
                ProtocolChoice::ST2110,
                ProtocolChoice::Dante,
                ProtocolChoice::NDI,
                ProtocolChoice::AVB,
            ],
            ProtocolChoice::Audio => vec![
                ProtocolChoice::AES67,
                ProtocolChoice::Dante,
                ProtocolChoice::AVB,
            ],
            ProtocolChoice::Video => vec![
                ProtocolChoice::ST2110,
                ProtocolChoice::NDI,
            ],
            other => vec![other.clone()],
        }
    }

    /// Whether this protocol choice's traffic requires a PTP clock — the single
    /// source of truth for the rule, read both by `AvProtocol::is_selected`'s
    /// `Ptp` arm (gates real packet dispatch) and by `cli::selected_extras_display`
    /// (drives the cosmetic "(+ PTP)" startup-banner suffix). The two used to
    /// repeat the same variant list independently; a comment in cli.rs flagged
    /// the risk of them drifting apart.
    pub fn needs_ptp(&self) -> bool {
        matches!(self, ProtocolChoice::AES67 | ProtocolChoice::ST2110
            | ProtocolChoice::Dante | ProtocolChoice::AVB)
    }

    /// Whether this protocol choice's traffic requires IGMP (IP multicast
    /// protocols only) — same role as `needs_ptp`, one source of truth for both
    /// `is_selected`'s `Igmp` arm and the startup-banner suffix.
    pub fn needs_igmp(&self) -> bool {
        matches!(self, ProtocolChoice::AES67 | ProtocolChoice::ST2110 | ProtocolChoice::Dante)
    }
}

impl AvProtocol {
    pub fn is_selected(&self, expanded: &[ProtocolChoice]) -> bool {
        // ProtocolChoice::All is always fully expanded to concrete variants via includes()
        // before is_selected() is called, so All never appears in the expanded slice here.
        match self {
            AvProtocol::Aes67  { .. } => expanded.iter().any(|c| matches!(c, ProtocolChoice::AES67)),
            AvProtocol::St2110 { .. } => expanded.iter().any(|c| matches!(c, ProtocolChoice::ST2110)),
            AvProtocol::Dante  { .. } => expanded.iter().any(|c| matches!(c, ProtocolChoice::Dante)),
            AvProtocol::Ndi    { .. }
            | AvProtocol::Tcp  { .. } => expanded.iter().any(|c| matches!(c, ProtocolChoice::NDI)),
            AvProtocol::Avb    { .. }
            | AvProtocol::Msrp { .. }
            | AvProtocol::Mvrp { .. }
            | AvProtocol::AvdeccAdp(_) => expanded.iter().any(|c| matches!(c, ProtocolChoice::AVB)),
            AvProtocol::LldpEee { .. } => true,
            // Flow control is universal infrastructure — always relevant.
            AvProtocol::FlowControl { .. } => true,
            // PTP is relevant for all clock-dependent protocols; NDI uses its own timing
            AvProtocol::Ptp { .. } => expanded.iter().any(|c| c.needs_ptp()),
            // IGMP is only relevant for IP multicast protocols (AES67, ST2110, Dante)
            AvProtocol::Igmp { .. } => expanded.iter().any(|c| c.needs_igmp()),
            // SAP/SDP is only relevant for protocols that use it (AES67 and ST2110)
            AvProtocol::Sap { .. } =>
                expanded.iter().any(|c| matches!(c, ProtocolChoice::AES67 | ProtocolChoice::ST2110)),
        }
    }
}

#[cfg(test)]
mod gating_rules_tests {
    use super::*;

    #[test]
    fn needs_ptp_true_for_clock_dependent_protocols() {
        for c in [ProtocolChoice::AES67, ProtocolChoice::ST2110, ProtocolChoice::Dante, ProtocolChoice::AVB] {
            assert!(c.needs_ptp(), "{:?} should need PTP", c);
        }
    }

    #[test]
    fn needs_ptp_false_for_ndi() {
        // NDI uses its own TCP-based timing, no PTP.
        assert!(!ProtocolChoice::NDI.needs_ptp());
    }

    #[test]
    fn needs_igmp_true_only_for_ip_multicast_protocols() {
        for c in [ProtocolChoice::AES67, ProtocolChoice::ST2110, ProtocolChoice::Dante] {
            assert!(c.needs_igmp(), "{:?} should need IGMP", c);
        }
        assert!(!ProtocolChoice::AVB.needs_igmp(), "AVB is L2-only, no IP multicast");
        assert!(!ProtocolChoice::NDI.needs_igmp());
    }

    #[test]
    fn is_selected_igmp_arm_agrees_with_needs_igmp() {
        // Pins the relationship the deduplication relies on: is_selected's Igmp
        // arm must answer exactly what needs_igmp says for every concrete choice.
        let igmp = AvProtocol::Igmp {
            src: "0.0.0.0".parse().unwrap(), src_mac: [0; 6],
            group: "239.0.0.1".parse().unwrap(), igmp_type: IgmpType::Join,
        };
        for c in ProtocolChoice::all_choices() {
            for concrete in c.includes() {
                assert_eq!(igmp.is_selected(std::slice::from_ref(&concrete)), concrete.needs_igmp(),
                    "{:?} disagreement", concrete);
            }
        }
    }
}

/// Human-readable name for an AVTP subtype byte (IEEE 1722-2016 Table 6).
pub fn avtp_subtype_name(subtype: u8) -> &'static str {
    match subtype {
        0x00 => "IEC 61883",  // audio/video (most common AVB stream)
        0x01 => "MMA Streams",
        0x02 => "CRF",        // Clock Reference Format
        0x03 => "CVF",        // Compressed Video Format
        0x04 => "CEF",        // Control/Encrypted Format
        0x7E => "MAAP",       // MAC Address Acquisition Protocol
        0x7F => "Experimental",
        _    => "AVTP",
    }
}

// ── Stream Protocol Types ──

#[derive(Debug, Clone, PartialEq)]
pub enum St2110Type { Video, Audio, Ancdata, Unknown }

// ── AVB / MSRP types ──

#[derive(Debug, Clone, PartialEq)]
pub enum MsrpDeclType { TalkerAdvertise, TalkerFailed, Listener }

/// Human-readable reason for an MSRP TalkerFailed FailureCode (IEEE 802.1Qat
/// Table 35-6). Returns "unknown failure" for codes outside the standard set;
/// callers always show the numeric code alongside so an unmapped code is still
/// actionable. (Verified against a live AVB talker reporting code 8 — egress
/// port not AVB-capable — which the old 1/2/3-only table showed as "(failure)".)
pub fn msrp_failure_reason(code: u8) -> &'static str {
    match code {
        1  => "insufficient bandwidth",
        2  => "insufficient bridge resources",
        3  => "insufficient bandwidth for Traffic Class",
        4  => "StreamID already in use by another Talker",
        5  => "stream destination address already in use",
        6  => "stream pre-empted by a higher-rank stream",
        7  => "reported latency has changed",
        8  => "egress port is not AVB-capable",
        9  => "use a different destination address",
        10 => "out of MSRP resources",
        11 => "out of MMRP resources",
        12 => "cannot store destination address",
        13 => "requested priority is not an SR Class priority",
        14 => "MaxFrameSize too large for the media",
        15 => "max fan-in ports limit reached",
        16 => "changed FirstValue for a registered StreamID",
        17 => "VLAN blocked on this egress port (registration forbidden)",
        18 => "VLAN tagging disabled on this egress port",
        19 => "SR class priority mismatch",
        _  => "unknown failure",
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MsrpDeclaration {
    pub decl_type:           MsrpDeclType,
    pub stream_id:           [u8; 8],
    pub dest_mac:            Option<[u8; 6]>,
    pub vlan_id:             Option<u16>,
    pub max_frame_size:      Option<u16>,
    pub max_interval_frames: Option<u16>,
    pub priority:            Option<u8>,     // traffic class priority (0–7)
    pub failure_code:        Option<u8>,     // TalkerFailed only
    pub listener_state:      Option<u8>,     // Listener only: 0=Ignore 1=AskingFailed 2=Ready 3=ReadyFailed
}
#[derive(Debug, Clone, PartialEq)]
pub enum DanteKind {
    Discovery { device_name: Option<String> },
    AudioStream,
    Control,
    /// ConMon (Dante control & monitoring) multicast — 224.0.0.230–233, ports
    /// 8700–8708, "Audinate" signature at payload offset 16. Link-local
    /// multicast that snooping switches always flood: a continuous (~33 Hz
    /// metering) liveness signal visible from any port, no SPAN needed.
    ConMon { device_mac: [u8; 6], channels: Option<u8> },
    /// Product-specific control-plane traffic that positively identifies the
    /// source's Transmitter Class by its port family (DVS / Via / Hardware-FPGA).
    /// See `dante_control_plane_class`.
    ControlPlane { class: TransmitterClass },
}

// ── Transmitter Class (CONTEXT.md) ──

/// Which kind of Dante implementation is sourcing a Dante Audio Flow. "Software
/// Dante" is not one class — DVS and Via are distinct products.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransmitterClass {
    Hardware, // FPGA / embedded endpoint
    Dvs,      // Dante Virtual Soundcard (software)
    Via,      // Dante Via (a different software product)
}

impl TransmitterClass {
    /// User-facing label, using Audinate's product vocabulary.
    pub fn label(self) -> &'static str {
        match self {
            TransmitterClass::Hardware => "Hardware",
            TransmitterClass::Dvs => "DVS",
            TransmitterClass::Via => "Via",
        }
    }
}

/// How strongly a Transmitter Class verdict is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransmitterConfidence {
    Confirmed, // positive control-plane port fingerprint
    Inferred,  // from timing and/or TTL, no control plane
    Hint,      // weakest — absent QoS marking (DSCP 0) only
}

/// A Transmitter Class verdict plus how confident it is and how many independent
/// signals support it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransmitterVerdict {
    pub class: TransmitterClass,
    pub confidence: TransmitterConfidence,
    pub signals: u8,
}

/// Independent signals about a Dante flow's source, fed to `classify_transmitter`.
/// Fields are populated as evidence arrives within a Session; an empty struct
/// yields no verdict.
#[derive(Debug, Clone, Copy, Default)]
pub struct TransmitterSignals {
    /// Positive control-plane port fingerprint, if the source's control traffic was seen.
    pub control_plane: Option<TransmitterClass>,
    /// Packet-timing regularity: Some(true) = metronomic (hardware), Some(false) = noisy (software).
    pub metronomic: Option<bool>,
    /// Source host TTL (e.g. 128 → Windows host → software).
    pub ttl: Option<u8>,
    /// Audio flow arrived with no DSCP marking (DSCP 0).
    pub dscp_zero: bool,
}

/// Classify a UDP flow as Dante control-plane traffic by its product-specific
/// port family (Audinate's published port list), returning the Transmitter Class
/// that family positively identifies. None if neither port belongs to a known
/// family. Hardware ConMon (8700–8708) and control (8800) are handled by the
/// existing ConMon/Control detection, not here.
pub fn dante_control_plane_class(src_port: u16, dst_port: u16) -> Option<TransmitterClass> {
    let either = |f: &dyn Fn(u16) -> bool| f(src_port) || f(dst_port);
    // DVS control & monitoring: external 38700–38708 / 38800, internal 38900 / 8899.
    let is_dvs = |p: u16| (38700..=38708).contains(&p) || p == 38800 || p == 38900 || p == 8899;
    // Via: control & monitoring 28700–28708 / 28800 / 28900, control 4777,
    // audio control 24440/24441/24444/24455, audio 34336–34600.
    let is_via = |p: u16| (28700..=28708).contains(&p) || p == 28800 || p == 28900 || p == 4777
        || matches!(p, 24440 | 24441 | 24444 | 24455) || (34336..=34600).contains(&p);
    // Hardware/FPGA tells: metering 8751 (FPGA-based devices), FPGA flow keepalive 61440–61951.
    let is_hw = |p: u16| p == 8751 || (61440..=61951).contains(&p);
    if either(&is_dvs) { Some(TransmitterClass::Dvs) }
    else if either(&is_via) { Some(TransmitterClass::Via) }
    else if either(&is_hw) { Some(TransmitterClass::Hardware) }
    else { None }
}

/// Decide the Transmitter Class from independent signals. Pure — no IO, no state.
///
/// Precedence (CONTEXT.md): the control-plane fingerprint is near-authoritative
/// and wins when present. Timing regularity is the confound-proof fallback and
/// **overrides** the DSCP signal — a metronomic source is Hardware even at DSCP 0.
/// TTL corroborates. DSCP 0 alone is only a weak hint and never a sole basis for
/// a confident DVS verdict. Inferred software defaults to DVS — distinguishing
/// DVS from Via requires the control plane. Returns None when nothing points
/// anywhere.
pub fn classify_transmitter(s: &TransmitterSignals) -> Option<TransmitterVerdict> {
    use TransmitterClass::*;
    use TransmitterConfidence::*;

    // 1. Control plane — positive identification, plus any corroborating signals.
    if let Some(class) = s.control_plane {
        let mut signals = 1u8;
        match class {
            Hardware => {
                if s.metronomic == Some(true) { signals += 1; }
            }
            Dvs | Via => {
                if s.metronomic == Some(false) { signals += 1; }
                if s.ttl == Some(128) { signals += 1; }
                if s.dscp_zero { signals += 1; }
            }
        }
        return Some(TransmitterVerdict { class, confidence: Confirmed, signals });
    }

    // 2. Timing regularity — confound-proof; overrides DSCP.
    if let Some(metronomic) = s.metronomic {
        return Some(if metronomic {
            TransmitterVerdict { class: Hardware, confidence: Inferred, signals: 1 }
        } else {
            let mut signals = 1u8;
            if s.ttl == Some(128) { signals += 1; }
            if s.dscp_zero { signals += 1; }
            TransmitterVerdict { class: Dvs, confidence: Inferred, signals }
        });
    }

    // 3. TTL alone — Windows host → software.
    if s.ttl == Some(128) {
        let mut signals = 1u8;
        if s.dscp_zero { signals += 1; }
        return Some(TransmitterVerdict { class: Dvs, confidence: Inferred, signals });
    }

    // 4. DSCP 0 alone — weakest hint, never confident.
    if s.dscp_zero {
        return Some(TransmitterVerdict { class: Dvs, confidence: Hint, signals: 1 });
    }

    None
}

/// Whether `s` classifies as software (DVS/Via) when the DSCP-zero signal is
/// excluded. The DSCP-violation gate needs this rather than the displayed
/// verdict from `classify_transmitter(s)` directly — otherwise DSCP 0 would
/// suppress its own violation, and a misconfigured hardware device sending
/// DSCP 0 would go unflagged. Keeping the override here, rather than at each
/// call site building its own `TransmitterSignals { dscp_zero: false, ..s }`
/// copy, is what stops the two from drifting again — they already have once
/// (a prior copy silently dropped the TTL signal too, not just dscp_zero).
pub fn is_software_ignoring_dscp(s: &TransmitterSignals) -> bool {
    let s = TransmitterSignals { dscp_zero: false, ..*s };
    classify_transmitter(&s).is_some_and(|v| matches!(v.class, TransmitterClass::Dvs | TransmitterClass::Via))
}
#[derive(Debug, Clone, PartialEq)]
pub enum NdiKind {
    Discovery { source_name: Option<String> },
}

// ── AVDECC ADP (IEEE 1722.1 discovery) ──

/// Parsed payload of an AVDECC ADP (AVDECC Discovery Protocol) frame.
/// ADP uses AVTP EtherType (0x22F0), subtype 0x7A with cd=1 → wire byte 0 = 0xFA.
/// Destination MAC 91:E0:F0:01:00:00 is a globally registered (forwardable) multicast.
#[derive(Debug, Clone, PartialEq)]
pub struct AvdeccAdp {
    pub message_type:          u8,       // 0=ENTITY_AVAILABLE, 1=ENTITY_DEPARTING, 2=ENTITY_DISCOVER
    pub entity_id:             [u8; 8],  // EUI-64 of the announcing entity
    pub entity_model_id:       [u8; 8],  // EUI-64 identifying the product model (OUI = vendor)
    pub entity_capabilities:   u32,      // bitmask: AEM_SUPPORTED=0x08, CLASS_A=0x100, CLASS_B=0x200
    pub talker_stream_sources: u16,      // number of talker streams this entity can source
    pub talker_capabilities:   u16,      // bitmask: IMPLEMENTED=0x01, AUDIO=0x200, VIDEO=0x400
    pub listener_stream_sinks: u16,      // number of listener sinks
    pub listener_capabilities: u16,      // bitmask: IMPLEMENTED=0x01, AUDIO=0x200, VIDEO=0x400
    pub gptp_grandmaster_id:   [u8; 8],  // EUI-64 of the gPTP grandmaster this entity is using
    pub gptp_domain_number:    u8,       // gPTP domain (usually 0)
    pub valid_time_secs:       u64,      // announcement lifetime in seconds (valid_time field × 2)
    pub available_index:       u32,      // increments each time the entity's state changes
}

// ── SDP metadata (from SAP/SDP parser) ──

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SdpSession {
    pub session_id:   String,
    pub session_name: String,
    pub info:         String,
    pub media:        Vec<SdpMedia>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SdpMedia {
    pub media_type:    String,
    pub port:          u16,
    pub payload_types: Vec<u8>,
    pub connection:    String,
    pub rtpmap:        String,
    pub clock_hz:      f64,
    pub channels:      u8,
    pub ptime_ms:      f64,
    pub ts_refclk:     String,
    pub mediaclk:      String,
}

#[cfg(test)]
mod transmitter_tests {
    use super::*;

    // ── dante_control_plane_class ─────────────────────────────────────────────
    #[test]
    fn dvs_control_ports_classify_dvs() {
        assert_eq!(dante_control_plane_class(38700, 50000), Some(TransmitterClass::Dvs));
        assert_eq!(dante_control_plane_class(50000, 38708), Some(TransmitterClass::Dvs));
        assert_eq!(dante_control_plane_class(38800, 1), Some(TransmitterClass::Dvs));
        assert_eq!(dante_control_plane_class(8899, 1), Some(TransmitterClass::Dvs));
    }

    #[test]
    fn via_control_ports_classify_via() {
        assert_eq!(dante_control_plane_class(28700, 50000), Some(TransmitterClass::Via));
        assert_eq!(dante_control_plane_class(4777, 1), Some(TransmitterClass::Via));
        assert_eq!(dante_control_plane_class(34336, 1), Some(TransmitterClass::Via));
        assert_eq!(dante_control_plane_class(24444, 1), Some(TransmitterClass::Via));
    }

    #[test]
    fn fpga_ports_classify_hardware() {
        assert_eq!(dante_control_plane_class(8751, 1), Some(TransmitterClass::Hardware));
        assert_eq!(dante_control_plane_class(1, 61440), Some(TransmitterClass::Hardware));
    }

    #[test]
    fn unrelated_ports_classify_nothing() {
        assert_eq!(dante_control_plane_class(5004, 5004), None);
        assert_eq!(dante_control_plane_class(8700, 8800), None); // hardware ConMon/control handled elsewhere
    }

    // ── classify_transmitter: control-plane (Confirmed) ───────────────────────
    #[test]
    fn control_plane_dvs_is_confirmed() {
        let v = classify_transmitter(&TransmitterSignals {
            control_plane: Some(TransmitterClass::Dvs), ..Default::default()
        }).unwrap();
        assert_eq!(v.class, TransmitterClass::Dvs);
        assert_eq!(v.confidence, TransmitterConfidence::Confirmed);
    }

    #[test]
    fn control_plane_via_is_confirmed() {
        let v = classify_transmitter(&TransmitterSignals {
            control_plane: Some(TransmitterClass::Via), ..Default::default()
        }).unwrap();
        assert_eq!(v.class, TransmitterClass::Via);
        assert_eq!(v.confidence, TransmitterConfidence::Confirmed);
    }

    #[test]
    fn control_plane_hardware_is_confirmed() {
        let v = classify_transmitter(&TransmitterSignals {
            control_plane: Some(TransmitterClass::Hardware), ..Default::default()
        }).unwrap();
        assert_eq!(v.class, TransmitterClass::Hardware);
        assert_eq!(v.confidence, TransmitterConfidence::Confirmed);
    }

    #[test]
    fn no_signals_no_verdict() {
        assert!(classify_transmitter(&TransmitterSignals::default()).is_none());
    }

    // ── classify_transmitter: timing fallback + precedence ────────────────────
    #[test]
    fn metronomic_timing_overrides_dscp_zero_to_hardware() {
        // A metronomic source is Hardware even with no QoS marking — timing beats DSCP.
        let v = classify_transmitter(&TransmitterSignals {
            metronomic: Some(true), dscp_zero: true, ..Default::default()
        }).unwrap();
        assert_eq!(v.class, TransmitterClass::Hardware);
        assert_eq!(v.confidence, TransmitterConfidence::Inferred);
    }

    #[test]
    fn noisy_timing_infers_dvs() {
        let v = classify_transmitter(&TransmitterSignals {
            metronomic: Some(false), ..Default::default()
        }).unwrap();
        assert_eq!(v.class, TransmitterClass::Dvs);
        assert_eq!(v.confidence, TransmitterConfidence::Inferred);
    }

    #[test]
    fn control_plane_overrides_timing_for_confirmed_verdict() {
        // Timing alone would say Hardware; a DVS control-plane fingerprint wins and
        // upgrades the verdict to Confirmed.
        let v = classify_transmitter(&TransmitterSignals {
            control_plane: Some(TransmitterClass::Dvs), metronomic: Some(true), ..Default::default()
        }).unwrap();
        assert_eq!(v.class, TransmitterClass::Dvs);
        assert_eq!(v.confidence, TransmitterConfidence::Confirmed);
    }

    // ── classify_transmitter: TTL corroboration + confidence ──────────────────
    #[test]
    fn ttl_128_alone_infers_dvs() {
        let v = classify_transmitter(&TransmitterSignals { ttl: Some(128), ..Default::default() }).unwrap();
        assert_eq!(v.class, TransmitterClass::Dvs);
        assert_eq!(v.confidence, TransmitterConfidence::Inferred);
    }

    #[test]
    fn ttl_128_does_not_override_metronomic_hardware() {
        // A metronomic source stays Hardware even with a Windows-like TTL — timing wins.
        let v = classify_transmitter(&TransmitterSignals {
            metronomic: Some(true), ttl: Some(128), ..Default::default()
        }).unwrap();
        assert_eq!(v.class, TransmitterClass::Hardware);
    }

    #[test]
    fn dscp_zero_alone_is_only_a_hint() {
        let v = classify_transmitter(&TransmitterSignals { dscp_zero: true, ..Default::default() }).unwrap();
        assert_eq!(v.class, TransmitterClass::Dvs);
        assert_eq!(v.confidence, TransmitterConfidence::Hint);
        assert_eq!(v.signals, 1);
    }

    #[test]
    fn confirmed_verdict_counts_corroborating_signals() {
        // Control-plane DVS + noisy timing + Windows TTL + no QoS marking = 4 signals.
        let v = classify_transmitter(&TransmitterSignals {
            control_plane: Some(TransmitterClass::Dvs),
            metronomic: Some(false),
            ttl: Some(128),
            dscp_zero: true,
        }).unwrap();
        assert_eq!(v.class, TransmitterClass::Dvs);
        assert_eq!(v.confidence, TransmitterConfidence::Confirmed);
        assert_eq!(v.signals, 4);
    }

    // ── is_software_ignoring_dscp ──────────────────────────────────────────────

    #[test]
    fn is_software_ignoring_dscp_agrees_with_ttl_only_verdict() {
        // Regression for the drift bug: TTL 128 alone infers DVS (see
        // ttl_128_alone_infers_dvs above). The DSCP gate must reach the same
        // class without dscp_zero in play, not just without it explicitly set.
        let s = TransmitterSignals { ttl: Some(128), dscp_zero: true, ..Default::default() };
        assert!(is_software_ignoring_dscp(&s));
    }

    #[test]
    fn is_software_ignoring_dscp_false_for_hardware_control_plane() {
        let s = TransmitterSignals {
            control_plane: Some(TransmitterClass::Hardware), dscp_zero: true, ..Default::default()
        };
        assert!(!is_software_ignoring_dscp(&s));
    }

    #[test]
    fn is_software_ignoring_dscp_false_with_no_other_signals() {
        // dscp_zero is the ONLY signal — excluding it must leave no verdict at all,
        // so the unclassified/hardware case still gets flagged for DSCP 0.
        let s = TransmitterSignals { dscp_zero: true, ..Default::default() };
        assert!(!is_software_ignoring_dscp(&s));
    }
}
