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
}

impl AvProtocol {
    pub fn is_selected(&self, expanded: &[ProtocolChoice]) -> bool {
        // ProtocolChoice::All is always fully expanded to concrete variants via includes()
        // before is_selected() is called, so All never appears in the expanded slice here.
        match self {
            AvProtocol::Aes67  { .. } => expanded.iter().any(|c| matches!(c, ProtocolChoice::AES67)),
            AvProtocol::St2110 { .. } => expanded.iter().any(|c| matches!(c, ProtocolChoice::ST2110)),
            AvProtocol::Dante  { .. } => expanded.iter().any(|c| matches!(c, ProtocolChoice::Dante)),
            AvProtocol::Ndi    { .. } => expanded.iter().any(|c| matches!(c, ProtocolChoice::NDI)),
            AvProtocol::Avb    { .. }
            | AvProtocol::Msrp { .. }
            | AvProtocol::Mvrp { .. }
            | AvProtocol::AvdeccAdp(_) => expanded.iter().any(|c| matches!(c, ProtocolChoice::AVB)),
            AvProtocol::LldpEee { .. } => true,
            // Flow control is universal infrastructure — always relevant.
            AvProtocol::FlowControl { .. } => true,
            // PTP is relevant for all clock-dependent protocols; NDI uses its own timing
            AvProtocol::Ptp { .. } =>
                expanded.iter().any(|c| matches!(c,
                    ProtocolChoice::AES67 | ProtocolChoice::ST2110
                    | ProtocolChoice::Dante | ProtocolChoice::AVB)),
            // IGMP is only relevant for IP multicast protocols (AES67, ST2110, Dante)
            AvProtocol::Igmp { .. } =>
                expanded.iter().any(|c| matches!(c, ProtocolChoice::AES67 | ProtocolChoice::ST2110 | ProtocolChoice::Dante)),
            // SAP/SDP is only relevant for protocols that use it (AES67 and ST2110)
            AvProtocol::Sap { .. } =>
                expanded.iter().any(|c| matches!(c, ProtocolChoice::AES67 | ProtocolChoice::ST2110)),
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
