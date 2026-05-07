// AVStreamLens — src/protocols.rs
// Contains all network protocol definitions, enums, and constants.

use std::net::Ipv4Addr;

// ═══════════════════════════════════════════════════════════
// SECTION 1 — TYPES AND CONSTANTS
// ═══════════════════════════════════════════════════════════

// Ports and network ranges
pub const SAP_PORT:          u16 = 9875;
pub const MDNS_PORT:         u16 = 5353;
pub const ETHERTYPE_AVTP:    u16 = 0x22F0;
pub const ETHERTYPE_PTP:     u16 = 0x88F7;
pub const PTP_EVENT_PORT:    u16 = 319;
pub const PTP_GENERAL_PORT:  u16 = 320;
pub const DANTE_CTRL_PORTS: &[u16] = &[4440, 4455, 8700, 8800];
pub const NDI_PORT_MIN:      u16 = 5960;
pub const NDI_PORT_MAX:      u16 = 5980;
pub const SRT_MAGIC:         u32 = 0x00000004; // SRT_CMD_HANDSHAKE induction
pub const RIST_PORT_BASE:    u16 = 5000;
pub const IP_PROTO_IGMP:     u8  = 0x02;
pub const STREAM_TIMEOUT_SECS: u64 = 10;

// Default RTP clock frequency
pub const DEFAULT_CLOCK_HZ: f64 = 48_000.0;

// ❖ Protocol Choices and Enums ❖

#[derive(Debug, Clone, PartialEq)]
pub enum AvProtocol {
    Aes67  { src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16, payload_type: u8 },
    St2110 { src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16, stream_type: St2110Type },
    Dante  { kind: DanteKind, src: Ipv4Addr, dst_port: u16 },
    Ndi    { kind: NdiKind,   src: Ipv4Addr },
    Avb    { subtype: u8 },
    Sap    { src: Ipv4Addr, sdp: SdpSession },
    Ptp    { info: PtpInfo },
    // ── Nouveaux protocoles ──
    Srt    { src: Ipv4Addr, dst_port: u16, is_handshake: bool },
    Rist   { src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16 },
    Igmp   { src: Ipv4Addr, group: Ipv4Addr, igmp_type: IgmpType },
}

#[derive(Debug, Clone, PartialEq)]
pub enum IgmpType {
    Join,       // Membership Report v2/v3
    Leave,      // Leave Group
    Query,      // Membership Query
    Unknown(u8),
}

#[derive(Debug, Clone, PartialEq)]
pub struct PtpInfo {
    pub version: u8,
    pub message_type: u8,
    pub domain: u8,
    pub clock_id: Option<String>,
    pub grandmaster_id: Option<String>,
    pub clock_quality: Option<String>,
    pub correction_ns: Option<i64>,
    pub path_delay_ns: Option<i64>,
    pub origin_timestamp_ns: Option<u64>,
    // PTP message parsing improvements
    pub message_name: String,        // "Sync", "Follow_Up", "Delay_Req", "Delay_Resp", etc.
    pub port_id: Option<u16>,
    pub sequence_id: u16,
    pub log_sync_interval: i8,
    pub log_min_pdelay_req_interval: i8,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolChoice { All, AES67, Audio, Video, ST2110, Dante, NDI, AVB, PTP, SRT, RIST, IGMP }

impl ProtocolChoice {
    pub fn name(&self) -> &'static str {
        match self {
            ProtocolChoice::All   => "All",
            ProtocolChoice::AES67 => "AES67",
            ProtocolChoice::Audio => "Audio (AES67 + Dante + RIST)",
            ProtocolChoice::Video => "Video (ST2110 + NDI + SRT + RIST)",
            ProtocolChoice::ST2110 => "ST2110",
            ProtocolChoice::Dante => "Dante",
            ProtocolChoice::NDI   => "NDI",
            ProtocolChoice::AVB   => "AVB",
            ProtocolChoice::PTP   => "PTP",
            ProtocolChoice::SRT   => "SRT",
            ProtocolChoice::RIST  => "RIST",
            ProtocolChoice::IGMP  => "IGMP",
        }
    }

    pub fn needs_udp(&self) -> bool {
        matches!(self, ProtocolChoice::AES67 | ProtocolChoice::Audio | ProtocolChoice::Video
            | ProtocolChoice::ST2110 | ProtocolChoice::Dante
            | ProtocolChoice::NDI | ProtocolChoice::PTP | ProtocolChoice::SRT | ProtocolChoice::RIST)
    }

    pub fn needs_avb(&self) -> bool {
        matches!(self, ProtocolChoice::AVB)
    }

    pub fn needs_ptp_filter(&self) -> bool {
        matches!(self, ProtocolChoice::PTP)
    }

    pub fn requires_valid_ptp_clock(&self) -> bool {
        matches!(self, ProtocolChoice::AES67 | ProtocolChoice::Audio | ProtocolChoice::Video
            | ProtocolChoice::ST2110 | ProtocolChoice::AVB)
    }

    pub fn all_choices() -> Vec<ProtocolChoice> {
        // PTP et IGMP sont toujours actifs — non présents ici
        vec![
            ProtocolChoice::Audio,
            ProtocolChoice::Video,
            ProtocolChoice::AES67,
            ProtocolChoice::AVB,
            ProtocolChoice::Dante,
            ProtocolChoice::NDI,
            ProtocolChoice::ST2110,
            ProtocolChoice::SRT,
            ProtocolChoice::RIST,
        ]
    }

    /// Protocoles inclus dans ce choix (pour affichage et expansion)
    pub fn includes(&self) -> Vec<ProtocolChoice> {
        match self {
            ProtocolChoice::Audio => vec![
                ProtocolChoice::AES67,
                ProtocolChoice::Dante,
                ProtocolChoice::RIST,
            ],
            ProtocolChoice::Video => vec![
                ProtocolChoice::ST2110,
                ProtocolChoice::NDI,
                ProtocolChoice::SRT,
                ProtocolChoice::RIST,
            ],
            other => vec![other.clone()],
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum St2110Type { Video, Audio, Ancdata, Unknown }

#[derive(Debug, Clone, PartialEq)]
pub enum DanteKind  { Discovery, AudioStream, Control }

#[derive(Debug, Clone, PartialEq)]
pub enum NdiKind    { Discovery, Stream }

// ───olutamente───────────────────────────────────────────────────
// SDP metadata (from SAP/SDP parser)
// ─────────────────────────────────────────────────────────
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
