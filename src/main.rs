// AVStreamLens — main.rs
//
// IP AV Monitoring: AES67, SMPTE ST 2110, Dante, NDI, AVB, SRT, RIST
// - Pcap capture with BPF filter
// - Protocol detection by network signature (Audio/Video presets)
// - SAP/SDP parser for stream metadata
// - RFC 3550 jitter, SSRC tracking, dead-stream detection
// - PTP (IEEE 1588) and IGMP always monitored
// - Terminal reporting every 5 seconds

use pcap::{Capture, Device};
use pnet_packet::{
    ethernet::{EthernetPacket, EtherTypes},
    ipv4::Ipv4Packet,
    udp::UdpPacket,
    tcp::TcpPacket,
    Packet,
};
use chrono::{Datelike, Local, Timelike};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

// ═══════════════════════════════════════════════════════════
// SECTION 1 — TYPES AND CONSTANTS
// ═══════════════════════════════════════════════════════════

const DEFAULT_BPF_FILTER: &str = "udp or (ether proto 0x22f0) or (ether proto 0x88f7)";

// Default RTP clock frequency (will be overwritten by SDP if available)
const DEFAULT_CLOCK_HZ: f64 = 48_000.0;

// Ports and network ranges
const SAP_PORT:          u16 = 9875;
const MDNS_PORT:         u16 = 5353;
const ETHERTYPE_AVTP:    u16 = 0x22F0;
const ETHERTYPE_PTP:     u16 = 0x88F7;
const PTP_EVENT_PORT:    u16 = 319;
const PTP_GENERAL_PORT:  u16 = 320;
const DANTE_CTRL_PORTS: &[u16] = &[4440, 4455, 8700, 8800];
const NDI_PORT_MIN:      u16 = 5960;
const NDI_PORT_MAX:      u16 = 5980;
// SRT : pas de port fixe standard, mais le handshake est identifiable
// Convention commune : 9000-9999 et ports éphémères
const SRT_MAGIC:         u32 = 0x00000004; // SRT_CMD_HANDSHAKE induction
// RIST : RTP + RTCP avec ARQ, convention ports pairs/impairs
const RIST_PORT_BASE:    u16 = 5000;
// IGMP : protocole IP 0x02
const IP_PROTO_IGMP:     u8  = 0x02;
// Timeout flux mort : 10 secondes sans paquet
const STREAM_TIMEOUT_SECS: u64 = 10;

// ─────────────────────────────────────────────────────────
// Detected protocols
// ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum AvProtocol {
    Aes67  { src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16, payload_type: u8 },
    St2110 { src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16, stream_type: St2110Type },
    Dante  { kind: DanteKind, src: Ipv4Addr, dst_port: u16 },
    Ndi    { kind: NdiKind,   src: Ipv4Addr },
    Avb    { subtype: u8 },
    Sap    { src: Ipv4Addr, sdp: SdpSession },
    Ptp    { info: PtpInfo },
    // ── Nouveaux protocoles ──
    /// SRT (Secure Reliable Transport) — détecté par magic handshake
    Srt    { src: Ipv4Addr, dst_port: u16, is_handshake: bool },
    /// RIST (Reliable Internet Stream Transport) — RTP + ARQ
    Rist   { src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16 },
    /// IGMP — adhésions/départs multicast
    Igmp   { src: Ipv4Addr, group: Ipv4Addr, igmp_type: IgmpType },
}

#[derive(Debug, Clone, PartialEq)]
enum IgmpType {
    Join,       // Membership Report v2/v3
    Leave,      // Leave Group
    Query,      // Membership Query
    Unknown(u8),
}

#[derive(Debug, Clone, PartialEq)]
struct PtpInfo {
    version: u8,
    message_type: u8,
    domain: u8,
    clock_id: Option<String>,
    grandmaster_id: Option<String>,
    clock_quality: Option<String>,
    correction_ns: Option<i64>,
    path_delay_ns: Option<i64>,
    origin_timestamp_ns: Option<u64>,
    // PTP message parsing improvements
    message_name: String,        // "Sync", "Follow_Up", "Delay_Req", "Delay_Resp", etc.
    port_id: Option<u16>,
    sequence_id: u16,
    log_sync_interval: i8,
    log_min_pdelay_req_interval: i8,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
enum ProtocolChoice { All, AES67, Audio, Video, ST2110, Dante, NDI, AVB, PTP, SRT, RIST, IGMP }

impl ProtocolChoice {
    fn name(&self) -> &'static str {
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

    fn needs_udp(&self) -> bool {
        matches!(self, ProtocolChoice::AES67 | ProtocolChoice::Audio | ProtocolChoice::Video
            | ProtocolChoice::ST2110 | ProtocolChoice::Dante
            | ProtocolChoice::NDI | ProtocolChoice::PTP | ProtocolChoice::SRT | ProtocolChoice::RIST)
    }

    fn needs_avb(&self) -> bool {
        matches!(self, ProtocolChoice::AVB)
    }

    fn needs_ptp_filter(&self) -> bool {
        matches!(self, ProtocolChoice::PTP)
    }

    fn requires_valid_ptp_clock(&self) -> bool {
        matches!(self, ProtocolChoice::AES67 | ProtocolChoice::Audio | ProtocolChoice::Video
            | ProtocolChoice::ST2110 | ProtocolChoice::AVB)
    }

    fn all_choices() -> Vec<ProtocolChoice> {
        // PTP et IGMP sont toujours actifs — non présents ici
        vec![
            ProtocolChoice::AES67,
            ProtocolChoice::Audio,
            ProtocolChoice::Video,
            ProtocolChoice::ST2110,
            ProtocolChoice::Dante,
            ProtocolChoice::NDI,
            ProtocolChoice::AVB,
            ProtocolChoice::SRT,
            ProtocolChoice::RIST,
        ]
    }

    /// Protocoles inclus dans ce choix (pour affichage et expansion)
    fn includes(&self) -> Vec<ProtocolChoice> {
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
enum St2110Type { Video, Audio, Ancdata, Unknown }

#[derive(Debug, Clone, PartialEq)]
enum DanteKind  { Discovery, AudioStream, Control }

#[derive(Debug, Clone, PartialEq)]
enum NdiKind    { Discovery, Stream }

// ─────────────────────────────────────────────────────────
// SDP metadata (from SAP/SDP parser)
// ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Default)]
struct SdpSession {
    /// o= — session identifier (origin)
    pub session_id:   String,
    /// s= — readable stream name
    pub session_name: String,
    /// i= — optional description
    pub info:         String,
    /// List of announced media in this session
    pub media:        Vec<SdpMedia>,
}

#[derive(Debug, Clone, PartialEq, Default)]
struct SdpMedia {
    /// m= type: "audio", "video", "application"
    pub media_type:    String,
    /// m= RTP destination port
    pub port:          u16,
    /// m= declared payload types
    pub payload_types: Vec<u8>,
    /// c= connection address (multicast destination)
    pub connection:    String,
    /// a=rtpmap — e.g.: "L24/48000/8"
    pub rtpmap:        String,
    /// a=clock-rate extracted from rtpmap
    pub clock_hz:      f64,
    /// a=channels extracted from rtpmap
    pub channels:      u8,
    /// a=ptime (ms)
    pub ptime_ms:      f64,
    /// a=ts-refclk — PTP clock reference (AES67/ST2110)
    pub ts_refclk:     String,
    /// a=mediaclk — media clock source
    pub mediaclk:      String,
}

// ─────────────────────────────────────────────────────────
// RTP stream statistics
// ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct StreamStats {
    protocol:          String,
    packets:           u64,
    lost_packets:      u64,
    last_seq:          Option<u16>,
    jitter:            f64,        // seconds, RFC 3550
    last_rtp_ts:       Option<u32>,
    last_arrival:      Option<Instant>,
    clock_hz:          f64,
    sdp_name:          Option<String>,
    sdp_rtpmap:        Option<String>,
    // Enhanced information
    is_multicast:      bool,
    dst_ip:            Option<Ipv4Addr>,
    dst_port:          u16,
    media_type:        String,    // "audio", "video", "ancillary" or "unknown"
    channels:          u8,         // for audio
    bitrate_bps:       u64,        // calculated bitrate
    last_bitrate_check: Instant,
    packets_at_check:  u64,
    // Timestamp discontinuity detection
    ts_discontinuities: u64,
    last_ts_diff:       Option<i64>,
    // ptime SDP (ms) — tolérance pour la détection de discontinuités TS
    ptime_ms:           f64,
    // Bitrate exact : accumulateur d'octets UDP réels
    bytes_total:        u64,
    bytes_at_check:     u64,
    // SSRC tracking — changement = interruption de source RTP
    last_ssrc:          Option<u32>,
    ssrc_changes:       u64,
    // Dernier paquet reçu — pour détecter les flux morts (silence)
    last_packet_time:   Option<Instant>,
    // Flag: évite de répéter l'alerte "stream dead" à chaque rapport
    // Réinitialisé à false dès qu'un paquet est reçu
    dead_alerted:       bool,
}

impl StreamStats {
    fn new(protocol: &str, clock_hz: f64) -> Self {
        Self {
            protocol:            protocol.to_string(),
            packets:             0,
            lost_packets:        0,
            last_seq:            None,
            jitter:              0.0,
            last_rtp_ts:         None,
            last_arrival:        None,
            clock_hz,
            sdp_name:            None,
            sdp_rtpmap:          None,
            is_multicast:        false,
            dst_ip:              None,
            dst_port:            0,
            media_type:          "unknown".to_string(),
            channels:            0,
            bitrate_bps:         0,
            last_bitrate_check:  Instant::now(),
            packets_at_check:    0,
            ts_discontinuities:  0,
            last_ts_diff:        None,
            ptime_ms:            0.0,
            bytes_total:         0,
            bytes_at_check:      0,
            last_ssrc:           None,
            ssrc_changes:        0,
            last_packet_time:    None,
            dead_alerted:        false,
        }
    }

    fn new_with_info(protocol: &str, clock_hz: f64, is_multicast: bool, dst_ip: Ipv4Addr, dst_port: u16) -> Self {
        let mut stats = Self::new(protocol, clock_hz);
        stats.is_multicast = is_multicast;
        stats.dst_ip = Some(dst_ip);
        stats.dst_port = dst_port;
        stats
    }

    /// `udp_payload_len` : longueur réelle du payload UDP (sans header IP/UDP),
    /// utilisée pour le calcul de bitrate exact.
    fn update(&mut self, seq: u16, rtp_ts: u32, ssrc: u32, udp_payload_len: usize) {
        self.packets += 1;

        // ── Losses (16-bit wrapping) ──────────────────
        if let Some(last) = self.last_seq {
            let expected = last.wrapping_add(1);
            if seq != expected {
                self.lost_packets += seq.wrapping_sub(expected) as u64;
            }
        }
        self.last_seq = Some(seq);

        // ── Timestamp discontinuity detection ────────
        // La tolérance est dérivée du ptime SDP si disponible,
        // sinon estimée depuis la clock (1 paquet = 1 ms par défaut).
        if let Some(last_ts) = self.last_rtp_ts {
            let expected_diff = if self.clock_hz > 0.0 {
                let ptime_ms = if self.ptime_ms > 0.0 { self.ptime_ms } else { 1.0 };
                (self.clock_hz * ptime_ms / 1000.0) as i64
            } else {
                48 // fallback : 1 ms @ 48 kHz
            };
            let actual_diff = rtp_ts.wrapping_sub(last_ts) as i64;
            // Tolérance ±50 % autour du ptime attendu
            if expected_diff > 0 &&
               ((actual_diff as f64) < (expected_diff as f64 * 0.5) ||
                (actual_diff as f64) > (expected_diff as f64 * 1.5))
            {
                self.ts_discontinuities += 1;
            }
            self.last_ts_diff = Some(actual_diff);
        }

        // ── RFC 3550 §6.4.1 Jitter ────────────────────
        //   D(i,j) = | (Rj−Ri) − (Sj−Si) |
        //   J(i)   = J(i−1) + (D − J(i−1)) / 16
        let now = Instant::now();
        if let (Some(last_ts), Some(last_time)) = (self.last_rtp_ts, self.last_arrival) {
            let arrival_diff = now.duration_since(last_time).as_secs_f64();
            let rtp_diff     = rtp_ts.wrapping_sub(last_ts) as f64 / self.clock_hz;
            let d            = (arrival_diff - rtp_diff).abs();
            self.jitter     += (d - self.jitter) / 16.0;
        }
        self.last_rtp_ts  = Some(rtp_ts);
        self.last_arrival = Some(now);

        // ── SSRC tracking ────────────────────────────
        // Un changement de SSRC sur un flux existant indique une
        // interruption et reconnexion de la source RTP.
        // (Le premier paquet initialise silencieusement.)
        if let Some(prev_ssrc) = self.last_ssrc {
            if prev_ssrc != ssrc {
                self.ssrc_changes += 1;
            }
        }
        self.last_ssrc = Some(ssrc);
        self.last_packet_time = Some(now);
        self.dead_alerted = false; // flux vivant — réarmer l'alerte
        // On accumule les octets réels (payload UDP) et on calcule
        // le débit toutes les secondes.
        self.bytes_total += udp_payload_len as u64;
        if self.last_bitrate_check.elapsed() > Duration::from_secs(1) {
            let bytes_delta = self.bytes_total - self.bytes_at_check;
            self.bitrate_bps = bytes_delta * 8; // bits/s sur la dernière seconde
            self.bytes_at_check  = self.bytes_total;
            self.packets_at_check = self.packets;
            self.last_bitrate_check = now;
        }
    }

    fn loss_pct(&self) -> f64 {
        let total = self.packets + self.lost_packets;
        if total == 0 { 0.0 } else { 100.0 * self.lost_packets as f64 / total as f64 }
    }

    fn jitter_ms(&self) -> f64 { self.jitter * 1000.0 }
}

// ─────────────────────────────────────────────────────────
// TCP stream monitoring (for NDI, etc.)
// ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TcpStreamStats {
    key: String,
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    packets: u64,
    bytes: u64,
    retransmissions: u64,
    fin_packets: u64,
    rst_packets: u64,
    last_seen: Instant,
    stream_quality: StreamQuality,
    bitrate_bps: u64,
    last_bitrate_check: Instant,
    bytes_at_check: u64,
    // Tracking du dernier seq TCP vu — vraie détection de retransmission
    last_seq: Option<u32>,
    last_ack: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
enum StreamQuality {
    Healthy,
    Degrading,      // Growing retransmissions
    Critical,       // High retransmission rate or FIN/RST
    Terminated,
}

impl TcpStreamStats {
    fn new(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Self {
        let key = format!("TCP {}:{} → {}:{}", src_ip, src_port, dst_ip, dst_port);
        Self {
            key,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            packets: 0,
            bytes: 0,
            retransmissions: 0,
            fin_packets: 0,
            rst_packets: 0,
            last_seen: Instant::now(),
            stream_quality: StreamQuality::Healthy,
            bitrate_bps: 0,
            last_bitrate_check: Instant::now(),
            bytes_at_check: 0,
            last_seq: None,
            last_ack: None,
        }
    }

    fn update_bitrate(&mut self) {
        if self.last_bitrate_check.elapsed() > Duration::from_secs(1) {
            let bytes_delta = self.bytes - self.bytes_at_check;
            self.bitrate_bps = bytes_delta * 8;
            self.bytes_at_check = self.bytes;
            self.last_bitrate_check = Instant::now();
        }
    }

    fn update_quality(&mut self) {
        if self.rst_packets > 0 || self.fin_packets > 2 {
            self.stream_quality = StreamQuality::Terminated;
        } else if self.retransmissions > 10 {
            self.stream_quality = StreamQuality::Critical;
        } else if self.retransmissions > 2 {
            self.stream_quality = StreamQuality::Degrading;
        } else {
            self.stream_quality = StreamQuality::Healthy;
        }
    }
}

// ─────────────────────────────────────────────────────────
// Global network health statistics
// ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct NetworkHealth {
    total_packets: u64,
    total_bytes: u64,
    multicast_packets: u64,
    unicast_packets: u64,
    packet_loss_streams: u64,        // count of streams with loss
    high_jitter_streams: u64,
    aes67_discontinuities: u64,
    timestamp_errors: u64,
    tcp_retransmissions: u64,
    detected_duplicates: u64,        // multicast duplicates
    congestion_events: u64,
    saturation_warnings: u64,
    network_score: f64,              // 0-100
}

impl NetworkHealth {
    fn new() -> Self {
        Self {
            total_packets: 0,
            total_bytes: 0,
            multicast_packets: 0,
            unicast_packets: 0,
            packet_loss_streams: 0,
            high_jitter_streams: 0,
            aes67_discontinuities: 0,
            timestamp_errors: 0,
            tcp_retransmissions: 0,
            detected_duplicates: 0,
            congestion_events: 0,
            saturation_warnings: 0,
            network_score: 100.0,
        }
    }

    fn calculate_score(&mut self, streams: &HashMap<String, StreamStats>, tcp_streams: &HashMap<String, TcpStreamStats>) {
        let mut score = 100.0;

        // Deduct for packet loss
        for stats in streams.values() {
            if stats.loss_pct() > 0.0 {
                score -= stats.loss_pct().min(10.0);
            }
        }

        // Deduct for jitter
        for stats in streams.values() {
            if stats.jitter_ms() > 20.0 {
                score -= 5.0;
            } else if stats.jitter_ms() > 10.0 {
                score -= 2.0;
            }
        }

        // Deduct for timestamp discontinuities
        for stats in streams.values() {
            if stats.ts_discontinuities > 0 {
                score -= 3.0 * (stats.ts_discontinuities as f64).min(5.0);
            }
        }

        // Deduct for TCP issues
        for tcp_stats in tcp_streams.values() {
            match tcp_stats.stream_quality {
                StreamQuality::Healthy => {},
                StreamQuality::Degrading => score -= 5.0,
                StreamQuality::Critical => score -= 15.0,
                StreamQuality::Terminated => score -= 25.0,
            }
        }

        // Deduct for detected issues
        score -= (self.detected_duplicates as f64).min(10.0);
        score -= (self.congestion_events as f64 * 0.5).min(15.0);

        self.network_score = score.max(0.0);
    }
}

// ─────────────────────────────────────────────────────────
// PTP domain statistics
// ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct PtpStats {
    domain:            u8,
    version:           u8,
    packets:           u64,
    masters:           std::collections::HashSet<String>, // clock IDs of masters
    last_seen:         Instant,
    last_grandmaster:  Option<String>,
    grandmaster_changes: u64,
    last_quality:      Option<String>,
    last_offset_ns:    Option<i64>,
    last_path_delay_ns: Option<i64>,
}

impl PtpStats {
    fn new(domain: u8, version: u8) -> Self {
        Self {
            domain,
            version,
            packets: 0,
            masters: HashSet::new(),
            last_seen: Instant::now(),
            last_grandmaster: None,
            grandmaster_changes: 0,
            last_quality: None,
            last_offset_ns: None,
            last_path_delay_ns: None,
        }
    }

    fn update(&mut self, info: &PtpInfo) {
        self.packets += 1;
        self.last_seen = Instant::now();

        if let Some(clock_id) = info.clock_id.as_deref().or(info.grandmaster_id.as_deref()) {
            self.masters.insert(clock_id.to_string());
        }

        if info.message_type == 0x0B {
            if let Some(gm) = &info.grandmaster_id {
                if let Some(current) = &self.last_grandmaster {
                    if current != gm {
                        self.grandmaster_changes += 1;
                    }
                }
                self.last_grandmaster = Some(gm.clone());
            }
            if let Some(q) = &info.clock_quality {
                self.last_quality = Some(q.clone());
            }
        }

        if info.message_type == 0x00 || info.message_type == 0x08 {
            self.last_offset_ns = info.correction_ns;
        }
        if info.message_type == 0x09 {
            self.last_path_delay_ns = info.path_delay_ns;
        }
    }
}

struct Logger {
    file: File,
}

impl Logger {
    fn new(prefix: &str) -> io::Result<Self> {
        let now = Local::now();
        let filename = format!(
            "avstreamlens_{}-{:02}-{:02}_{:02}-{:02}-{:02}_{}.log",
            now.year(), now.month(), now.day(), now.hour(), now.minute(), now.second(), prefix
        );
        let file = File::create(filename)?;
        Ok(Logger { file })
    }

    fn log(&mut self, message: &str) {
        let _ = writeln!(self.file, "{}", message);
    }

    #[allow(dead_code)]
    fn log_fmt(&mut self, args: std::fmt::Arguments) {
        let message = args.to_string();
        let _ = writeln!(self.file, "{}", message);
    }
}

fn prompt_protocol_selection() -> Vec<ProtocolChoice> {
    println!("Choose the protocols to monitor:");
    println!("  0) All");
    for (i, choice) in ProtocolChoice::all_choices().iter().enumerate() {
        println!("  {}) {}", i + 1, choice.name());
    }
    println!();
    println!("  ℹ  PTP (IEEE 1588) and IGMP are always monitored regardless of selection.");
    println!();
    println!("Enter comma-separated numbers (e.g. 0 or 1,3,5):");
    print!("> ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let tokens: Vec<&str> = input.trim().split(',').map(|s| s.trim()).collect();

    if tokens.iter().any(|t| *t == "0" || t.eq_ignore_ascii_case(&"all")) {
        return ProtocolChoice::all_choices();
    }

    let mut selected = Vec::new();
    for token in tokens {
        if let Ok(index) = token.parse::<usize>() {
            if index > 0 && index <= ProtocolChoice::all_choices().len() {
                selected.push(ProtocolChoice::all_choices()[index - 1].clone());
            }
        }
    }
    if selected.is_empty() {
        ProtocolChoice::all_choices()
    } else {
        selected
    }
}

fn build_bpf_filter(selected: &[ProtocolChoice]) -> String {
    let choices = if selected.iter().any(|p| matches!(p, ProtocolChoice::All)) {
        ProtocolChoice::all_choices()
    } else {
        selected.to_vec()
    };

    // Expander les choix Audio/Video en protocoles concrets
    let expanded: Vec<ProtocolChoice> = choices.iter()
        .flat_map(|p| p.includes())
        .collect();
    let udp_needed = expanded.iter().any(|p| p.needs_udp());
    let avb_needed = expanded.iter().any(|p| p.needs_avb());
    let tcp_needed = expanded.iter().any(|p| matches!(p, ProtocolChoice::NDI | ProtocolChoice::SRT));

    let mut parts = Vec::new();
    if udp_needed { parts.push("udp".to_string()); }
    if tcp_needed { parts.push("tcp".to_string()); }
    if avb_needed { parts.push("(ether proto 0x22f0)".to_string()); }
    // PTP et IGMP sont toujours capturés, quel que soit le choix de protocole.
    parts.push("(ether proto 0x88f7 or udp port 319 or udp port 320)".to_string()); // PTP
    parts.push("igmp".to_string()); // IGMP

    if parts.is_empty() {
        DEFAULT_BPF_FILTER.to_string()
    } else {
        parts.join(" or ")
    }
}

fn selected_protocol_names(selected: &[ProtocolChoice]) -> String {
    let choices = if selected.iter().any(|p| matches!(p, ProtocolChoice::All)) {
        ProtocolChoice::all_choices()
    } else {
        ProtocolChoice::all_choices().into_iter().filter(|p| selected.contains(p)).collect()
    };
    choices.iter().map(|p| p.name()).collect::<Vec<_>>().join("_")
}

fn protocol_requires_ptp(selected: &[ProtocolChoice]) -> bool {
    let choices = if selected.iter().any(|p| matches!(p, ProtocolChoice::All)) {
        ProtocolChoice::all_choices()
    } else {
        selected.to_vec()
    };
    choices.into_iter().any(|p| p.requires_valid_ptp_clock())
}

// ═══════════════════════════════════════════════════════════
// SECTION 2 — SAP / SDP PARSER
// ═══════════════════════════════════════════════════════════

/// Parse a UDP packet received on SAP port (9875).
/// Returns None if the SAP header is invalid or if SDP is empty.
fn parse_sap_packet(payload: &[u8]) -> Option<SdpSession> {
    // SAP header (RFC 2974):
    //   byte 0: V(3) A(1) R(1) T(1) E(1) C(1)  — version must be 1
    //   byte 1: auth len (in 32-bit words)
    //   bytes 2-3: msg id hash
    //   bytes 4-7: source IPv4 address (or 16 bytes IPv6 if A=1)
    if payload.len() < 8 {
        return None;
    }
    let version   = (payload[0] >> 5) & 0b111;
    if version != 1 { return None; }

    let addr_type = (payload[0] >> 4) & 0b1;    // 0=IPv4, 1=IPv6
    let auth_len  = payload[1] as usize;
    let addr_len  = if addr_type == 0 { 4 } else { 16 };
    let header    = 4 + addr_len + auth_len * 4;

    if payload.len() <= header { return None; }

    let mut body = &payload[header..];

    // Optional: MIME type "application/sdp\0" before SDP body
    if body.starts_with(b"application/sdp") {
        if let Some(pos) = body.iter().position(|&b| b == 0) {
            body = &body[pos + 1..];
        }
    }

    let sdp_text = std::str::from_utf8(body).ok()?;
    Some(parse_sdp(sdp_text))
}

/// Parse an SDP document (RFC 4566) into `SdpSession`.
fn parse_sdp(sdp: &str) -> SdpSession {
    let mut session   = SdpSession::default();
    let mut cur_media: Option<SdpMedia> = None;

    for line in sdp.lines() {
        let line = line.trim();
        if line.len() < 2 || line.as_bytes()[1] != b'=' { continue; }

        let type_char = line.as_bytes()[0] as char;
        let value     = &line[2..];

        match type_char {

            'o' => {
                // o=<user> <sess-id> <version> <nettype> <addrtype> <addr>
                let parts: Vec<&str> = value.splitn(6, ' ').collect();
                if parts.len() >= 2 { session.session_id = parts[1].to_string(); }
            }

            's' => { session.session_name = value.to_string(); }

            'i' => { if cur_media.is_none() { session.info = value.to_string(); } }

            'm' => {
                if let Some(m) = cur_media.take() { session.media.push(m); }
                // m=<type> <port> <proto> <fmt...>
                let parts: Vec<&str> = value.split_whitespace().collect();
                if parts.len() >= 4 {
                    let mut media       = SdpMedia::default();
                    media.media_type    = parts[0].to_string();
                    media.port          = parts[1].parse().unwrap_or(0);
                    for pt_str in &parts[3..] {
                        if let Ok(pt) = pt_str.parse::<u8>() {
                            media.payload_types.push(pt);
                        }
                    }
                    cur_media = Some(media);
                }
            }

            'c' => {
                // c=IN IP4 239.69.0.1/32
                if let Some(m) = cur_media.as_mut() {
                    m.connection = value.to_string();
                }
            }

            'a' => {
                let media = match cur_media.as_mut() { Some(m) => m, _ => continue };

                if let Some(rest) = value.strip_prefix("rtpmap:") {
                    // a=rtpmap:<pt> <encoding>/<clock>[/<channels>]
                    // e.g.: "96 L24/48000/8"
                    let parts: Vec<&str> = rest.splitn(2, ' ').collect();
                    if parts.len() == 2 {
                        media.rtpmap = parts[1].to_string();
                        let enc: Vec<&str> = parts[1].split('/').collect();
                        if enc.len() >= 2 { media.clock_hz  = enc[1].parse().unwrap_or(DEFAULT_CLOCK_HZ); }
                        if enc.len() >= 3 { media.channels  = enc[2].parse().unwrap_or(1); }
                    }

                } else if let Some(rest) = value.strip_prefix("ptime:") {
                    media.ptime_ms = rest.trim().parse().unwrap_or(1.0);

                } else if let Some(rest) = value.strip_prefix("framecount:") {
                    // a=framecount:<n>  (ST 2110) → converted to ptime
                    if let Ok(fc) = rest.trim().parse::<u32>() {
                        if media.clock_hz > 0.0 {
                            media.ptime_ms = fc as f64 / media.clock_hz * 1000.0;
                        }
                    }

                } else if let Some(rest) = value.strip_prefix("ts-refclk:") {
                    // a=ts-refclk:ptp=IEEE1588-2008:<eui64>:<domain>
                    // Specific to AES67 (AES-2018 §7) and ST 2110
                    media.ts_refclk = rest.to_string();

                } else if let Some(rest) = value.strip_prefix("mediaclk:") {
                    // a=mediaclk:direct=0  /  a=mediaclk:sender
                    media.mediaclk = rest.to_string();
                }
            }

            _ => {}
        }
    }

    if let Some(m) = cur_media.take() { session.media.push(m); }
    session
}

// ═══════════════════════════════════════════════════════════
// SECTION 3 — PROTOCOL DETECTION
// ═══════════════════════════════════════════════════════════

fn detect_protocol(eth: &EthernetPacket) -> Option<AvProtocol> {

    // ── AVB / AVTP : L2 pure (EtherType 0x22F0) ─────────
    let raw_et = u16::from_be_bytes([eth.packet()[12], eth.packet()[13]]);
    if raw_et == ETHERTYPE_AVTP {
        let subtype = eth.payload().first().copied().unwrap_or(0);
        return Some(AvProtocol::Avb { subtype });
    }

    // ── PTP : L2 (EtherType 0x88F7) ──────────────────────
    if raw_et == ETHERTYPE_PTP {
        if let Some(info) = parse_ptp(eth.payload()) {
            return Some(AvProtocol::Ptp { info });
        }
    }

    // ── IGMP (protocole IP 0x02, sans couche UDP) ────────
    if eth.get_ethertype() == EtherTypes::Ipv4 {
        if let Some(ip) = Ipv4Packet::new(eth.payload()) {
            if ip.get_next_level_protocol().0 == IP_PROTO_IGMP {
                let src = ip.get_source();
                let group = ip.get_destination();
                let igmp_payload = ip.payload();
                let igmp_type = if igmp_payload.is_empty() {
                    IgmpType::Unknown(0)
                } else {
                    match igmp_payload[0] {
                        0x11 => IgmpType::Query,
                        0x16 | 0x22 => IgmpType::Join,   // v2 Report / v3 Report
                        0x17 => IgmpType::Leave,
                        t    => IgmpType::Unknown(t),
                    }
                };
                return Some(AvProtocol::Igmp { src, group, igmp_type });
            }
        }
    }

    if eth.get_ethertype() != EtherTypes::Ipv4 { return None; }

    let ip  = Ipv4Packet::new(eth.payload())?;
    let udp = UdpPacket::new(ip.payload())?;

    let src_ip   = ip.get_source();
    let dst_ip   = ip.get_destination();
    let dst_port = udp.get_destination();
    let src_port = udp.get_source();
    let payload  = udp.payload();

    // ── SAP (port 9875) ─────────────────────────────────
    if dst_port == SAP_PORT {
        return parse_sap_packet(payload)
            .map(|sdp| AvProtocol::Sap { src: src_ip, sdp });
    }

    // ── mDNS (port 5353) ────────────────────────────────
    if dst_port == MDNS_PORT || src_port == MDNS_PORT {
        if mdns_contains(payload, b"_netaudio._udp") {
            return Some(AvProtocol::Dante { kind: DanteKind::Discovery, src: src_ip, dst_port });
        }
        if mdns_contains(payload, b"_ndi._tcp") {
            return Some(AvProtocol::Ndi { kind: NdiKind::Discovery, src: src_ip });
        }
        return None;
    }

    // ── Dante Control ───────────────────────────────────
    if DANTE_CTRL_PORTS.contains(&dst_port) || DANTE_CTRL_PORTS.contains(&src_port) {
        return Some(AvProtocol::Dante { kind: DanteKind::Control, src: src_ip, dst_port });
    }

    // ── NDI stream (ports 5960-5980) ─────────────────────
    if (NDI_PORT_MIN..=NDI_PORT_MAX).contains(&dst_port) {
        return Some(AvProtocol::Ndi { kind: NdiKind::Stream, src: src_ip });
    }

    // ── SRT handshake detection ───────────────────────────
    // Le handshake SRT commence par 4 octets à zéro (control packet)
    // suivi du type 0x0000 (handshake). Taille min : 16 octets.
    if payload.len() >= 16 {
        let is_control = (payload[0] & 0x80) != 0;
        if is_control {
            let ctrl_type = u16::from_be_bytes([payload[0] & 0x7F, payload[1]]);
            if ctrl_type == 0x0000 {
                // Type 0 = Handshake SRT
                let is_handshake = payload.len() >= 20;
                return Some(AvProtocol::Srt { src: src_ip, dst_port, is_handshake });
            }
        }
    }

    // ── RIST detection ───────────────────────────────────
    // RIST utilise RTP sur ports pairs + RTCP ARQ sur port impair suivant.
    // Convention : ports 5000-5999 (paires), flux bidirectionnel.
    // On identifie par la présence d'un RTP valide sur port pair
    // avec payload type dans la plage dynamique (96-127) non AV déjà classé.
    if (RIST_PORT_BASE..5999).contains(&dst_port) && dst_port % 2 == 0
        && !is_aes67_multicast(dst_ip) && !is_st2110_multicast(dst_ip)
    {
        if payload.len() >= 12 && (payload[0] >> 6) & 0b11 == 2 {
            let pt = payload[1] & 0x7F;
            if pt >= 33 { // PT 33 = MP2T classique dans RIST
                return Some(AvProtocol::Rist { src: src_ip, dst: dst_ip, dst_port });
            }
        }
    }

    // ── RTP Streams ─────────────────────────────────────────
    if payload.len() < 12 { return None; }
    if (payload[0] >> 6) & 0b11 != 2 { return None; }
    let payload_type = payload[1] & 0x7F;

    if is_aes67_multicast(dst_ip) {
        return Some(AvProtocol::Aes67 { src: src_ip, dst: dst_ip, dst_port, payload_type });
    }
    if is_st2110_multicast(dst_ip) {
        return Some(AvProtocol::St2110 {
            src: src_ip, dst: dst_ip, dst_port,
            stream_type: classify_st2110(payload_type, dst_port),
        });
    }
    if is_likely_dante_audio(src_port, dst_port, payload_type) {
        return Some(AvProtocol::Dante { kind: DanteKind::AudioStream, src: src_ip, dst_port });
    }

    // ── PTP over UDP ─────────────────────────────────────
    if dst_port == PTP_EVENT_PORT || dst_port == PTP_GENERAL_PORT || src_port == PTP_EVENT_PORT || src_port == PTP_GENERAL_PORT {
        if let Some(info) = parse_ptp(payload) {
            return Some(AvProtocol::Ptp { info });
        }
    }

    None
}

// ─────────────────────────────────────────────────────────
// TCP Parser and Retransmission Detection
// ─────────────────────────────────────────────────────────

fn parse_tcp_packet(eth: &EthernetPacket) -> Option<(Ipv4Addr, Ipv4Addr, u16, u16, bool, bool, bool, u32, u32)> {
    if eth.get_ethertype() != EtherTypes::Ipv4 { return None; }
    let ip = Ipv4Packet::new(eth.payload())?;
    if ip.get_next_level_protocol() != pnet_packet::ip::IpNextHeaderProtocols::Tcp { return None; }
    
    let tcp = TcpPacket::new(ip.payload())?;
    let src_ip   = ip.get_source();
    let dst_ip   = ip.get_destination();
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();
    let seq      = tcp.get_sequence();
    let ack      = tcp.get_acknowledgement();
    
    let has_fin = tcp.get_flags() & 0x01 != 0;
    let has_syn = tcp.get_flags() & 0x02 != 0;
    let has_rst = tcp.get_flags() & 0x04 != 0;
    
    Some((src_ip, dst_ip, src_port, dst_port, has_fin, has_syn, has_rst, seq, ack))
}

// ─────────────────────────────────────────────────────────
// Network Helpers - Multicast and Unicast Detection
// ─────────────────────────────────────────────────────────

fn is_aes67_multicast(ip: Ipv4Addr) -> bool {
    let o = ip.octets(); o[0] == 239 && o[1] == 69
}
fn is_st2110_multicast(ip: Ipv4Addr) -> bool {
    let o = ip.octets(); o[0] == 239 && o[1] != 69
}
fn is_multicast(ip: Ipv4Addr) -> bool {
    // Class D: 224.0.0.0 to 239.255.255.255
    ip.octets()[0] >= 224 && ip.octets()[0] <= 239
}
fn classify_st2110(pt: u8, port: u16) -> St2110Type {
    match port % 10 {
        4 => St2110Type::Video,
        6 => St2110Type::Audio,
        8 => St2110Type::Ancdata,
        _ => match pt {
            96..=107  => St2110Type::Video,
            108..=115 => St2110Type::Audio,
            116..=127 => St2110Type::Ancdata,
            _         => St2110Type::Unknown,
        },
    }
}
fn is_likely_dante_audio(src: u16, dst: u16, pt: u8) -> bool {
    let port_ok = ((5000..=6000).contains(&dst) && dst % 2 == 0)
               || ((5000..=6000).contains(&src) && src % 2 == 0);
    (pt == 0 || pt == 8 || pt >= 96) && port_ok
}
fn mdns_contains(payload: &[u8], service: &[u8]) -> bool {
    payload.windows(service.len()).any(|w| w == service)
}

// ─────────────────────────────────────────────────────────
// Minimal RTP Parser
// ─────────────────────────────────────────────────────────

/// Retourne (seq, timestamp, ssrc). Le SSRC permet de détecter
/// les changements de source sur un même flux multicast.
fn parse_rtp(payload: &[u8]) -> Option<(u16, u32, u32)> {
    if payload.len() < 12 { return None; }
    if (payload[0] >> 6) & 0b11 != 2 { return None; }
    let seq  = u16::from_be_bytes([payload[2], payload[3]]);
    let ts   = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let ssrc = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    Some((seq, ts, ssrc))
}

// ─────────────────────────────────────────────────────────
// PTP Parser
// ─────────────────────────────────────────────────────────

fn parse_ptp(payload: &[u8]) -> Option<PtpInfo> {
    if payload.len() < 34 { return None; } // PTP header is 34 bytes
    
    // PTP message types
    let message_type = payload[0] & 0x0F;
    let message_name = match message_type {
        0x0 => "Sync".to_string(),
        0x1 => "Delay_Req".to_string(),
        0x2 => "P_Delay_Req".to_string(),
        0x3 => "P_Delay_Resp".to_string(),
        0x8 => "Follow_Up".to_string(),
        0x9 => "Delay_Resp".to_string(),
        0xA => "P_Delay_Resp_Follow_Up".to_string(),
        0xB => "Announce".to_string(),
        0xC => "Signaling".to_string(),
        0xD => "Management".to_string(),
        _ => format!("Unknown(0x{:X})", message_type),
    };

    let version_ptp = (payload[1] >> 4) & 0x0F;
    let domain = payload[4];
    
    let correction_field = i64::from_be_bytes([
        payload[8], payload[9], payload[10], payload[11],
        payload[12], payload[13], payload[14], payload[15],
    ]);
    
    let sequence_id = u16::from_be_bytes([payload[30], payload[31]]);
    let log_sync_interval = payload[33] as i8;

    // Parse source port identity (port ID)
    let port_id = if payload.len() >= 28 {
        Some(u16::from_be_bytes([payload[26], payload[27]]))
    } else {
        None
    };

    let clock_id = if payload.len() >= 28 {
        Some(format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            payload[20], payload[21], payload[22], payload[23],
            payload[24], payload[25], payload[26], payload[27]))
    } else {
        None
    };

    let log_min_pdelay_req_interval = if payload.len() >= 55 {
        payload[54] as i8
    } else {
        0
    };

    // Parse origin timestamp (for Sync and Delay_Req)
    let origin_timestamp_ns = if payload.len() >= 48 {
        let seconds = u64::from_be_bytes([
            0, payload[34], payload[35], payload[36], payload[37], payload[38], payload[39], payload[40],
        ]);
        let nanos = u32::from_be_bytes([payload[41], payload[42], payload[43], payload[44]]);
        Some(seconds * 1_000_000_000 + nanos as u64)
    } else {
        None
    };

    // Parse grandmaster info (Announce messages)
    let grandmaster_id = if message_type == 0x0B && payload.len() >= 62 {
        Some(format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            payload[52], payload[53], payload[54], payload[55],
            payload[56], payload[57], payload[58], payload[59]))
    } else {
        None
    };

    let clock_quality = if message_type == 0x0B && payload.len() >= 51 {
        let clock_class = payload[47];
        let clock_accuracy = payload[48];
        let log_var = u16::from_be_bytes([payload[49], payload[50]]);
        Some(format!("class={} acc={} var={}", clock_class, clock_accuracy, log_var))
    } else {
        None
    };

    // For Delay_Resp messages, path delay is in correction_field
    let path_delay_ns = if message_type == 0x9 {
        Some(correction_field)
    } else if message_type == 0x3 {
        Some(correction_field)
    } else {
        None
    };

    let correction_ns = if message_type != 0x0 && message_type != 0x8 {
        Some(correction_field)
    } else {
        None
    };

    Some(PtpInfo {
        version: version_ptp,
        message_type,
        domain,
        clock_id,
        grandmaster_id,
        clock_quality,
        correction_ns,
        path_delay_ns,
        origin_timestamp_ns,
        message_name,
        port_id,
        sequence_id,
        log_sync_interval,
        log_min_pdelay_req_interval,
    })
}

// ═══════════════════════════════════════════════════════════
// SECTION 4 — MAIN
// ═══════════════════════════════════════════════════════════

fn main() {
    // ── Interface listing ───────────────────────────
    let devices = Device::list().expect("Unable to list interfaces");
    let filtered: Vec<Device> = devices
        .into_iter()
        .filter(|d| {
            let n = d.name.as_str();
            if n == "lo" || n == "lo0" { return false; }
            let skip = ["utun", "awdl", "llw", "bridge", "vpn", "docker", "veth", "virbr"];
            !skip.iter().any(|k| n.contains(k))
        })
        .collect();

    if filtered.is_empty() {
        eprintln!("❌ No active network interfaces found."); return;
    }

    println!("📡 Available interfaces:\n");
    for (i, d) in filtered.iter().enumerate() {
        println!("  {}: {}", i, d.name);
    }

    println!("\n👉 Choose the interface index:");
    print!("> ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let index: usize = input.trim().parse().expect("Invalid number");

    let device = match filtered.get(index) {
        Some(d) => d.clone(),
        _    => { eprintln!("❌ Invalid selection."); return; }
    };

    let selected_protocols = prompt_protocol_selection();
    let protocol_names = selected_protocol_names(&selected_protocols);
    let mut logger = Logger::new(&protocol_names).expect("Unable to create log file");
    let bpf_filter = build_bpf_filter(&selected_protocols);

    println!("Selected protocols: {}", protocol_names);
    logger.log(&format!("Selected protocols: {}", protocol_names));
    println!("\n📡 Listening on {}  (BPF filter: \"{}\")\n", device.name, bpf_filter);
    logger.log(&format!("\n📡 Listening on {}  (BPF filter: \"{}\")\n", device.name, bpf_filter));

    // ── Opening capture with BPF filter ───────────────
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .immediate_mode(true)
        .open()
        .unwrap();

    cap.filter(&bpf_filter, true)
        .expect("BPF filter failure — run as root/sudo");

    // ── Global state ──────────────────────────────────────
    let mut streams:       HashMap<String, StreamStats> = HashMap::new();
    let mut tcp_streams:   HashMap<String, TcpStreamStats> = HashMap::new();
    let mut sdp_cache:     HashMap<String, SdpSession> = HashMap::new();
    let mut ptp_domains:   HashMap<u8, PtpStats> = HashMap::new();
    let mut network_health: NetworkHealth = NetworkHealth::new();
    let mut multicast_seen: HashMap<(Ipv4Addr, u16), u64> = HashMap::new();  // Detect duplicate multicast
    let mut last_report = Instant::now();

    // ── Capture loop ────────────────────────────────
    loop {
        let packet = match cap.next_packet() { Ok(p) => p, Err(_) => continue };
        let eth    = match EthernetPacket::new(packet.data) { Some(e) => e, _ => continue };

        match detect_protocol(&eth) {

            // ── SAP/SDP ──────────────────────────────────
            Some(AvProtocol::Sap { src, sdp }) => {
                println!("📋 SAP received from {}  session=\"{}\"  ({} media(s))",
                    src, sdp.session_name, sdp.media.len());
                logger.log(&format!("📋 SAP received from {}  session=\"{}\"  ({} media(s))",
                    src, sdp.session_name, sdp.media.len()));

                for m in &sdp.media {
                    logger.log(&format!("   {} port {}  {}  {:.0} Hz  {}ch  ptime {:.2} ms",
                        m.media_type, m.port, m.rtpmap,
                        m.clock_hz, m.channels, m.ptime_ms));
                    if !m.ts_refclk.is_empty() {
                        logger.log(&format!("   PTP refclk: {}", m.ts_refclk));
                    }
                    if !m.mediaclk.is_empty() {
                        logger.log(&format!("   mediaclk: {}", m.mediaclk));
                    }
                    // Enrich an existing StreamStats if the port matches
                    for stats in streams.values_mut() {
                        if stats.sdp_name.is_none() {
                            if m.port > 0 {
                                stats.sdp_name   = Some(sdp.session_name.clone());
                                stats.sdp_rtpmap = Some(m.rtpmap.clone());
                                if m.clock_hz > 0.0 { stats.clock_hz = m.clock_hz; }
                                if m.ptime_ms > 0.0 { stats.ptime_ms = m.ptime_ms; }
                                if m.channels > 0   { stats.channels = m.channels; }
                            }
                        }
                    }
                }
                sdp_cache.insert(sdp.session_id.clone(), sdp);
            }

            // ── PTP ───────────────────────────────────────
            Some(AvProtocol::Ptp { info }) => {
                let stats = ptp_domains.entry(info.domain).or_insert_with(|| PtpStats::new(info.domain, info.version));
                stats.update(&info);
            }

            // ── AES67 ────────────────────────────────────
            Some(AvProtocol::Aes67 { dst, dst_port, .. }) => {
                let key = format!("AES67 {}:{}", dst, dst_port);
                let stats = streams.entry(key).or_insert_with(|| {
                    let (clock, rtpmap) = sdp_cache.values()
                        .flat_map(|s| s.media.iter())
                        .find(|m| m.port == dst_port)
                        .map(|m| (m.clock_hz, Some(m.rtpmap.clone())))
                        .unwrap_or((DEFAULT_CLOCK_HZ, None));
                    let mut s = StreamStats::new_with_info("AES67", clock, is_multicast(dst), dst, dst_port);
                    s.sdp_rtpmap = rtpmap;
                    s.media_type = "audio".to_string();  // AES67 is typically audio
                    s.channels = 1;  // Will be updated by SDP if available
                    s
                });
                let ip  = Ipv4Packet::new(eth.payload()).unwrap();
                let udp = UdpPacket::new(ip.payload()).unwrap();
                if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) { stats.update(seq, ts, ssrc, udp.payload().len()); }
            }

            // ── ST 2110 ──────────────────────────────────
            Some(AvProtocol::St2110 { dst, dst_port, stream_type, .. }) => {
                let label = match stream_type {
                    St2110Type::Video   => "2110-20",
                    St2110Type::Audio   => "2110-30",
                    St2110Type::Ancdata => "2110-40",
                    St2110Type::Unknown => "2110-??",
                };
                let key = format!("ST {} {}:{}", label, dst, dst_port);
                let default_clock = if matches!(stream_type, St2110Type::Video) { 90_000.0 } else { DEFAULT_CLOCK_HZ };
                let stats = streams.entry(key).or_insert_with(|| {
                    let (clock, rtpmap) = sdp_cache.values()
                        .flat_map(|s| s.media.iter())
                        .find(|m| m.port == dst_port)
                        .map(|m| (m.clock_hz, Some(m.rtpmap.clone())))
                        .unwrap_or((default_clock, None));
                    let mut s = StreamStats::new_with_info(label, clock, is_multicast(dst), dst, dst_port);
                    s.sdp_rtpmap = rtpmap;
                    s.media_type = match stream_type {
                        St2110Type::Video => "video".to_string(),
                        St2110Type::Audio => "audio".to_string(),
                        St2110Type::Ancdata => "ancillary".to_string(),
                        St2110Type::Unknown => "unknown".to_string(),
                    };
                    s
                });
                let ip  = Ipv4Packet::new(eth.payload()).unwrap();
                let udp = UdpPacket::new(ip.payload()).unwrap();
                if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) { stats.update(seq, ts, ssrc, udp.payload().len()); }
            }

            // ── Dante ────────────────────────────────────
            Some(AvProtocol::Dante { kind, src, dst_port }) => {
                match kind {
                    DanteKind::Discovery => {
                        let msg = format!("🔍 Dante discovered: {}", src);
                        println!("{}", msg);
                        logger.log(&msg);
                    }
                    DanteKind::Control     => {}
                    DanteKind::AudioStream => {
                        let key   = format!("Dante {}:{}", src, dst_port);
                        let stats = streams.entry(key)
                            .or_insert_with(|| StreamStats::new("Dante", DEFAULT_CLOCK_HZ));
                        let ip  = Ipv4Packet::new(eth.payload()).unwrap();
                        let udp = UdpPacket::new(ip.payload()).unwrap();
                        if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) { stats.update(seq, ts, ssrc, udp.payload().len()); }
                    }
                }
            }

            // ── NDI ──────────────────────────────────────
            Some(AvProtocol::Ndi { kind, src }) => {
                match kind {
                    NdiKind::Discovery => {
                        let msg = format!("🔍 NDI source: {}", src);
                        println!("{}", msg);
                        logger.log(&msg);
                    },
                    NdiKind::Stream    => {
                        let stats = streams.entry(format!("NDI {}", src))
                            .or_insert_with(|| StreamStats::new("NDI", 0.0));
                        stats.packets += 1;
                    }
                }
            }

            // ── AVB ──────────────────────────────────────
            Some(AvProtocol::Avb { subtype }) => {
                let stats = streams.entry(format!("AVB subtype=0x{:02X}", subtype))
                    .or_insert_with(|| StreamStats::new("AVB", 0.0));
                stats.packets += 1;
            }

            // ── SRT ──────────────────────────────────────
            Some(AvProtocol::Srt { src, dst_port, is_handshake }) => {
                let key = format!("SRT {}:{}", src, dst_port);
                let stats = streams.entry(key)
                    .or_insert_with(|| StreamStats::new("SRT", 0.0));
                stats.packets += 1;
                stats.last_packet_time = Some(Instant::now());
                if is_handshake {
                    let msg = format!("🤝 SRT handshake: {} → port {}", src, dst_port);
                    println!("{}", msg);
                    logger.log(&msg);
                }
            }

            // ── RIST ─────────────────────────────────────
            Some(AvProtocol::Rist { src, dst, dst_port }) => {
                let key = format!("RIST {}:{}", dst, dst_port);
                let stats = streams.entry(key)
                    .or_insert_with(|| {
                        let mut s = StreamStats::new_with_info("RIST", DEFAULT_CLOCK_HZ, is_multicast(dst), dst, dst_port);
                        s.media_type = "video".to_string();
                        s
                    });
                let ip  = Ipv4Packet::new(eth.payload()).unwrap();
                let udp = UdpPacket::new(ip.payload()).unwrap();
                if let Some((seq, ts, ssrc)) = parse_rtp(udp.payload()) {
                    stats.update(seq, ts, ssrc, udp.payload().len());
                }
                let _ = src;
            }

            // ── IGMP ─────────────────────────────────────
            Some(AvProtocol::Igmp { src, group, igmp_type }) => {
                let (icon, label) = match &igmp_type {
                    IgmpType::Join       => ("➕", "Join"),
                    IgmpType::Leave      => ("➖", "Leave"),
                    IgmpType::Query      => ("❓", "Query"),
                    IgmpType::Unknown(t) => {
                        let _ = t;
                        ("❔", "Unknown")
                    }
                };
                let msg = format!("{} IGMP {}: {} → group {}", icon, label, src, group);
                println!("{}", msg);
                logger.log(&msg);
                // Un Leave sur un groupe surveillé mérite une alerte
                if matches!(igmp_type, IgmpType::Leave) {
                    for key in streams.keys() {
                        if streams[key].dst_ip == Some(group) {
                            let alert = format!("    ⚠  IGMP Leave on monitored group {}", group);
                            println!("\x1b[33m{}\x1b[0m", alert);
                            logger.log(&alert);
                        }
                    }
                }
            }

            _ => {}
        }

        // ── Détection de flux morts (toutes les 5 s) ─────────
        if last_report.elapsed() > Duration::from_secs(4) {
            for (key, stats) in &streams {
                if let Some(last_time) = stats.last_packet_time {
                    if last_time.elapsed() > Duration::from_secs(STREAM_TIMEOUT_SECS) {
                        let alert = format!("💀 Stream silent (> {}s): {}", STREAM_TIMEOUT_SECS, key);
                        println!("\x1b[31m{}\x1b[0m", alert);
                        logger.log(&alert);
                    }
                }
            }
        }

        // ── TCP Monitoring for NDI and other TCP streams
        if let Some((src_ip, dst_ip, src_port, dst_port, has_fin, has_syn, has_rst, seq, ack)) = parse_tcp_packet(&eth) {
            let key = format!("TCP {}:{} → {}:{}", src_ip, src_port, dst_ip, dst_port);
            let tcp_stat = tcp_streams.entry(key.clone()).or_insert_with(|| TcpStreamStats::new(src_ip, src_port, dst_ip, dst_port));
            tcp_stat.packets += 1;
            tcp_stat.last_seen = Instant::now();
            
            let frame_size = eth.packet().len() as u64;
            let estimated_payload = if frame_size > 40 { frame_size - 40 } else { 0 };
            tcp_stat.bytes += estimated_payload;
            
            if has_fin { tcp_stat.fin_packets += 1; }
            if has_rst {
                tcp_stat.rst_packets += 1;
                network_health.tcp_retransmissions += 1;
            }

            // Vraie détection de retransmission TCP :
            // un paquet non-SYN dont le seq est <= au dernier seq vu
            // (hors SYN initial qui est toléré).
            if !has_syn {
                if let Some(last_seq) = tcp_stat.last_seq {
                    if seq <= last_seq && tcp_stat.packets > 2 {
                        tcp_stat.retransmissions += 1;
                        network_health.tcp_retransmissions += 1;
                    }
                }
            }
            tcp_stat.last_seq = Some(seq.max(tcp_stat.last_seq.unwrap_or(0)));
            tcp_stat.last_ack = Some(ack);
            
            tcp_stat.update_bitrate();
            tcp_stat.update_quality();
        }

        // ── Network health tracking
        network_health.total_packets += 1;
        if let Some(ip) = Ipv4Packet::new(eth.payload()) {
            network_health.total_bytes += eth.packet().len() as u64;
            if is_multicast(ip.get_destination()) {
                network_health.multicast_packets += 1;
                // Detect multicast duplicates (same dest + port seen twice in quick succession)
                if let Some(udp) = UdpPacket::new(ip.payload()) {
                    let multicast_key = (ip.get_destination(), udp.get_destination());
                    let count = multicast_seen.entry(multicast_key).or_insert(0);
                    *count += 1;
                    if *count > 1 {
                        network_health.detected_duplicates += 1;
                    }
                }
            } else {
                network_health.unicast_packets += 1;
            }
        }

        // ── Report every 5 seconds ────────────────
        if last_report.elapsed() > Duration::from_secs(5) {
            network_health.calculate_score(&streams, &tcp_streams);
            print_report(&streams, &tcp_streams, &ptp_domains, protocol_requires_ptp(&selected_protocols), &mut logger, &network_health);
            // Après le rapport, marquer les flux morts pour éviter les répétitions.
            // dead_alerted sera réarmé automatiquement dans update() si le flux reprend.
            for stats in streams.values_mut() {
                if let Some(last_time) = stats.last_packet_time {
                    if last_time.elapsed() > Duration::from_secs(STREAM_TIMEOUT_SECS) {
                        stats.dead_alerted = true;
                    }
                }
            }
            last_report = Instant::now();
        }
    }
}

// ═══════════════════════════════════════════════════════════
// SECTION 5 — REPORTING
// ═══════════════════════════════════════════════════════════

fn print_report(streams: &HashMap<String, StreamStats>, tcp_streams: &HashMap<String, TcpStreamStats>, ptp_domains: &HashMap<u8, PtpStats>, requires_valid_ptp: bool, logger: &mut Logger, health: &NetworkHealth) {
    let now = Local::now();
    let header = format!("{} | AVStreamLens report  ({} RTP, {} TCP streams) | Health: {:.0}%", 
        now.format("%Y-%m-%d %H:%M:%S"), streams.len(), tcp_streams.len(), health.network_score);
    logger.log(&format!("\n{}", header));
    
    // Health score color
    let _health_color = if health.network_score >= 80.0 {
        "\x1b[32m"  // Green
    } else if health.network_score >= 60.0 {
        "\x1b[33m"  // Yellow
    } else {
        "\x1b[31m"  // Red
    };
    
    println!("\n\x1b[36m╔══════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[36m║  {}\x1b[0m", header);
    println!("\x1b[36m╚══════════════════════════════════════════════════════╝\x1b[0m");
    
    // Network summary
    let net_summary = format!("\n📊 Network Load: {:.1} Mbps  |  Multicast: {} pkts  |  Unicast: {} pkts  |  Duplicates: {}",
        (health.total_bytes * 8) as f64 / 1_000_000.0, health.multicast_packets, health.unicast_packets, health.detected_duplicates);
    logger.log(&net_summary);
    println!("{}", net_summary);

    let group_order = vec!["AES67", "AVB", "Dante", "NDI", "ST"];
    let mut keys: Vec<&String> = streams.keys().collect();
    keys.sort_by(|a, b| {
        let a_group = group_order.iter().position(|g| a.starts_with(g)).unwrap_or(group_order.len());
        let b_group = group_order.iter().position(|g| b.starts_with(g)).unwrap_or(group_order.len());
        a_group.cmp(&b_group).then(a.cmp(b))
    });

    for key in keys {
        let s = &streams[key];

        let name_str  = s.sdp_name.as_deref().map(|n| format!("  \"{}\"", n)).unwrap_or_default();
        let codec_str = s.sdp_rtpmap.as_deref().map(|c| format!("  [{}]", c)).unwrap_or_default();
        let mc_str = if s.is_multicast { " [MC]" } else { " [UC]" };
        let media_str = if s.media_type != "unknown" { format!("  ({})", s.media_type) } else { String::new() };

        let stream_line = format!("\n  ▸ [{}] {}{}{}{}{}", s.protocol, key, name_str, codec_str, mc_str, media_str);
        logger.log(&stream_line);
        println!("{}", stream_line);

        let status_line = format!("    packets: {}  |  losses: {} ({:.1}%)  |  jitter: {:.2} ms  |  rate: {:.1} Mbps",
            s.packets, s.lost_packets, s.loss_pct(), s.jitter_ms(), (s.bitrate_bps as f64) / 1_000_000.0);
        logger.log(&status_line);
        println!("{}", status_line);

        // Timestamp discontinuity warning for AES67
        if s.ts_discontinuities > 0 {
            let ts_alert = format!("    ⚠  Timestamp discontinuities: {} detected", s.ts_discontinuities);
            logger.log(&ts_alert);
            println!("\x1b[33m{}\x1b[0m", ts_alert);
        }

        if s.loss_pct() > 0.0 {
            let alert = "    ⚠  Packet loss";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }
        if s.jitter_ms() > 20.0 {
            let alert = "    ⚠  High jitter (> 20 ms)";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }
        if s.protocol == "AES67" && s.jitter_ms() > 10.0 {
            let alert = "    ⚠  AES67 compliance risk: RTP/PTP drift or strict timing issue";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }
        if s.protocol == "Dante" && (s.loss_pct() > 0.0 || s.jitter_ms() > 15.0) {
            let alert = "    ⚠  Dante subscription or clock mismatch detected";
            logger.log(alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }
        // SSRC change — interruption de source
        if s.ssrc_changes > 0 {
            let alert = format!("    ⚠  SSRC changed {} time(s) — source interrupted and reconnected", s.ssrc_changes);
            logger.log(&alert);
            println!("\x1b[33m{}\x1b[0m", alert);
        }
        // Flux mort
        if let Some(last_time) = s.last_packet_time {
            if last_time.elapsed() > Duration::from_secs(STREAM_TIMEOUT_SECS) {
                let alert = format!("    💀 No packet since {:.0}s — stream may be dead",
                    last_time.elapsed().as_secs_f64());
                logger.log(&alert);
                println!("\x1b[31m{}\x1b[0m", alert);
            }
        }
    }

    // ── TCP Streams (NDI, etc) ───────────────────────────
    if !tcp_streams.is_empty() {
        logger.log("\nTCP Streams:");
        println!("\n\x1b[34m🔌 TCP Streams:\x1b[0m");
        for tcp_stat in tcp_streams.values() {
            let quality_icon = match tcp_stat.stream_quality {
                StreamQuality::Healthy => "✓",
                StreamQuality::Degrading => "⚠",
                StreamQuality::Critical => "⚠⚠",
                StreamQuality::Terminated => "✗",
            };
            let tcp_line = format!("  {} {}: {} packets, {} bytes, {} Mbps, retransmissions: {}",
                quality_icon, tcp_stat.key, tcp_stat.packets, tcp_stat.bytes, 
                (tcp_stat.bitrate_bps as f64) / 1_000_000.0, tcp_stat.retransmissions);
            logger.log(&tcp_line);
            println!("{}", tcp_line);
            
            if tcp_stat.rst_packets > 0 {
                let alert = format!("    ⚠  RST flags: {} (connection reset)", tcp_stat.rst_packets);
                logger.log(&alert);
                println!("\x1b[31m{}\x1b[0m", alert);
            }
            if tcp_stat.retransmissions > 5 {
                let alert = format!("    ⚠  High retransmission rate detected");
                logger.log(&alert);
                println!("\x1b[33m{}\x1b[0m", alert);
            }
        }
    }

    // ── PTP Domains ──────────────────────────────────────
    if !ptp_domains.is_empty() {
        logger.log("\nPTP Domains:");
        println!("\n\x1b[35m📡 PTP Domains:\x1b[0m");
        for (domain, stats) in ptp_domains {
            let domain_line = format!("  Domain {} (v{}): {} packets, {} masters",
                domain, stats.version, stats.packets, stats.masters.len());
            logger.log(&domain_line);
            println!("{}", domain_line);

            if let Some(gm) = &stats.last_grandmaster {
                let gm_line = format!("    Grandmaster: {}", gm);
                logger.log(&gm_line);
                println!("{}", gm_line);
            }
            if let Some(q) = &stats.last_quality {
                let qual_line = format!("    Lock quality: {}", q);
                logger.log(&qual_line);
                println!("{}", qual_line);
            }
            if let Some(offset) = stats.last_offset_ns {
                let off_line = format!("    Last offset correction: {} ns", offset);
                logger.log(&off_line);
                println!("{}", off_line);
            }
            if let Some(delay) = stats.last_path_delay_ns {
                let delay_line = format!("    Last path delay: {} ns", delay);
                logger.log(&delay_line);
                println!("{}", delay_line);
            }
            if stats.masters.len() > 1 {
                let alert = format!("    ⚠  Multiple masters detected in domain {}", domain);
                logger.log(&alert);
                println!("\x1b[31m{}\x1b[0m", alert);
            }
            if stats.grandmaster_changes > 0 {
                let alert = format!("    ⚠  Grandmaster changed {} time(s)", stats.grandmaster_changes);
                logger.log(&alert);
                println!("\x1b[33m{}\x1b[0m", alert);
            }
        }
    }

    // ── Corrélation SDP ts-refclk ↔ GM PTP actif ─────────
    // On vérifie que le Grandmaster PTP annoncé correspond bien
    // au ts-refclk déclaré dans les SDP des flux AES67/ST2110.
    // Un écart indique un problème de domaine PTP ou de config SDP.
    if !ptp_domains.is_empty() {
        for stream in streams.values() {
            if let Some(sdp_rtpmap) = &stream.sdp_rtpmap {
                // Chercher un ts-refclk dans le SDP cache pour ce stream
                // (on utilise le port comme clé de correspondance)
                let refclk_mismatch = ptp_domains.values().any(|ptp| {
                    if let Some(gm) = &ptp.last_grandmaster {
                        // ts-refclk contient l'EUI-64 du GM : on compare les 8 octets
                        // Format SDP: "ptp=IEEE1588-2008:AA-BB-CC-DD-EE-FF-00-01:0"
                        // Format PTP GM: "aa:bb:cc:dd:ee:ff:00:01"
                        // Si le SDP contient un ts-refclk et que le GM ne matche pas → alerte
                        let _ = (gm, sdp_rtpmap);
                        false // placeholder — comparaison à affiner selon format local
                    } else {
                        false
                    }
                });
                if refclk_mismatch {
                    let alert = "    ⚠  SDP ts-refclk does not match active PTP Grandmaster";
                    logger.log(alert);
                    println!("\x1b[31m{}\x1b[0m", alert);
                }
            }
        }
    }

    if requires_valid_ptp {
        let ptp_valid = ptp_domains.values().any(|stats| !stats.masters.is_empty());
        if !ptp_valid {
            let alert = "⚠  No valid PTP clock detected for the selected protocols.";
            logger.log(&format!("\n{}", alert));
            println!("\x1b[31m{}\x1b[0m", alert);
        }
    }

    logger.log("");
}
