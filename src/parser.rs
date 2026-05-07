// AVStreamLens — src/parser.rs
// Contains all functions responsible for detecting the type of network traffic
// and parsing the metadata packets (SDP, PTP, RTP, TCP, etc.).

use pnet_packet::{
    ethernet::{EthernetPacket, EtherTypes},
    ipv4::Ipv4Packet,
    udp::UdpPacket,
    tcp::TcpPacket,
    Packet,
};

// Import modules
use crate::protocols::{AvProtocol, St2110Type, DanteKind, NdiKind, SdpSession, SdpMedia, PtpInfo, DEFAULT_CLOCK_HZ};
use std::net::Ipv4Addr;

// ═════════════════════════════════════════════════════════════════
// SECTION 1 — NETWORK HELPERS & CONSTANTS
// ════════════════════════════════════════════════════════════════

const DEFAULT_BPF_FILTER: &str = "udp or (ether proto 0x22f0) or (ether proto 0x88f7)";

// ─────────────────────────────────────────────────────────
// Network Helpers - Multicast and Unicast Detection
// ─────────────────────────────────────────────────────────

pub fn is_aes67_multicast(ip: Ipv4Addr) -> bool {
    let o = ip.octets(); o[0] == 239 && o[1] == 69
}
pub fn is_st2110_multicast(ip: Ipv4Addr) -> bool {
    let o = ip.octets(); o[0] == 239 && o[1] != 69
}
pub fn is_multicast(ip: Ipv4Addr) -> bool {
    // Class D: 224.0.0.0 to 239.255.255.255
    ip.octets()[0] >= 224 && ip.octets()[0] <= 239
}
pub fn classify_st2110(pt: u8, port: u16) -> St2110Type {
    match port % 10 {
        4 => St2110Type::Video,
        6 => St2110Type::Audio,
        8 => St2110Type::Ancdata,
        _ => match pt {
            96..=107  => St2110Type::Video,
            108..=115 => St2110Type::Audio,
            116..=127 => St2110Type::Ancdata,
            _         => St2110Type::Unknown,
        }
    }
}
pub fn is_likely_dante_audio(src: u16, dst: u16, pt: u8) -> bool {
    let port_ok = ((5000..=6000).contains(&dst) && dst % 2 == 0)
               || ((5000..=6000).contains(&src) && src % 2 == 0);
    (pt == 0 || pt == 8 || pt >= 96) && port_ok
}
pub fn mdns_contains(payload: &[u8], service: &[u8]) -> bool {
    payload.windows(service.len()).any(|w| w == service)
}

// ═════════════════════════════════════════════════════════════════
// SECTION 2 — SDP PARSING (RFC 4566/2974)
// ══════════════════════════════════════════════════════════

/// Parse a UDP packet received on SAP port (9875).
/// Returns None if the SAP header is invalid or if SDP is empty.
pub fn parse_sap_packet(payload: &[u8]) -> Option<SdpSession> {
    // SAP header (RFC 2974):
    //   byte 0: V(3) A(1) R(1) T(1) E(1) C(1)  — version must be 1
    //   byte 1: auth len (in 32-bit words)
    //   bytes 2-3: msg id hash
    //   bytes 4-7: source IPv4 address (or 16 bytes IPv6 if A=1)
    if payload.len() < 8 { return None; }
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
pub fn parse_sdp(sdp: &str) -> SdpSession {
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

// ═════════════════════════════════════════════════════════════════
// SECTION 3 — PROTOCOL DETECTION (ETHERNET/IP/UDP)
// ══════════════════════════════════════════════════════════

/// Analyzes an Ethernet frame to determine the encapsulated AV protocol.
pub fn detect_protocol(eth: &EthernetPacket) -> Option<AvProtocol> {
    // ── AVB / AVTP : L2 pure (EtherType 0x22F0) ─────────
    let raw_et = u16::from_be_bytes([eth.packet()[12], eth.packet()[13]]);
    if raw_et == crate::protocols::ETHERTYPE_AVTP {
        let subtype = eth.payload().first().copied().unwrap_or(0);
        return Some(AvProtocol::Avb { subtype });
    }

    // ── PTP : L2 (EtherType 0x88F7) ──────────────────────
    if raw_et == crate::protocols::ETHERTYPE_PTP {
        if let Some(info) = parse_ptp(eth.payload()) {
            return Some(AvProtocol::Ptp { info });
        }
    }

    // ── IGMP (protocole IP 0x02, sans couche UDP) ────────
    if eth.get_ethertype() == EtherTypes::Ipv4 {
        if let Some(ip) = Ipv4Packet::new(eth.payload()) {
            if ip.get_next_level_protocol().0 == crate::protocols::IP_PROTO_IGMP {
                let src = ip.get_source();
                let group = ip.get_destination();
                let igmp_payload = ip.payload();
                let igmp_type = if igmp_payload.is_empty() {
                    crate::protocols::IgmpType::Unknown(0)
                } else {
                    match igmp_payload[0] {
                        0x11 => crate::protocols::IgmpType::Query,   // Membership Query
                        0x16 | 0x22 => crate::protocols::IgmpType::Join,   // v2 Report / v3 Report
                        0x17 => crate::protocols::IgmpType::Leave,
                        t    => crate::protocols::IgmpType::Unknown(t),
                    }
                };
                return Some(AvProtocol::Igmp { src, group, igmp_type });
            }
        }
    }

    if eth.get_ethertype() != EtherTypes::Ipv4 { return None; }

    // Try to extract IPv4/UDP layers
    let ip  = Ipv4Packet::new(eth.payload())?;
    let udp = UdpPacket::new(ip.payload())?;

    let src_ip   = ip.get_source();
    let dst_ip   = ip.get_destination();
    let dst_port = udp.get_destination();
    let src_port = udp.get_source();
    let payload  = udp.payload();

    // ── SAP (port 9875) ─────────────────────────────────
    if dst_port == crate::protocols::SAP_PORT {
        return parse_sap_packet(payload)
            .map(|sdp| AvProtocol::Sap { src: src_ip, sdp });
    }

    // ── mDNS (port 5353) ────────────────────────────────
    if dst_port == crate::protocols::MDNS_PORT || src_port == crate::protocols::MDNS_PORT {
        if mdns_contains(payload, b"_netaudio._udp") {
            return Some(AvProtocol::Dante { kind: DanteKind::Discovery, src: src_ip, dst_port });
        }
        if mdns_contains(payload, b"_ndi._tcp") {
            return Some(AvProtocol::Ndi { kind: NdiKind::Discovery, src: src_ip });
        }
        return None;
    }

    // ── Dante Control ───────────────────────────────────
    if crate::protocols::DANTE_CTRL_PORTS.contains(&dst_port) || crate::protocols::DANTE_CTRL_PORTS.contains(&src_port) {
        return Some(AvProtocol::Dante { kind: DanteKind::Control, src: src_ip, dst_port });
    }

    // ── NDI stream (ports 5960-5980) ─────────────────────
    if (crate::protocols::NDI_PORT_MIN..=crate::protocols::NDI_PORT_MAX).contains(&dst_port) {
        return Some(AvProtocol::Ndi { kind: NdiKind::Stream, src: src_ip });
    }

    // ── SRT handshake detection ───────────────────────────
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
    if (crate::protocols::RIST_PORT_BASE..5999).contains(&dst_port) && dst_port % 2 == 0
        && !is_aes67_multicast(dst_ip) && !is_st2110_multicast(dst_ip)
    {
        if payload.len() >= 12 && (payload[0] >> 6) & 0b11 == 2 {
            let pt = payload[1] & 0x7F;
            if pt >= 33 { // PT 33 = MP2T classique dans RIST
                return Some(AvProtocol::Rist { src: src_ip, dst: dst_ip, dst_port: dst_port });
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
    if dst_port == crate::protocols::PTP_EVENT_PORT || dst_port == crate::protocols::PTP_GENERAL_PORT || src_port == crate::protocols::PTP_EVENT_PORT || src_port == crate::protocols::PTP_GENERAL_PORT {
        if let Some(info) = parse_ptp(payload) {
            return Some(AvProtocol::Ptp { info });
        }
    }

    None
}


// ═════════════════════════════════════════════════════════════════
// SECTION 4 — TCP PARSING
// ══════════════════════════════════════════════════════════
// ══════════════════════════════════════════════════════════════════
pub type TcpData = (Ipv4Addr, Ipv4Addr, u16, u16, bool, bool, bool, u32, u32);

/// Parses a TCP packet to extract flow details (IP addresses, ports, and flags).
pub fn parse_tcp_packet(eth: &EthernetPacket) -> Option<TcpData> {
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

// ═════════════════════════════════════════════════════════════════
// SECTION 5 — RTP/PTP PARSING
// ══════════════════════════════════════════════════════════
// ══════════════════════════════════════════════════════════════════

/// Parses raw RTP payload data to extract sequence number, timestamp, and SSRC.
pub fn parse_rtp(payload: &[u8]) -> Option<(u16, u32, u32)> {
    if payload.len() < 12 { return None; }
    if (payload[0] >> 6) & 0b11 != 2 { return None; }
    let seq  = u16::from_be_bytes([payload[2], payload[3]]);
    let ts   = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let ssrc = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    Some((seq, ts, ssrc))
}

/// Parses a PTP message payload against defined RFC standards (RFC 6188).
pub fn parse_ptp(payload: &[u8]) -> Option<PtpInfo> {
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
