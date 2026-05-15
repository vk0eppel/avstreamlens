// AVStreamLens — src/parser.rs
// Contains all functions responsible for detecting the type of network traffic
// and parsing the metadata packets (SDP, PTP, RTP, TCP, etc.).

/// AVStreamLens — parser.rs
/// Functions for network traffic detection and protocol parsing
/// (SDP, PTP, RTP, TCP, etc.)

use pnet_packet::{
    ethernet::{EthernetPacket, EtherTypes},
    ipv4::Ipv4Packet,
    udp::UdpPacket,
    tcp::TcpPacket,
    Packet,
};

use crate::protocols::{AvProtocol, St2110Type, DanteKind, NdiKind, SdpSession, SdpMedia, PtpInfo, MsrpDeclaration, MsrpDeclType, DEFAULT_CLOCK_HZ, PTP_VERSION_V1, PTP_VERSION_V2};
use std::net::Ipv4Addr;

// Constants for network filtering and detection
// BPF filter string for default monitoring
// Multicast detection for AV/PTP streams
// BPF filter string for default monitoring
pub const DEFAULT_BPF_FILTER: &str = "udp or (ether proto 0x22F0) or (ether proto 0x88F7)";
// Class D: 224.0.0.0 to 239.255.255.255
pub fn is_multicast(ip: Ipv4Addr) -> bool {
    ip.octets()[0] >= 224 && ip.octets()[0] <= 239
}
// Detect AES67 (first octet: 239.69.*)
pub fn is_aes67_multicast(ip: Ipv4Addr) -> bool {
    let octets = ip.octets(); octets[0] == 239 && octets[1] == 69
}
// Detect ST2110 multicast (first octet: 239.x.x.x where x ≠ 69)
pub fn is_st2110_multicast(ip: Ipv4Addr) -> bool {
    let octets = ip.octets(); octets[0] == 239 && octets[1] != 69
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
// Detect if a stream is likely Dante audio based on port and payload type patterns
pub fn is_likely_dante_audio(src: u16, dst: u16, pt: u8) -> bool {
    // Dante requires BOTH endpoints to use even ports in 5000-6000 (transmitter and receiver
    // are both allocated from this range). OR logic produces false positives when any app
    // uses a Dante-range source port while sending to a high ephemeral destination port.
    let port_ok = ((5000..=6000).contains(&dst) && dst % 2 == 0)
               && ((5000..=6000).contains(&src) && src % 2 == 0);
    (pt == 0 || pt == 8 || pt >= 96) && port_ok
}
// Check if mDNS payload contains a specific service string (e.g., "_netaudio._udp" or "_ndi._tcp")
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

    // Push the last media section — the loop only pushes on the next 'm=' line,
    // so the final block is still in cur_media when the loop ends.
    if let Some(m) = cur_media { session.media.push(m); }

    session
}

// ═════════════════════════════════════════════════════════════════
// SECTION 2a — LLDP / EEE PARSER
// ═════════════════════════════════════════════════════════════════

/// Parse an LLDP frame (EtherType 0x88CC) looking for the IEEE 802.3az EEE TLV.
///
/// LLDP TLV encoding: `[type(7 bits) | length(9 bits)][value]`
/// EEE TLV: type=127 (org-specific), OUI=00-12-0F, subtype=0x05
/// Value layout: Tw_sys_tx(2) Tw_sys_rx(2) Fallback_tw(2) Tx_tw_echo(2) Rx_tw_echo(2)
///
/// Returns Some only when EEE TLV is present and at least one wake-up time is non-zero.
pub fn parse_lldp_eee(payload: &[u8]) -> Option<crate::protocols::AvProtocol> {
    let mut pos = 0usize;
    let mut chassis_id = String::new();
    let mut port_id    = String::new();
    let mut tx_wake: u16 = 0;
    let mut rx_wake: u16 = 0;
    let mut eee_found  = false;

    while pos + 2 <= payload.len() {
        let header  = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let tlv_type   = (header >> 9) as u8;
        let tlv_len    = (header & 0x01FF) as usize;
        pos += 2;

        if tlv_type == 0 { break; } // End of LLDPDU
        if pos + tlv_len > payload.len() { break; }

        let value = &payload[pos..pos + tlv_len];

        match tlv_type {
            1 => { // Chassis ID
                if tlv_len >= 2 {
                    chassis_id = format_lldp_id(&value[1..]);
                }
            }
            2 => { // Port ID
                if tlv_len >= 2 {
                    port_id = format_lldp_id(&value[1..]);
                }
            }
            127 if tlv_len >= 4 => { // Organizationally Specific
                let oui     = (value[0] as u32) << 16 | (value[1] as u32) << 8 | value[2] as u32;
                let subtype = value[3];
                // IEEE 802.3 OUI = 0x00120F, EEE subtype = 0x05
                if oui == 0x00120F && subtype == 0x05 && tlv_len >= 14 {
                    tx_wake   = u16::from_be_bytes([value[4],  value[5]]);
                    rx_wake   = u16::from_be_bytes([value[6],  value[7]]);
                    eee_found = true;
                }
            }
            _ => {}
        }

        pos += tlv_len;
    }

    if eee_found && (tx_wake > 0 || rx_wake > 0) {
        Some(crate::protocols::AvProtocol::LldpEee {
            chassis_id,
            port_id,
            tx_wake_us: tx_wake,
            rx_wake_us: rx_wake,
        })
    } else {
        None
    }
}

fn format_lldp_id(bytes: &[u8]) -> String {
    // Try UTF-8 first (port descriptions are often ASCII)
    if let Ok(s) = std::str::from_utf8(bytes) {
        if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            return s.trim().to_string();
        }
    }
    // Fall back to colon-separated hex
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
}

// ═════════════════════════════════════════════════════════════════
// SECTION 2b — AVB PROTOCOL PARSERS (AVTP / MSRP / MVRP)
// ═════════════════════════════════════════════════════════════════

/// Extract the AVTP stream_id from a raw AVTP payload (after Ethernet header).
/// Returns Some only when the stream_valid (sv) bit is set.
pub fn parse_avtp_stream_id(payload: &[u8]) -> Option<[u8; 8]> {
    if payload.len() < 12 { return None; }
    if payload[1] & 0x80 == 0 { return None; } // sv bit not set
    payload[4..12].try_into().ok()
}

/// Parse an MSRP PDU (IEEE 802.1Qat, EtherType 0x22EA).
/// Returns a vec of Talker Advertise, Talker Failed, and Listener declarations.
/// Ignores Domain messages (type 4) and unknown types.
pub fn parse_msrp(payload: &[u8]) -> Vec<MsrpDeclaration> {
    let mut decls = Vec::new();
    if payload.is_empty() || payload[0] != 0x00 { return decls; } // ProtocolVersion check

    let mut pos = 1usize;
    while pos < payload.len() {
        let attr_type = payload[pos];
        if attr_type == 0x00 { break; } // end-mark
        if pos + 4 > payload.len() { break; }

        let attr_len  = payload[pos + 1] as usize;
        let list_len  = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;

        // VectorHeader (2 bytes) + FirstValue (attr_len bytes)
        if pos + 2 + attr_len > payload.len() { break; }
        let first_value = &payload[pos + 2 .. pos + 2 + attr_len];

        match attr_type {
            1 if attr_len >= 25 => { // TalkerAdvertise
                let stream_id: [u8; 8] = first_value[0..8].try_into().unwrap_or([0u8; 8]);
                let dest_mac:  [u8; 6] = first_value[8..14].try_into().unwrap_or([0u8; 6]);
                let vlan_id    = u16::from_be_bytes([first_value[14], first_value[15]]) & 0x0FFF;
                let max_frame  = u16::from_be_bytes([first_value[16], first_value[17]]);
                let max_frames = u16::from_be_bytes([first_value[18], first_value[19]]);
                let priority   = (first_value[20] >> 5) & 0x07;
                decls.push(MsrpDeclaration {
                    decl_type: MsrpDeclType::TalkerAdvertise,
                    stream_id,
                    dest_mac: Some(dest_mac),
                    vlan_id: Some(vlan_id),
                    max_frame_size: Some(max_frame),
                    max_interval_frames: Some(max_frames),
                    priority: Some(priority),
                    failure_code: None,
                    listener_state: None,
                });
            }
            2 if attr_len >= 34 => { // TalkerFailed
                let stream_id: [u8; 8] = first_value[0..8].try_into().unwrap_or([0u8; 8]);
                let dest_mac:  [u8; 6] = first_value[8..14].try_into().unwrap_or([0u8; 6]);
                let vlan_id    = u16::from_be_bytes([first_value[14], first_value[15]]) & 0x0FFF;
                let max_frame  = u16::from_be_bytes([first_value[16], first_value[17]]);
                let max_frames = u16::from_be_bytes([first_value[18], first_value[19]]);
                let priority   = (first_value[20] >> 5) & 0x07;
                let failure    = first_value[28];
                decls.push(MsrpDeclaration {
                    decl_type: MsrpDeclType::TalkerFailed,
                    stream_id,
                    dest_mac: Some(dest_mac),
                    vlan_id: Some(vlan_id),
                    max_frame_size: Some(max_frame),
                    max_interval_frames: Some(max_frames),
                    priority: Some(priority),
                    failure_code: Some(failure),
                    listener_state: None,
                });
            }
            3 if attr_len >= 9 => { // Listener
                let stream_id: [u8; 8] = first_value[0..8].try_into().unwrap_or([0u8; 8]);
                let state = first_value[8];
                decls.push(MsrpDeclaration {
                    decl_type: MsrpDeclType::Listener,
                    stream_id,
                    dest_mac: None,
                    vlan_id: None,
                    max_frame_size: None,
                    max_interval_frames: None,
                    priority: None,
                    failure_code: None,
                    listener_state: Some(state),
                });
            }
            _ => {} // Domain (4) or unknown — skip
        }

        // Advance past VectorHeader + AttributeList
        if list_len == 0 { break; }
        pos += list_len;
    }
    decls
}

/// Parse an MVRP PDU (IEEE 802.1Q, EtherType 0x88F5).
/// Returns the list of VLAN IDs being registered (deduped).
pub fn parse_mvrp(payload: &[u8]) -> Vec<u16> {
    let mut vlans: Vec<u16> = Vec::new();
    if payload.is_empty() || payload[0] != 0x00 { return vlans; }

    let mut pos = 1usize;
    while pos < payload.len() {
        let attr_type = payload[pos];
        if attr_type == 0x00 { break; }
        if pos + 4 > payload.len() { break; }

        let attr_len = payload[pos + 1] as usize;
        let list_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;

        // VLAN ID: AttributeType=1, AttributeLength=2
        if attr_type == 1 && attr_len == 2 && pos + 2 + 2 <= payload.len() {
            let vid = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) & 0x0FFF;
            if vid > 0 && !vlans.contains(&vid) { vlans.push(vid); }
        }

        if list_len == 0 { break; }
        pos += list_len;
    }
    vlans
}

// ═════════════════════════════════════════════════════════════════
// SECTION 3 — PROTOCOL DETECTION (ETHERNET/IP/UDP)
// ══════════════════════════════════════════════════════════

/// Analyzes an Ethernet frame to determine the encapsulated AV protocol.
pub fn detect_protocol(eth: &EthernetPacket) -> Option<AvProtocol> {
    let raw_et = u16::from_be_bytes([eth.packet()[12], eth.packet()[13]]);

    // ── MSRP : L2 (EtherType 0x22EA) ────────────────────
    if raw_et == crate::protocols::ETHERTYPE_MSRP {
        let decls = parse_msrp(eth.payload());
        if !decls.is_empty() {
            return Some(AvProtocol::Msrp { declarations: decls });
        }
        return None;
    }

    // ── LLDP : L2 (EtherType 0x88CC) — scan for EEE TLV ─
    if raw_et == crate::protocols::ETHERTYPE_LLDP {
        return parse_lldp_eee(eth.payload());
    }

    // ── MVRP : L2 (EtherType 0x88F5) ────────────────────
    if raw_et == crate::protocols::ETHERTYPE_MVRP {
        let vlan_ids = parse_mvrp(eth.payload());
        if !vlan_ids.is_empty() {
            return Some(AvProtocol::Mvrp { vlan_ids });
        }
        return None;
    }

    // ── AVB / AVTP : L2 pure (EtherType 0x22F0) ─────────
    if raw_et == crate::protocols::ETHERTYPE_AVTP {
        let subtype   = eth.payload().first().copied().unwrap_or(0);
        let stream_id = parse_avtp_stream_id(eth.payload());
        return Some(AvProtocol::Avb { subtype, stream_id });
    }

    // ── gPTP / AVB : L2 (EtherType 0x88F7) ──────────────────────
    // L2 PTP frames carry the PTP payload directly after the Ethernet header — no IP layer.
    if raw_et == crate::protocols::ETHERTYPE_PTP {
        if let Some(mut info) = parse_ptp(eth.payload()) {
            info.protocol_kind = Some("AVB".to_string());
            return Some(AvProtocol::Ptp { info });
        }
        return None;
    }

    // ── IGMP (IP protocol 0x02, no UDP layer) ────────────
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

    // NDI stream detection is handled in main.rs via IP-based matching (ndi_sources set
    // populated from mDNS discovery). A port-range check here would cause double-counting.

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

    // ── PTP over UDP (ports 319/320) ─────────────────────
    // Must come before the RTP gate: PTP payloads don't have RTP version bits set.
    if dst_port == crate::protocols::PTP_EVENT_PORT || dst_port == crate::protocols::PTP_GENERAL_PORT || src_port == crate::protocols::PTP_EVENT_PORT || src_port == crate::protocols::PTP_GENERAL_PORT {
        if let Some(mut info) = parse_ptp(payload) {
            info.protocol_kind = Some(if info.version == crate::protocols::PTP_VERSION_V1 {
                "PTPv1".to_string()
            } else {
                "PTPv2".to_string()
            });
            info.src_ip = Some(src_ip);
            return Some(AvProtocol::Ptp { info });
        }
    }

    // ── RTP Streams ─────────────────────────────────────────
    if payload.len() < 12 { return None; }
    if (payload[0] >> 6) & 0b11 != 2 { return None; }

    let payload_type = payload[1] & 0x7F;

    // Dante port check first — takes priority over IP-based multicast classification.
    // Dante multicast uses 239.x.x.x addresses (typically 239.255.*) which would otherwise
    // be misclassified as ST2110. Both src AND dst must be in 5000–6000 (even).
    if is_likely_dante_audio(src_port, dst_port, payload_type) {
        return Some(AvProtocol::Dante { kind: DanteKind::AudioStream, src: src_ip, dst_port });
    }
    if is_aes67_multicast(dst_ip) {
        return Some(AvProtocol::Aes67 { src: src_ip, dst: dst_ip, dst_port, payload_type });
    }
    if is_st2110_multicast(dst_ip) {
        return Some(AvProtocol::St2110 {
            src: src_ip, dst: dst_ip, dst_port,
            stream_type: classify_st2110(payload_type, dst_port),
        });
    }

    None
}

// ═══════════════════════════════════════════════════════════
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

/// Parse a `ts-refclk` SDP attribute value into `(normalized_grandmaster_id, domain)`.
///
/// Handles:
/// - `ptp=IEEE1588-2008:<eui64>:<domain>` — PTPv2, 8-byte EUI-64 (dashes or colons)
/// - `ptp=IEEE1588-2002:<uuid>:<domain>`  — PTPv1, 6-byte MAC
///
/// Returns `None` for non-PTP types (`localmac=...`, etc.).
/// The returned ID uses lowercase colon-separated bytes, matching `PtpStats::last_grandmaster`.
pub fn parse_ts_refclk(s: &str) -> Option<(String, u8)> {
    let rest = if let Some(r) = s.strip_prefix("ptp=IEEE1588-2008:") {
        r
    } else if let Some(r) = s.strip_prefix("ptp=IEEE1588-2002:") {
        r
    } else {
        return None;
    };

    // The last colon-separated token is the domain number; everything before is the clock ID.
    // EUI-64 example: "00-1d-c1-ff-fe-12-34-56:0"  or  "00:1d:c1:ff:fe:12:34:56:0"
    // Split on the final ':' to separate ID from domain.
    let last_colon = rest.rfind(':')?;
    let id_part    = &rest[..last_colon];
    let domain_str = &rest[last_colon + 1..];
    let domain: u8 = domain_str.trim().parse().ok()?;

    // Normalize: replace '-' with ':', lowercase
    let normalized = id_part.replace('-', ":").to_lowercase();

    Some((normalized, domain))
}

// ─── PTPv1 subdomain → domain number mapping ────────────────────────────────
// IEEE 1588-2002 uses 16-byte ASCII subdomain names instead of a numeric domain.
// The four well-known names map to 0–3; anything else maps to 0 (unknown = default).
fn map_ptpv1_subdomain(s: &[u8]) -> u8 {
    let s = &s[..16.min(s.len())];
    let starts = |prefix: &[u8]| s.starts_with(prefix);
    if      starts(b"_ALT1") { 1 }
    else if starts(b"_ALT2") { 2 }
    else if starts(b"_ALT3") { 3 }
    else                      { 0 }  // "_DFLT" and anything else → 0
}

/// Parse a PTPv1 (IEEE 1588-2002) UDP payload.
///
/// Two wire encodings exist, distinguished by `hdr_shift`:
///
/// Separate-byte (hdr_shift=0, e.g. ptpd):
///   [0]     versionPTP = 0x01
///   [1]     versionNetwork = 0x01
///   [2-17]  subdomain (16 bytes)
///   [20-25] sourceUuid   [26-27] sourcePortId   [28-29] sequenceId
///   [30]    control      [31]    logMessagePeriod
///
/// Nibble-packed (hdr_shift=2, byte[0]=0x11):
///   [0]     (versionPTP=1)<<4 | versionNetwork=1  = 0x11
///   [1]     (messageType)<<4  | sourceCT          = 0x11 for Sync/UDP
///   [2-3]   flags
///   [4-19]  subdomain (16 bytes)
///   [22-27] sourceUuid   [28-29] sourcePortId   [30-31] sequenceId
///   [32]    control      [33]    logMessagePeriod
///
/// Sync body (bytes 40-123, same absolute offsets for both encodings):
///   [40-49] originTimestamp   [50-53] epochNumber/UTC offset
///   [54]    padding   [55] grandmasterCommunicationTechnology
///   [56-61] grandmasterClockUuid (6 bytes)
///   [62-67] grandmasterPortId / sequenceId / padding
///   [67]    grandmasterClockStratum
///   [68-71] grandmasterClockIdentifier (4 bytes ASCII, e.g. "ATOM", "GPS ")
fn parse_ptp_v1(payload: &[u8], hdr_shift: usize) -> Option<PtpInfo> {
    if payload.len() < 40 { return None; }

    let sd = 2 + hdr_shift;   // subdomain start
    let uu = 20 + hdr_shift;  // sourceUuid start
    let po = 26 + hdr_shift;  // sourcePortId offset
    let sq = 28 + hdr_shift;  // sequenceId offset
    let ct = 30 + hdr_shift;  // control byte
    let lp = 31 + hdr_shift;  // logMessagePeriod

    let domain      = map_ptpv1_subdomain(&payload[sd..sd + 16]);
    let control     = payload[ct];
    let sequence_id = u16::from_be_bytes([payload[sq], payload[sq + 1]]);
    let log_sync_interval = payload[lp] as i8;

    let (message_type, message_name) = match control {
        0x00 => (0x00u8, "Sync"),
        0x01 => (0x01u8, "Delay_Req"),
        0x02 => (0x08u8, "Follow_Up"),
        0x03 => (0x09u8, "Delay_Resp"),
        0x04 => (0x0Du8, "Management"),
        _    => (0xFFu8, "Unknown"),
    };

    let clock_id = Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        payload[uu], payload[uu+1], payload[uu+2],
        payload[uu+3], payload[uu+4], payload[uu+5]
    ));

    let port_id = Some(u16::from_be_bytes([payload[po], payload[po + 1]]));

    // Grandmaster fields in the Sync body (body starts at byte 34, same for both encodings):
    //   [34-35] epoch  [36-39] seconds  [40-43] nanoseconds  [44-45] epochNumber
    //   [46-47] utcOffset  [48] pad  [49] gmCommunicationTechnology
    //   [50-55] grandmasterClockUuid   [56-57] gmPortId   [58-59] gmSequenceId
    //   [60] pad  [61] gmClockStratum  [62-65] gmClockIdentifier (4-char ASCII)
    let (grandmaster_id, clock_quality) = if message_type == 0x00 && payload.len() >= 66 {
        let uuid = &payload[50..56];
        if uuid.iter().all(|&b| b == 0) {
            (None, None)  // not yet configured
        } else {
            let gm = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5]
            );
            let stratum = payload[61];
            let ident   = std::str::from_utf8(&payload[62..66])
                .unwrap_or("????")
                .trim_end_matches('\0');
            (Some(gm), Some(format!("stratum={} ident={}", stratum, ident)))
        }
    } else {
        (None, None)
    };

    Some(PtpInfo {
        version:                     PTP_VERSION_V1,
        message_type,
        domain,
        clock_id,
        grandmaster_id,
        clock_quality,
        correction_ns:               None,
        path_delay_ns:               None,
        origin_timestamp_ns:         None,
        message_name:                message_name.to_string(),
        port_id,
        sequence_id,
        log_sync_interval,
        log_min_pdelay_req_interval: 0,
        protocol_kind:               None,
        src_ip:                      None, // set by caller
    })
}

/// Parses a PTP message payload against defined RFC standards (RFC 6188).
pub fn parse_ptp(payload: &[u8]) -> Option<PtpInfo> {
    if payload.len() < 2 { return None; }

    // PTPv2 has one reliable wire marker: versionPTP = 2 in the low nibble of byte 1.
    // Anything that doesn't match is PTPv1 (we are already in a PTP context: port 319/320
    // or EtherType 0x88F7, so non-PTP traffic is not a concern here).
    if payload[1] & 0x0F != PTP_VERSION_V2 {
        // Auto-detect PTPv1 layout by checking the subdomain start:
        //   nibble-packed (byte[0]=0x11): subdomain at byte 4  → hdr_shift = 2
        //   separate-byte (byte[0]=0x01): subdomain at byte 2  → hdr_shift = 0
        // All standard PTPv1 subdomains begin with '_' (0x5F), making payload[4]=='_'
        // a reliable indicator of the nibble-packed layout.
        let hdr_shift = if payload.len() >= 5 && payload[4] == b'_' { 2 } else { 0 };
        return parse_ptp_v1(payload, hdr_shift);
    }

    // Common header is 34 bytes — enough to identify domain, clock, and message type.
    // Announce-specific fields (grandmaster) require 64 bytes and are guarded below.
    if payload.len() < 34 { return None; }

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

    let version_ptp = PTP_VERSION_V2;
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
    // PTPv2 originTimestamp: 6-byte seconds (34–39) + 4-byte nanoseconds (40–43)
    let origin_timestamp_ns = if payload.len() >= 44 {
        let seconds = u64::from_be_bytes([
            0, 0, payload[34], payload[35], payload[36], payload[37], payload[38], payload[39],
        ]);
        let nanos = u32::from_be_bytes([payload[40], payload[41], payload[42], payload[43]]);
        Some(seconds.saturating_mul(1_000_000_000).saturating_add(nanos as u64))
    } else {
        None
    };

    // Parse grandmaster info (Announce messages)
    // PTPv1 (RFC 6188): version=0, clock_class at offset 48
    let grandmaster_id = if message_type == 0x0B && payload.len() >= 64 {
        Some(format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            payload[53], payload[54], payload[55], payload[56],
            payload[57], payload[58], payload[59], payload[60]))
    } else {
        None
    };

    let clock_quality = if message_type == 0x0B && payload.len() >= 64 {
        let clock_class = payload[48];
        let clock_accuracy = payload[49];
        let log_var = u16::from_be_bytes([payload[50], payload[51]]);
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
        version:           version_ptp,
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
        protocol_kind:     None,  // set by caller
        src_ip:            None,  // set by caller
    })
}
