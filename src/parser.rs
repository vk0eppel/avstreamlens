// AVStreamLens — src/parser.rs
// Contains all functions responsible for detecting the type of network traffic
// and parsing the metadata packets (SDP, PTP, RTP, TCP, etc.).

/// AVStreamLens — parser.rs
/// Functions for network traffic detection and protocol parsing
/// (SDP, PTP, RTP, TCP, etc.)

use pnet_packet::{
    ethernet::EthernetPacket,
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

/// Extract an mDNS service instance name — the label immediately preceding a given
/// DNS-encoded service label (e.g. `\x04_ndi` for NDI, `\x09_netaudio` for Dante).
fn extract_mdns_instance_name(payload: &[u8], service_needle: &[u8]) -> Option<String> {
    let pos = payload.windows(service_needle.len())
        .position(|w| w == service_needle)?;
    if pos == 0 { return None; }
    let mut best: Option<String> = None;
    for name_len in 1usize..=63 {
        if pos < name_len + 1 { break; }
        let len_pos = pos - name_len - 1;
        if payload[len_pos] as usize != name_len { continue; }
        let name_bytes = &payload[len_pos + 1..pos];
        if let Ok(s) = std::str::from_utf8(name_bytes) {
            let s = s.trim();
            if !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                best = Some(s.to_string());
            }
        }
    }
    best
}

/// Extract the Dante device instance name from an mDNS payload.
pub fn extract_dante_name(payload: &[u8]) -> Option<String> {
    extract_mdns_instance_name(payload, b"\x09_netaudio")
}

/// Extract the NDI source instance name from an mDNS payload.
pub fn extract_ndi_name(payload: &[u8]) -> Option<String> {
    extract_mdns_instance_name(payload, b"\x04_ndi")
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

/// Peel off any 802.1Q / 802.1ad VLAN tags and return the inner EtherType
/// together with the slice of bytes that follows it (the L2 payload).
///
/// Handles single and stacked (QinQ) tags. Returns None if the frame is
/// truncated mid-tag.
pub fn unwrap_vlan<'a>(eth: &'a EthernetPacket<'a>) -> Option<(u16, &'a [u8])> {
    let raw = eth.packet();
    if raw.len() < 14 { return None; }
    let mut et   = u16::from_be_bytes([raw[12], raw[13]]);
    let mut off  = 14usize;
    // 0x8100 = 802.1Q,  0x88A8 = 802.1ad (QinQ),  0x9100 = legacy QinQ
    while et == 0x8100 || et == 0x88A8 || et == 0x9100 {
        if raw.len() < off + 4 { return None; }
        et  = u16::from_be_bytes([raw[off + 2], raw[off + 3]]);
        off += 4;
    }
    Some((et, &raw[off..]))
}

/// Analyzes an Ethernet frame to determine the encapsulated AV protocol.
pub fn detect_protocol(eth: &EthernetPacket) -> Option<AvProtocol> {
    let (raw_et, l2_payload) = unwrap_vlan(eth)?;

    // ── MSRP : L2 (EtherType 0x22EA) ────────────────────
    if raw_et == crate::protocols::ETHERTYPE_MSRP {
        let decls = parse_msrp(l2_payload);
        if !decls.is_empty() {
            return Some(AvProtocol::Msrp { declarations: decls });
        }
        return None;
    }

    // ── LLDP : L2 (EtherType 0x88CC) — scan for EEE TLV ─
    if raw_et == crate::protocols::ETHERTYPE_LLDP {
        return parse_lldp_eee(l2_payload);
    }

    // ── MVRP : L2 (EtherType 0x88F5) ────────────────────
    if raw_et == crate::protocols::ETHERTYPE_MVRP {
        let vlan_ids = parse_mvrp(l2_payload);
        if !vlan_ids.is_empty() {
            return Some(AvProtocol::Mvrp { vlan_ids });
        }
        return None;
    }

    // ── AVB / AVTP : L2 pure (EtherType 0x22F0) ─────────
    if raw_et == crate::protocols::ETHERTYPE_AVTP {
        let subtype   = l2_payload.first().copied().unwrap_or(0);
        let stream_id = parse_avtp_stream_id(l2_payload);
        return Some(AvProtocol::Avb { subtype, stream_id });
    }

    // ── gPTP / AVB : L2 (EtherType 0x88F7) ──────────────────────
    // L2 PTP frames carry the PTP payload directly after the Ethernet header — no IP layer.
    if raw_et == crate::protocols::ETHERTYPE_PTP {
        if let Some(mut info) = parse_ptp(l2_payload) {
            info.protocol_kind = Some("AVB".to_string());
            return Some(AvProtocol::Ptp { info });
        }
        return None;
    }

    // Non-IPv4 frames are not relevant past this point.
    if raw_et != 0x0800 { return None; }

    // ── IGMP (IP protocol 0x02, no UDP layer) ────────────
    if let Some(ip) = Ipv4Packet::new(l2_payload) {
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

    // NDI stream detection is handled in main.rs via IP-based matching (ndi_sources set
    // populated from mDNS discovery). A port-range check here would cause double-counting.

    // Try to extract IPv4/UDP layers
    let ip  = Ipv4Packet::new(l2_payload)?;
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
            let device_name = extract_dante_name(payload);
            return Some(AvProtocol::Dante { kind: DanteKind::Discovery { device_name }, src: src_ip, dst_port });
        }
        if mdns_contains(payload, b"_ndi._tcp") {
            let source_name = extract_ndi_name(payload);
            return Some(AvProtocol::Ndi { kind: NdiKind::Discovery { source_name }, src: src_ip });
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
    let (et, payload) = unwrap_vlan(eth)?;
    if et != 0x0800 { return None; }
    let ip = Ipv4Packet::new(payload)?;
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

fn ptp_class_str(class: u8) -> String {
    match class {
        6   => "Primary reference — locked".to_string(),
        7   => "Primary reference — free-running".to_string(),
        52  => "Application-specific".to_string(),
        135 => "Primary reference — holdover".to_string(),
        165 => "Default".to_string(),
        187 | 255 => "Slave-only".to_string(),
        _   => format!("class={}", class),
    }
}

fn ptp_accuracy_str(acc: u8) -> &'static str {
    match acc {
        0x20..=0x21 => "< 100 ns",
        0x22..=0x23 => "< 1 µs",
        0x24..=0x25 => "< 10 µs",
        0x26..=0x27 => "< 100 µs",
        0x28..=0x29 => "< 1 ms",
        0xFE        => "unknown precision",
        _           => "other",
    }
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
                .trim_end_matches('\0')
                .trim();
            let class_str = match stratum {
                1 => "Primary reference".to_string(),
                2 => "Secondary reference".to_string(),
                n => format!("Stratum {}", n),
            };
            let quality = if ident.is_empty() {
                class_str
            } else {
                format!("{}  {}", class_str, ident)
            };
            (Some(gm), Some(quality))
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
        // PTPv1 layout selection by header byte 0:
        //   0x11 = nibble-packed (versionPTP<<4 | versionNetwork) → hdr_shift = 2
        //   0x01 = separate-byte (versionPTP only)                → hdr_shift = 0
        // Falling back to subdomain-byte sniffing (payload[4]=='_') breaks for custom
        // subdomain names that don't start with '_'. Byte 0 is unambiguous per spec.
        let hdr_shift = if payload[0] == 0x11 { 2 } else { 0 };
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
        let clock_class    = payload[48];
        let clock_accuracy = payload[49];
        Some(format!("{}  {}", ptp_class_str(clock_class), ptp_accuracy_str(clock_accuracy)))
    } else {
        None
    };

    // IEEE 1588-2008 §5.3.3: correctionField is in units of ns × 2^16; shift right to get ns.
    let correction_field_ns = correction_field >> 16;

    // All PTPv2 messages carry a correction field; store it for every message type.
    let correction_ns = Some(correction_field_ns);

    // For Delay_Resp / P_Delay_Resp, the correction field represents path delay.
    let path_delay_ns = if message_type == 0x9 || message_type == 0x3 {
        Some(correction_field_ns)
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

// ═════════════════════════════════════════════════════════════════
// TESTS
// ═════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use pnet_packet::ethernet::EthernetPacket;
    use std::net::Ipv4Addr;

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Build a raw Ethernet frame: 12-byte dst+src prefix, then ethertype bytes,
    /// optional extra bytes (VLAN tags), then payload.
    fn eth_frame(ethertype: &[u8], extra: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(ethertype);
        f.extend_from_slice(extra);
        f.extend_from_slice(payload);
        f
    }

    /// Build a minimal valid PTPv2 Announce payload (64 bytes).
    fn ptpv2_announce(gm: [u8; 8], domain: u8, clock_class: u8, clock_acc: u8) -> Vec<u8> {
        let mut p = vec![0u8; 64];
        p[0]  = 0x0B;       // messageType = Announce
        p[1]  = 0x02;       // versionPTP = 2
        p[4]  = domain;
        p[20..28].copy_from_slice(&[0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22]); // clock_id
        p[30] = 0x00; p[31] = 0x07; // sequenceId = 7
        p[48] = clock_class;
        p[49] = clock_acc;
        p[53..61].copy_from_slice(&gm);
        p
    }

    /// Build a minimal PTPv1 nibble-packed Sync payload (66 bytes).
    fn ptpv1_nibble_sync(gm_uuid: [u8; 6], stratum: u8, ident: &[u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 66];
        p[0] = 0x11;                        // nibble-packed marker → hdr_shift=2
        p[4..9].copy_from_slice(b"_DFLT"); // subdomain → domain 0
        p[32] = 0x00;                       // control = Sync
        p[50..56].copy_from_slice(&gm_uuid);
        p[61] = stratum;
        p[62..66].copy_from_slice(ident);
        p
    }

    // ── parse_rtp ────────────────────────────────────────────────────────────

    #[test]
    fn rtp_valid_extracts_fields() {
        let p = [
            0x80, 0x60,              // V=2, PT=96
            0x00, 0x05,              // seq = 5
            0x00, 0x00, 0xBB, 0x80, // ts = 48000
            0xDE, 0xAD, 0xBE, 0xEF, // ssrc
        ];
        let (seq, ts, ssrc) = parse_rtp(&p).unwrap();
        assert_eq!(seq,  5);
        assert_eq!(ts,   48_000);
        assert_eq!(ssrc, 0xDEADBEEF);
    }

    #[test]
    fn rtp_wrong_version_returns_none() {
        let mut p = [0u8; 12];
        p[0] = 0x40; // V=1
        assert!(parse_rtp(&p).is_none());
    }

    #[test]
    fn rtp_too_short_returns_none() {
        assert!(parse_rtp(&[0x80, 0x60, 0x00]).is_none());
    }

    // ── parse_ptp — PTPv2 ────────────────────────────────────────────────────

    #[test]
    fn ptpv2_announce_extracts_grandmaster() {
        let gm = [0x00, 0x1A, 0xE5, 0xFF, 0xFE, 0x12, 0x34, 0x56];
        let p  = ptpv2_announce(gm, 0, 6, 0x20);
        let info = parse_ptp(&p).unwrap();
        assert_eq!(info.version, 2);
        assert_eq!(info.domain,  0);
        assert_eq!(info.grandmaster_id.as_deref(), Some("00:1a:e5:ff:fe:12:34:56"));
        let q = info.clock_quality.unwrap();
        assert!(q.contains("Primary reference — locked"), "got: {}", q);
        assert!(q.contains("< 100 ns"),                  "got: {}", q);
    }

    #[test]
    fn ptpv2_announce_domain_preserved() {
        let p = ptpv2_announce([0; 8], 3, 6, 0x20);
        assert_eq!(parse_ptp(&p).unwrap().domain, 3);
    }

    #[test]
    fn ptpv2_sync_has_no_grandmaster() {
        let mut p = vec![0u8; 44];
        p[0] = 0x00; p[1] = 0x02; // Sync, v2
        let info = parse_ptp(&p).unwrap();
        assert_eq!(info.message_type, 0x00);
        assert!(info.grandmaster_id.is_none());
    }

    #[test]
    fn ptpv2_too_short_returns_none() {
        assert!(parse_ptp(&[0x0B, 0x02, 0x00]).is_none());
    }

    // ── parse_ptp — PTPv1 ────────────────────────────────────────────────────

    #[test]
    fn ptpv1_nibble_packed_extracts_grandmaster() {
        let p = ptpv1_nibble_sync([0xAA,0xBB,0xCC,0xDD,0xEE,0xFF], 1, b"GPS ");
        let info = parse_ptp(&p).unwrap();
        assert_eq!(info.version, 1);
        assert_eq!(info.domain,  0);
        assert_eq!(info.grandmaster_id.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        let q = info.clock_quality.unwrap();
        assert!(q.contains("Primary reference"), "got: {}", q);
        assert!(q.contains("GPS"),               "got: {}", q);
    }

    #[test]
    fn ptpv1_separate_byte_detected() {
        let mut p = vec![0u8; 40];
        p[0]  = 0x01; // separate-byte marker → hdr_shift=0
        p[1]  = 0x01;
        p[30] = 0x00; // control = Sync
        let info = parse_ptp(&p).unwrap();
        assert_eq!(info.version,      1);
        assert_eq!(info.message_type, 0x00);
    }

    #[test]
    fn ptpv1_alt1_subdomain_maps_to_domain_1() {
        let mut p = vec![0u8; 40];
        p[0] = 0x01;
        p[1] = 0x01;
        p[2..7].copy_from_slice(b"_ALT1"); // hdr_shift=0, sd=2
        p[30] = 0x01; // Delay_Req
        let info = parse_ptp(&p).unwrap();
        assert_eq!(info.domain, 1);
    }

    // ── unwrap_vlan ──────────────────────────────────────────────────────────

    #[test]
    fn vlan_untagged_passthrough() {
        let frame = eth_frame(&[0x22, 0xF0], &[], &[0x01, 0x02]);
        let eth = EthernetPacket::new(&frame).unwrap();
        let (et, payload) = unwrap_vlan(&eth).unwrap();
        assert_eq!(et, 0x22F0);
        assert_eq!(payload, &[0x01, 0x02]);
    }

    #[test]
    fn vlan_single_802_1q_tag_stripped() {
        // 0x8100 | TCI(2) | inner-ET | payload
        let frame = eth_frame(&[0x81, 0x00], &[0x00, 0x64, 0x22, 0xF0], &[0xAA, 0xBB]);
        let eth = EthernetPacket::new(&frame).unwrap();
        let (et, payload) = unwrap_vlan(&eth).unwrap();
        assert_eq!(et, 0x22F0);
        assert_eq!(payload, &[0xAA, 0xBB]);
    }

    #[test]
    fn vlan_qinq_both_tags_stripped() {
        // 0x88A8(outer) | TCI | 0x8100(inner) | TCI | ET | payload
        let frame = eth_frame(
            &[0x88, 0xA8],
            &[0x00, 0x0A, 0x81, 0x00, 0x00, 0x64, 0x22, 0xF0],
            &[0xCC, 0xDD],
        );
        let eth = EthernetPacket::new(&frame).unwrap();
        let (et, payload) = unwrap_vlan(&eth).unwrap();
        assert_eq!(et, 0x22F0);
        assert_eq!(payload, &[0xCC, 0xDD]);
    }

    // ── parse_sdp ────────────────────────────────────────────────────────────

    #[test]
    fn sdp_single_media_section_parsed() {
        let sdp = "v=0\r\no=- 12345 1 IN IP4 192.168.1.1\r\ns=Stage Mix\r\n\
                   m=audio 5004 RTP/AVP 96\r\nc=IN IP4 239.69.0.1\r\n\
                   a=rtpmap:96 L24/48000/2\r\na=ptime:1\r\n";
        let s = parse_sdp(sdp);
        assert_eq!(s.session_id,   "12345");
        assert_eq!(s.session_name, "Stage Mix");
        assert_eq!(s.media.len(), 1);
        let m = &s.media[0];
        assert_eq!(m.port,     5004);
        assert_eq!(m.channels, 2);
        assert!((m.clock_hz - 48_000.0).abs() < 1.0);
        assert!((m.ptime_ms - 1.0).abs() < 0.01);
    }

    #[test]
    fn sdp_multiple_media_sections_all_captured() {
        // Verifies the fix that pushes the final media section after the loop.
        let sdp = "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\ns=Multi\r\n\
                   m=audio 5004 RTP/AVP 96\r\na=rtpmap:96 L24/48000/2\r\n\
                   m=video 5006 RTP/AVP 103\r\na=rtpmap:103 raw/90000\r\n";
        let s = parse_sdp(sdp);
        assert_eq!(s.media.len(), 2);
        assert_eq!(s.media[0].port, 5004);
        assert_eq!(s.media[1].port, 5006);
    }

    #[test]
    fn sdp_ts_refclk_attribute_captured() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\ns=X\r\n\
                   m=audio 5004 RTP/AVP 96\r\na=rtpmap:96 L24/48000\r\n\
                   a=ts-refclk:ptp=IEEE1588-2008:00-1a-e5-ff-fe-12-34-56:0\r\n";
        let s = parse_sdp(sdp);
        assert_eq!(s.media[0].ts_refclk,
                   "ptp=IEEE1588-2008:00-1a-e5-ff-fe-12-34-56:0");
    }

    // ── parse_ts_refclk ──────────────────────────────────────────────────────

    #[test]
    fn ts_refclk_ptpv2_dashes_normalised() {
        let (id, domain) = parse_ts_refclk(
            "ptp=IEEE1588-2008:00-1a-e5-ff-fe-12-34-56:0").unwrap();
        assert_eq!(id,     "00:1a:e5:ff:fe:12:34:56");
        assert_eq!(domain, 0);
    }

    #[test]
    fn ts_refclk_ptpv2_colons_domain_3() {
        let (id, domain) = parse_ts_refclk(
            "ptp=IEEE1588-2008:00:1a:e5:ff:fe:12:34:56:3").unwrap();
        assert_eq!(id,     "00:1a:e5:ff:fe:12:34:56");
        assert_eq!(domain, 3);
    }

    #[test]
    fn ts_refclk_ptpv1_uuid_parsed() {
        let (id, domain) = parse_ts_refclk(
            "ptp=IEEE1588-2002:00-1a-e5-ff-fe-12:0").unwrap();
        assert_eq!(id,     "00:1a:e5:ff:fe:12");
        assert_eq!(domain, 0);
    }

    #[test]
    fn ts_refclk_localmac_returns_none() {
        assert!(parse_ts_refclk("localmac=00-1a-e5-ff-fe-12-34-56").is_none());
    }

    // ── parse_msrp ───────────────────────────────────────────────────────────

    fn msrp_talker_advertise_pdu() -> Vec<u8> {
        // Header: version(1) + type(1) + attr_len(1) + list_len(2)
        // Then: VectorHeader(2) + FirstValue(25)
        let mut p = vec![
            0x00,       // MSRP version
            0x01,       // attr_type = TalkerAdvertise
            0x19,       // attr_len = 25
            0x00, 0x1B, // list_len = 27 (= 2 VectorHeader + 25 FirstValue)
            0x00, 0x01, // VectorHeader (NumberOfValues=1)
        ];
        p.extend_from_slice(&[0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x01]); // stream_id
        p.extend_from_slice(&[0x01,0x02,0x03,0x04,0x05,0x06]);            // dest_mac
        p.extend_from_slice(&[0x00, 0x64]);  // vlan_id = 100
        p.extend_from_slice(&[0x05, 0xDC]);  // max_frame_size = 1500
        p.extend_from_slice(&[0x00, 0x08]);  // max_interval_frames = 8
        p.push(0x60);                         // priority byte: (0x60 >> 5) & 7 = 3
        p.extend_from_slice(&[0x00; 4]);     // padding to reach attr_len=25
        p
    }

    #[test]
    fn msrp_talker_advertise_parsed() {
        let decls = parse_msrp(&msrp_talker_advertise_pdu());
        assert_eq!(decls.len(), 1);
        let d = &decls[0];
        assert!(matches!(d.decl_type, crate::protocols::MsrpDeclType::TalkerAdvertise));
        assert_eq!(d.stream_id,           [0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x01]);
        assert_eq!(d.vlan_id,             Some(100));
        assert_eq!(d.max_frame_size,      Some(1500));
        assert_eq!(d.max_interval_frames, Some(8));
        assert_eq!(d.priority,            Some(3));
    }

    #[test]
    fn msrp_empty_payload_returns_empty() {
        assert!(parse_msrp(&[]).is_empty());
    }

    #[test]
    fn msrp_wrong_version_returns_empty() {
        assert!(parse_msrp(&[0x01, 0x00]).is_empty());
    }

    // ── parse_mvrp ───────────────────────────────────────────────────────────

    #[test]
    fn mvrp_single_vlan_id_parsed() {
        let p = [
            0x00,       // version
            0x01,       // attr_type = VLAN member
            0x02,       // attr_len = 2
            0x00, 0x04, // list_len = 4
            0x00, 0x01, // VectorHeader
            0x00, 0x64, // FirstValue = VLAN 100
        ];
        assert_eq!(parse_mvrp(&p), vec![100]);
    }

    #[test]
    fn mvrp_empty_returns_empty() {
        assert!(parse_mvrp(&[]).is_empty());
    }

    // ── parse_lldp_eee ───────────────────────────────────────────────────────

    fn lldp_with_eee(tx: u16, rx: u16) -> Vec<u8> {
        let mut p = Vec::new();
        // Chassis ID TLV: type=1, len=7 → header = (1<<9)|7 = 0x0207
        p.extend_from_slice(&[0x02, 0x07, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        // Port ID TLV: type=2, len=7 → header = (2<<9)|7 = 0x0407
        p.extend_from_slice(&[0x04, 0x07, 0x03, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        // EEE TLV: type=127, len=14 → header = (127<<9)|14 = 0xFE0E
        // Value: OUI(3) + subtype(1) + Tw_sys_tx(2) + Tw_sys_rx(2) + zeros(8)
        p.extend_from_slice(&[0xFE, 0x0E, 0x00, 0x12, 0x0F, 0x05]);
        p.extend_from_slice(&tx.to_be_bytes());
        p.extend_from_slice(&rx.to_be_bytes());
        p.extend_from_slice(&[0x00; 8]);
        // End of LLDPDU
        p.extend_from_slice(&[0x00, 0x00]);
        p
    }

    #[test]
    fn lldp_eee_detected_with_wake_times() {
        let proto = parse_lldp_eee(&lldp_with_eee(16, 16)).unwrap();
        match proto {
            crate::protocols::AvProtocol::LldpEee { tx_wake_us, rx_wake_us, .. } => {
                assert_eq!(tx_wake_us, 16);
                assert_eq!(rx_wake_us, 16);
            }
            _ => panic!("expected LldpEee variant"),
        }
    }

    #[test]
    fn lldp_eee_zero_wake_times_ignored() {
        // EEE TLV present but both wake times are 0 — should not report as EEE
        assert!(parse_lldp_eee(&lldp_with_eee(0, 0)).is_none());
    }

    #[test]
    fn lldp_no_eee_tlv_returns_none() {
        let p = [
            0x02, 0x07, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // chassis
            0x04, 0x07, 0x03, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // port
            0x00, 0x00, // end
        ];
        assert!(parse_lldp_eee(&p).is_none());
    }

    // ── is_likely_dante_audio ────────────────────────────────────────────────

    #[test]
    fn dante_audio_both_ports_in_range_even() {
        assert!(is_likely_dante_audio(5002, 5004, 96));
    }

    #[test]
    fn dante_audio_ephemeral_src_port_rejected() {
        assert!(!is_likely_dante_audio(50000, 5004, 96));
    }

    #[test]
    fn dante_audio_odd_dst_port_rejected() {
        assert!(!is_likely_dante_audio(5002, 5005, 96));
    }

    #[test]
    fn dante_audio_dst_out_of_range_rejected() {
        assert!(!is_likely_dante_audio(5002, 6002, 96));
    }

    // ── multicast helpers ────────────────────────────────────────────────────

    #[test]
    fn aes67_multicast_address_recognised() {
        assert!( is_aes67_multicast( Ipv4Addr::new(239, 69, 0, 1)));
        assert!(!is_aes67_multicast( Ipv4Addr::new(239,  0, 0, 1)));
        assert!(!is_aes67_multicast( Ipv4Addr::new(192,168, 1, 1)));
    }

    #[test]
    fn st2110_multicast_address_recognised() {
        assert!( is_st2110_multicast(Ipv4Addr::new(239,  0, 0, 1)));
        assert!(!is_st2110_multicast(Ipv4Addr::new(239, 69, 0, 1))); // AES67, not ST2110
        assert!(!is_st2110_multicast(Ipv4Addr::new(192,168, 1, 1)));
    }

    // ── mDNS name extraction ─────────────────────────────────────────────────

    #[test]
    fn dante_name_extracted_from_mdns_label() {
        // DNS label encoding: \x05Stage + \x09_netaudio
        let mut p = vec![0x05, b'S', b't', b'a', b'g', b'e'];
        p.extend_from_slice(b"\x09_netaudio");
        assert_eq!(extract_dante_name(&p), Some("Stage".to_string()));
    }

    #[test]
    fn ndi_name_extracted_from_mdns_label() {
        // DNS label encoding: \x06Source + \x04_ndi
        let mut p = vec![0x06, b'S', b'o', b'u', b'r', b'c', b'e'];
        p.extend_from_slice(b"\x04_ndi");
        assert_eq!(extract_ndi_name(&p), Some("Source".to_string()));
    }

    #[test]
    fn dante_name_absent_returns_none() {
        assert!(extract_dante_name(b"no matching service here").is_none());
    }

    // ── map_ptpv1_subdomain ──────────────────────────────────────────────────

    #[test]
    fn ptpv1_subdomain_maps_to_domain_number() {
        let make = |s: &[u8]| { let mut a = [0u8; 16]; a[..s.len()].copy_from_slice(s); a };
        assert_eq!(map_ptpv1_subdomain(&make(b"_DFLT")), 0);
        assert_eq!(map_ptpv1_subdomain(&make(b"_ALT1")), 1);
        assert_eq!(map_ptpv1_subdomain(&make(b"_ALT2")), 2);
        assert_eq!(map_ptpv1_subdomain(&make(b"_ALT3")), 3);
        assert_eq!(map_ptpv1_subdomain(&make(b"custom")), 0); // unknown → default 0
    }
}
