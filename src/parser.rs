// AVStreamLens — src/parser.rs
// Top-level protocol dispatcher + small helpers (RTP, TCP, VLAN, multicast).
// Per-protocol parsers live in submodules under `parser/`.

pub mod sdp;
pub mod ptp;
pub mod avb;
pub mod lldp;
pub mod mdns;
pub mod flow_control;

// Re-export the public API so consumers (main.rs, capture.rs) can keep using
// `crate::parser::parse_*` and `crate::parser::extract_*` without churn.
pub use sdp::{parse_sap_packet, parse_ts_refclk};
pub use ptp::parse_ptp;
pub use avb::{parse_avtp_stream_id, parse_msrp, parse_mvrp};
pub use lldp::parse_lldp_eee;
pub use mdns::{extract_dante_name, extract_ndi_name, mdns_contains};
pub use flow_control::parse_flow_control;

use pnet_packet::{
    ethernet::EthernetPacket,
    ipv4::Ipv4Packet,
    udp::UdpPacket,
    tcp::TcpPacket,
    Packet,
};

use crate::protocols::{AvProtocol, St2110Type, DanteKind, NdiKind};
use std::net::Ipv4Addr;

// ═════════════════════════════════════════════════════════════════
// SECTION 1 — MULTICAST CLASSIFICATION
// ═════════════════════════════════════════════════════════════════

/// Class D: 224.0.0.0 to 239.255.255.255
pub fn is_multicast(ip: Ipv4Addr) -> bool {
    ip.octets()[0] >= 224 && ip.octets()[0] <= 239
}

/// Detect AES67 (first octet: 239.69.*)
pub fn is_aes67_multicast(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 239 && octets[1] == 69
}

/// Detect ST2110 multicast (first octet: 239.x.x.x where x ≠ 69)
pub fn is_st2110_multicast(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 239 && octets[1] != 69
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

/// Detect if a stream is likely Dante audio based on port and payload type patterns.
/// Dante requires BOTH endpoints to use even ports in 5000-6000 (transmitter and receiver
/// are both allocated from this range). OR logic produces false positives when any app
/// uses a Dante-range source port while sending to a high ephemeral destination port.
pub fn is_likely_dante_audio(src: u16, dst: u16, pt: u8) -> bool {
    let port_ok = ((5000..=6000).contains(&dst) && dst.is_multiple_of(2))
               && ((5000..=6000).contains(&src) && src.is_multiple_of(2));
    (pt == 0 || pt == 8 || pt >= 96) && port_ok
}

// ═════════════════════════════════════════════════════════════════
// SECTION 2 — VLAN UNWRAPPING
// ═════════════════════════════════════════════════════════════════

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

// ═════════════════════════════════════════════════════════════════
// SECTION 3 — TOP-LEVEL PROTOCOL DETECTION
// ═════════════════════════════════════════════════════════════════

/// Analyzes an Ethernet frame to determine the encapsulated AV protocol.
///
/// Dispatch order matters and is documented in CLAUDE.md under "Protocol Dispatch":
/// MSRP → LLDP → Flow-control → MVRP → AVTP/AVB → gPTP → IGMP → SAP → mDNS →
/// Dante control → UDP PTP → RTP gate → Dante audio (before AES67/ST2110 IP
/// checks) → AES67 → ST2110.
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

    // ── Flow control : L2 (EtherType 0x8808) — PAUSE / PFC
    if raw_et == crate::protocols::ETHERTYPE_FLOW_CTRL {
        return parse_flow_control(l2_payload);
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
    // subtype (byte 0), seq (byte 2), and stream_id (bytes 4-11) are all read from
    // the VLAN-unwrapped payload — AVB normally rides a tagged VLAN, so reading the
    // sequence counter from the raw Ethernet payload would land inside the 802.1Q tag.
    if raw_et == crate::protocols::ETHERTYPE_AVTP {
        let subtype   = l2_payload.first().copied().unwrap_or(0);
        let seq       = l2_payload.get(2).copied();
        let stream_id = parse_avtp_stream_id(l2_payload);
        return Some(AvProtocol::Avb { subtype, stream_id, seq });
    }

    // ── gPTP / AVB : L2 (EtherType 0x88F7) ──────────────
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
    if let Some(ip) = Ipv4Packet::new(l2_payload)
        && ip.get_next_level_protocol().0 == crate::protocols::IP_PROTO_IGMP
    {
        let src = ip.get_source();
        let group = ip.get_destination();
        let igmp_payload = ip.payload();
        let igmp_type = if igmp_payload.is_empty() {
            crate::protocols::IgmpType::Unknown(0)
        } else {
            match igmp_payload[0] {
                0x11 => crate::protocols::IgmpType::Query,
                0x16 | 0x22 => crate::protocols::IgmpType::Join,
                0x17 => crate::protocols::IgmpType::Leave,
                t    => crate::protocols::IgmpType::Unknown(t),
            }
        };
        return Some(AvProtocol::Igmp { src, group, igmp_type });
    }

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
        if mdns_contains(payload, b"\x09_netaudio")
            || mdns_contains(payload, b"\x0d_netaudio-cmc")
            || mdns_contains(payload, b"\x0d_netaudio-arc")
        {
            let device_name = extract_dante_name(payload);
            return Some(AvProtocol::Dante { kind: DanteKind::Discovery { device_name }, src: src_ip, dst: dst_ip, dst_port });
        }
        if mdns_contains(payload, b"\x04_ndi") {
            let source_name = extract_ndi_name(payload);
            return Some(AvProtocol::Ndi { kind: NdiKind::Discovery { source_name }, src: src_ip });
        }
        return None;
    }

    // ── Dante Control ───────────────────────────────────
    if crate::protocols::DANTE_CTRL_PORTS.contains(&dst_port) || crate::protocols::DANTE_CTRL_PORTS.contains(&src_port) {
        return Some(AvProtocol::Dante { kind: DanteKind::Control, src: src_ip, dst: dst_ip, dst_port });
    }

    // ── PTP over UDP (ports 319/320) ─────────────────────
    // Must come before the RTP gate: PTP payloads don't have RTP version bits set.
    let is_ptp_port = dst_port == crate::protocols::PTP_EVENT_PORT
        || dst_port == crate::protocols::PTP_GENERAL_PORT
        || src_port == crate::protocols::PTP_EVENT_PORT
        || src_port == crate::protocols::PTP_GENERAL_PORT;
    if is_ptp_port
        && let Some(mut info) = parse_ptp(payload)
    {
        info.protocol_kind = Some(if info.version == crate::protocols::PTP_VERSION_V1 {
            "PTPv1".to_string()
        } else {
            "PTPv2".to_string()
        });
        info.src_ip = Some(src_ip);
        return Some(AvProtocol::Ptp { info });
    }

    // ── RTP Streams ─────────────────────────────────────
    if payload.len() < 12 { return None; }
    if (payload[0] >> 6) & 0b11 != 2 { return None; }

    let payload_type = payload[1] & 0x7F;

    // Dante port check first — takes priority over IP-based multicast classification.
    // Dante multicast uses 239.x.x.x addresses (typically 239.255.*) which would otherwise
    // be misclassified as ST2110. Both src AND dst must be in 5000–6000 (even).
    if is_likely_dante_audio(src_port, dst_port, payload_type) {
        return Some(AvProtocol::Dante { kind: DanteKind::AudioStream, src: src_ip, dst: dst_ip, dst_port });
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

// ═════════════════════════════════════════════════════════════════
// SECTION 4 — TCP PARSING
// ═════════════════════════════════════════════════════════════════

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
// SECTION 5 — RTP PARSING
// ═════════════════════════════════════════════════════════════════

/// Parses raw RTP payload data to extract sequence number, timestamp, and SSRC.
pub fn parse_rtp(payload: &[u8]) -> Option<(u16, u32, u32)> {
    if payload.len() < 12 { return None; }
    if (payload[0] >> 6) & 0b11 != 2 { return None; }
    let seq  = u16::from_be_bytes([payload[2], payload[3]]);
    let ts   = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let ssrc = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    Some((seq, ts, ssrc))
}

// ═════════════════════════════════════════════════════════════════
// TESTS
// ═════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use pnet_packet::ethernet::EthernetPacket;

    /// Build a raw Ethernet frame: 12-byte dst+src prefix, then ethertype bytes,
    /// optional extra bytes (VLAN tags), then payload.
    fn eth_frame(ethertype: &[u8], extra: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(ethertype);
        f.extend_from_slice(extra);
        f.extend_from_slice(payload);
        f
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

    // ── AVTP detection on tagged frames ──────────────────────────────────────

    #[test]
    fn avtp_seq_read_from_unwrapped_payload_on_tagged_frame() {
        // Regression: the AVTP sequence counter must be read from the
        // VLAN-unwrapped payload (byte 2 of the AVTP header), not the raw
        // Ethernet payload — otherwise on a tagged AVB VLAN it lands inside the
        // 802.1Q tag and loss detection silently breaks.
        let mut avtp = vec![0x00, 0x81, 0x2A, 0x00]; // subtype, sv-bit, seq=42, reserved
        avtp.extend_from_slice(&[0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x01]); // stream_id
        // 0x8100 VLAN | TCI(VLAN 100) | inner ET 0x22F0 | AVTP payload
        let frame = eth_frame(&[0x81, 0x00], &[0x00, 0x64, 0x22, 0xF0], &avtp);
        let eth = EthernetPacket::new(&frame).unwrap();
        match detect_protocol(&eth) {
            Some(AvProtocol::Avb { subtype, stream_id, seq }) => {
                assert_eq!(subtype, 0x00);
                assert_eq!(seq, Some(0x2A), "seq must come from the AVTP header, not the VLAN tag");
                assert_eq!(stream_id, Some([0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x01]));
            }
            other => panic!("expected Avb, got {:?}", other),
        }
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
}
