// AVStreamLens — src/parser.rs
// Top-level protocol dispatcher + small helpers (RTP, TCP, VLAN, multicast).
// Per-protocol parsers live in submodules under `parser/`.

pub mod sdp;
pub mod ptp;
pub mod avb;
pub mod avdecc;
pub mod lldp;
pub mod mdns;
pub mod flow_control;
pub mod conmon;

// Re-export the public API so consumers (main.rs, capture.rs) can keep using
// `crate::parser::parse_*` and `crate::parser::extract_*` without churn.
pub use sdp::{parse_sap_packet, parse_ts_refclk};
pub use ptp::parse_ptp;
pub use avb::{parse_avtp_stream_id, parse_msrp, parse_mvrp};
pub use avdecc::{parse_adp, fmt_eui64, media_type_summary, sr_class_str};
pub use lldp::parse_lldp_eee;
pub use mdns::{extract_dante_name, extract_ndi_name, mdns_contains};
pub use flow_control::parse_flow_control;
pub use conmon::parse_conmon;

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

/// "Dante audio" at the wire level is the union of three independent
/// heuristics, added incrementally as field cases turned up (see TODO.md's
/// open Dante port-range verification items) — no single function decides it:
///   1. **ATP official ports** (`detect_protocol_unwrapped`'s pre-RTP-gate
///      check): `239.255/16` dst port 4321 (multicast), or either src or dst
///      in 14336–15359 (unicast — field-confirmed asymmetric, e.g. a
///      software DVS's ephemeral port talking to a hardware peer's fixed
///      port). Non-RTP framing, so it's checked before the RTP version gate.
///   2. **`is_likely_dante_audio`** (below): strict, RTP-framed — both src
///      AND dst ports even in 5000–6000. Catches unicast and unambiguous
///      multicast transmit flows.
///   3. **`is_dante_multicast`**: RTP-framed, dst-port-only — `239.255/16`
///      with an even dst port in 5000–6000. Exists because (2) misses
///      multicast transmit flows whose source port is outside 5000–6000; this
///      is also what stops `is_st2110_multicast`'s catch-all from stealing
///      those flows (see `AUDIO_CLASSIFICATION_RULES`).
///
/// A reader auditing "does this tool recognize Dante audio on port X" needs
/// all three, not just the one nearest their diff.
///
/// Detect Dante's default multicast block (239.255.0.0/16). Dante multicast audio
/// flows are addressed here; the generic `is_st2110_multicast` catch-all would
/// otherwise claim them, so detection consults this block before falling through.
pub fn is_dante_multicast(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 239 && octets[1] == 255
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
/// Handles single and stacked (QinQ) tags. Returns `(EtherType, outermost-tag
/// PCP, payload)`. PCP is `Some` only when at least one VLAN tag was present;
/// `None` for untagged frames. Returns None if the frame is truncated mid-tag.
pub fn unwrap_vlan<'a>(eth: &'a EthernetPacket<'a>) -> Option<(u16, Option<u8>, &'a [u8])> {
    let raw = eth.packet();
    if raw.len() < 14 { return None; }
    let mut et   = u16::from_be_bytes([raw[12], raw[13]]);
    let mut off  = 14usize;
    let mut pcp: Option<u8> = None;
    // 0x8100 = 802.1Q,  0x88A8 = 802.1ad (QinQ),  0x9100 = legacy QinQ
    while et == 0x8100 || et == 0x88A8 || et == 0x9100 {
        if raw.len() < off + 4 { return None; }
        // Capture the outermost tag's PCP (bits [15:13] of the TCI word).
        // QinQ inner tags are ignored — outermost tag is what the switch reads.
        if pcp.is_none() {
            pcp = Some((raw[off] >> 5) & 0x07);
        }
        et  = u16::from_be_bytes([raw[off + 2], raw[off + 3]]);
        off += 4;
    }
    Some((et, pcp, &raw[off..]))
}

// ═════════════════════════════════════════════════════════════════
// SECTION 3 — TOP-LEVEL PROTOCOL DETECTION
// ═════════════════════════════════════════════════════════════════

/// Parse an IGMPv3 Membership Report (type 0x22) and extract the multicast group
/// addresses from its Group Records (RFC 3376 §4.2).
///
/// Layout after the IP header:
///   byte 0:   type = 0x22
///   byte 1:   reserved
///   bytes 2-3: checksum
///   bytes 4-5: reserved
///   bytes 6-7: number of group records (big-endian u16)
///   then for each record:
///     byte 0:   record type
///     byte 1:   aux data len (in 32-bit words)
///     bytes 2-3: number of sources (big-endian u16)
///     bytes 4-7: multicast address
///     then: 4*num_sources source bytes, then 4*aux_data_len aux bytes
fn parse_igmpv3_report(payload: &[u8]) -> crate::protocols::IgmpType {
    if payload.len() < 8 {
        return crate::protocols::IgmpType::MembershipReportV3 { groups: vec![] };
    }
    let num_records = u16::from_be_bytes([payload[6], payload[7]]) as usize;
    let mut groups = Vec::new();
    let mut off = 8usize;
    for _ in 0..num_records {
        if off + 8 > payload.len() { break; }
        let aux_len     = payload[off + 1] as usize;
        let num_sources = u16::from_be_bytes([payload[off + 2], payload[off + 3]]) as usize;
        let mcast = Ipv4Addr::new(
            payload[off + 4], payload[off + 5], payload[off + 6], payload[off + 7],
        );
        if mcast.is_multicast() {
            groups.push(mcast);
        }
        off += 8 + 4 * num_sources + 4 * aux_len;
    }
    crate::protocols::IgmpType::MembershipReportV3 { groups }
}

/// Analyzes an Ethernet frame (with VLAN tags already peeled by the caller) to
/// determine the encapsulated AV protocol. `main.rs` peels the tags once via
/// [`unwrap_vlan`] and passes the result here so the tag stack isn't walked
/// twice on the per-packet hot path. `eth` is still needed for the Ethernet
/// source MAC (IGMP querier identity) and for `parse_tcp_packet`; `AvProtocol`
/// is fully owned, so nothing in the result borrows `l2_payload`. Tests call the
/// `detect_protocol(&eth)` convenience wrapper at the bottom of this file.
///
/// Dispatch order matters and is documented in CLAUDE.md under "Protocol Dispatch":
/// MSRP → LLDP → Flow-control → MVRP → AVTP/AVB → gPTP → IGMP → SAP → mDNS →
/// Dante control → UDP PTP → RTP gate → Dante audio (before AES67/ST2110 IP
/// checks) → AES67 → ST2110.
pub fn detect_protocol_unwrapped(eth: &EthernetPacket, raw_et: u16, l2_payload: &[u8]) -> Option<AvProtocol> {
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
        // AVDECC ADP: byte 0 = 0xFA (cd=1, subtype=0x7A). Destination MAC is
        // 91:E0:F0:01:00:00, a globally registered multicast that bridges MUST
        // forward — this is how Milan Manager / Hive discover all devices without
        // a SPAN port. Handle before the generic AVTP path so sv=0 frames are not
        // silently discarded by handle_avb's stream-id gate.
        if l2_payload.first().copied() == Some(0xFA) {
            return parse_adp(l2_payload).map(AvProtocol::AvdeccAdp);
        }
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
        let m = eth.get_source();
        let src_mac = [m.0, m.1, m.2, m.3, m.4, m.5];
        let group = ip.get_destination();
        let igmp_payload = ip.payload();
        let igmp_type = if igmp_payload.is_empty() {
            crate::protocols::IgmpType::Unknown(0)
        } else {
            match igmp_payload[0] {
                0x11 => crate::protocols::IgmpType::Query {
                    version: if igmp_payload.len() >= 12 { 3 } else { 2 },
                },
                0x16 => crate::protocols::IgmpType::Join,
                0x17 => crate::protocols::IgmpType::Leave,
                0x22 => parse_igmpv3_report(igmp_payload),
                t    => crate::protocols::IgmpType::Unknown(t),
            }
        };
        return Some(AvProtocol::Igmp { src, src_mac, group, igmp_type });
    }

    // ── TCP (NDI's only transport) — plain decode, no NDI awareness here ──
    // `is_selected` gates this on NDI; `handle_tcp` does the is-this-actually-NDI
    // judgment against `ndi.sources` and the NDI port range.
    if let Some((src, dst, src_port, dst_port, has_fin, has_syn, has_rst, seq, ack)) =
        parse_tcp_packet(eth)
    {
        return Some(AvProtocol::Tcp(crate::protocols::TcpSegment {
            src, dst, src_port, dst_port, seq, ack, has_fin, has_syn, has_rst,
        }));
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
        // DNS QR bit (payload[2] bit 7): 0 = query, 1 = response.
        // Only responses carry PTR/SRV records with real device instance names.
        // Outgoing queries from the local machine contain the same service-label
        // bytes in the question section, so without this guard they would be
        // classified as Dante/NDI discovery with src_ip = the local machine's IP.
        let is_mdns_response = payload.get(2).is_some_and(|b| b & 0x80 != 0);
        if is_mdns_response {
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
        }
        return None;
    }

    // ── Dante ConMon (control & monitoring, ports 8700–8708) ─────────────
    // Multicast ConMon (224.0.0.230–233) is in the link-local 224.0.0.0/24
    // block that IGMP snooping never prunes — a continuous liveness signal
    // for every Dante device, visible from any port without SPAN. Must run
    // before the generic Dante-control port check, which overlaps on 8700.
    if (8700..=8708).contains(&dst_port)
        && let Some(cm) = parse_conmon(payload)
    {
        return Some(AvProtocol::Dante {
            kind: DanteKind::ConMon { device_mac: cm.device_mac, channels: cm.channels },
            src: src_ip, dst: dst_ip, dst_port,
        });
    }

    // ── Dante Control ───────────────────────────────────
    if crate::protocols::DANTE_CTRL_PORTS.contains(&dst_port) || crate::protocols::DANTE_CTRL_PORTS.contains(&src_port) {
        return Some(AvProtocol::Dante { kind: DanteKind::Control, src: src_ip, dst: dst_ip, dst_port });
    }

    // ── Dante control-plane fingerprint (DVS / Via / FPGA-hardware ports) ─
    // Product-specific control/monitoring port families positively identify the
    // source's Transmitter Class (DVS vs Via vs Hardware) without needing a
    // mirror port for its audio flow. Hardware ConMon (8700–8708) and control
    // (8800) are already handled above.
    if let Some(class) = crate::protocols::dante_control_plane_class(src_port, dst_port) {
        return Some(AvProtocol::Dante {
            kind: DanteKind::ControlPlane { class },
            src: src_ip, dst: dst_ip, dst_port,
        });
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

    // ── Dante ATP audio (official Audinate port allocations) ─────────────
    // Per Audinate's port list: multicast ATP audio = 239.255.0.0/16 dst port
    // 4321; unicast audio/video flows allocate from UDP 14336–15359. ATP
    // framing is not RTP, so this must run BEFORE the RTP version gate below.
    // The legacy RTP-gated 5000–6000 heuristic further down is retained
    // alongside. Field-confirmed (2026-07-06, DVS-to-hardware capture): only
    // ONE endpoint of a real unicast flow uses this range — a software
    // Dante Virtual Soundcard picks an arbitrary ephemeral port for its own
    // socket while the hardware peer uses a fixed in-range port (e.g.
    // 49158 → 14337). Requiring both ports in range silently dropped the
    // entire stream, so only one side is required — same tolerance
    // `is_dante_multicast` already applies to an out-of-range source port.
    if (is_dante_multicast(dst_ip) && dst_port == 4321)
        || (14336..=15359).contains(&dst_port)
        || (14336..=15359).contains(&src_port)
    {
        return Some(AvProtocol::Dante { kind: DanteKind::AudioStream, src: src_ip, dst: dst_ip, dst_port });
    }

    // ── RTP Streams ─────────────────────────────────────
    if payload.len() < 12 { return None; }
    if (payload[0] >> 6) & 0b11 != 2 { return None; }

    let payload_type = payload[1] & 0x7F;
    let ctx = AudioClassifyCtx { src_ip, dst_ip, src_port, dst_port, payload_type };
    AUDIO_CLASSIFICATION_RULES.iter().find_map(|rule| rule(&ctx))
}

/// Inputs needed to classify an RTP-bearing flow as Dante Audio Flow, AES67,
/// or ST2110 — used only by `AUDIO_CLASSIFICATION_RULES` below, not by the
/// earlier ATP/PTP/ConMon checks, which have unambiguous wire signatures of
/// their own and never reach this stage.
struct AudioClassifyCtx {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload_type: u8,
}

/// Dante/AES67/ST2110 classification precedence, evaluated top-to-bottom by
/// `detect_protocol_unwrapped`. This list's *order* is the ADR-0001 invariant
/// made explicit: Dante must be checked before the ST2110 catch-all, or a
/// Dante multicast flow in 239.255/16 gets stolen by `classify_st2110_stream`
/// (see docs/adr/0001-dante-st2110-classification.md). Previously this
/// precedence lived only in the position of four `if` statements in a function
/// body, protected by a single regression test and prose comments — this list
/// is now the one place the precedence itself lives; the pinning test
/// (`st2110_catch_all_is_the_last_classification_rule`) checks the list
/// directly rather than only inferring the order from behavior.
const AUDIO_CLASSIFICATION_RULES: &[fn(&AudioClassifyCtx) -> Option<AvProtocol>] = &[
    classify_dante_strict_ports,
    classify_dante_multicast_block,
    classify_aes67_stream,
    classify_st2110_stream,
];

/// Dante port check first — takes priority over IP-based multicast classification.
/// Dante multicast uses 239.x.x.x addresses (typically 239.255.*) which would otherwise
/// be misclassified as ST2110. Both src AND dst must be in 5000–6000 (even).
fn classify_dante_strict_ports(ctx: &AudioClassifyCtx) -> Option<AvProtocol> {
    is_likely_dante_audio(ctx.src_port, ctx.dst_port, ctx.payload_type).then_some(AvProtocol::Dante {
        kind: DanteKind::AudioStream, src: ctx.src_ip, dst: ctx.dst_ip, dst_port: ctx.dst_port,
    })
}

/// Multicast Dante (239.255.0.0/16): the strict both-ports rule above can miss
/// transmit flows whose source port isn't in range. For Dante's dedicated
/// multicast block, require only the destination port to be in the Dante range —
/// enough to stop the ST2110 239.x catch-all below from stealing the stream.
/// A 239.255.x.x flow on a non-Dante port still falls through to ST2110.
fn classify_dante_multicast_block(ctx: &AudioClassifyCtx) -> Option<AvProtocol> {
    (is_dante_multicast(ctx.dst_ip) && (5000..=6000).contains(&ctx.dst_port) && ctx.dst_port.is_multiple_of(2))
        .then_some(AvProtocol::Dante { kind: DanteKind::AudioStream, src: ctx.src_ip, dst: ctx.dst_ip, dst_port: ctx.dst_port })
}

fn classify_aes67_stream(ctx: &AudioClassifyCtx) -> Option<AvProtocol> {
    is_aes67_multicast(ctx.dst_ip).then_some(AvProtocol::Aes67 {
        src: ctx.src_ip, dst: ctx.dst_ip, dst_port: ctx.dst_port, payload_type: ctx.payload_type,
    })
}

fn classify_st2110_stream(ctx: &AudioClassifyCtx) -> Option<AvProtocol> {
    is_st2110_multicast(ctx.dst_ip).then(|| AvProtocol::St2110 {
        src: ctx.src_ip, dst: ctx.dst_ip, dst_port: ctx.dst_port,
        stream_type: classify_st2110(ctx.payload_type, ctx.dst_port),
    })
}

// ═════════════════════════════════════════════════════════════════
// SECTION 4 — TCP PARSING
// ═════════════════════════════════════════════════════════════════

pub type TcpData = (Ipv4Addr, Ipv4Addr, u16, u16, bool, bool, bool, u32, u32);

/// Parses a TCP packet to extract flow details (IP addresses, ports, and flags).
pub fn parse_tcp_packet(eth: &EthernetPacket) -> Option<TcpData> {
    let (et, _pcp, payload) = unwrap_vlan(eth)?;
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

    /// Convenience wrapper used throughout these tests: peel VLAN tags then
    /// dispatch. Production code calls `detect_protocol_unwrapped` directly,
    /// reusing the unwrap it already performs per packet.
    fn detect_protocol(eth: &EthernetPacket) -> Option<AvProtocol> {
        let (raw_et, _pcp, l2_payload) = unwrap_vlan(eth)?;
        detect_protocol_unwrapped(eth, raw_et, l2_payload)
    }

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
        let (et, pcp, payload) = unwrap_vlan(&eth).unwrap();
        assert_eq!(et, 0x22F0);
        assert_eq!(pcp, None, "untagged frames carry no PCP");
        assert_eq!(payload, &[0x01, 0x02]);
    }

    #[test]
    fn vlan_single_802_1q_tag_stripped() {
        // 0x8100 | TCI(PCP=3,DEI=0,VID=100) | inner-ET | payload
        // TCI = 0x60 0x64 → PCP = (0x60 >> 5) & 0x07 = 3
        let frame = eth_frame(&[0x81, 0x00], &[0x60, 0x64, 0x22, 0xF0], &[0xAA, 0xBB]);
        let eth = EthernetPacket::new(&frame).unwrap();
        let (et, pcp, payload) = unwrap_vlan(&eth).unwrap();
        assert_eq!(et, 0x22F0);
        assert_eq!(pcp, Some(3), "PCP extracted from outermost tag");
        assert_eq!(payload, &[0xAA, 0xBB]);
    }

    #[test]
    fn vlan_qinq_both_tags_stripped() {
        // 0x88A8(outer PCP=5) | TCI | 0x8100(inner PCP=3) | TCI | ET | payload
        // outer TCI first byte = 0xA0 → PCP = 5; inner TCI = 0x60 → PCP = 3
        let frame = eth_frame(
            &[0x88, 0xA8],
            &[0xA0, 0x0A, 0x81, 0x00, 0x60, 0x64, 0x22, 0xF0],
            &[0xCC, 0xDD],
        );
        let eth = EthernetPacket::new(&frame).unwrap();
        let (et, pcp, payload) = unwrap_vlan(&eth).unwrap();
        assert_eq!(et, 0x22F0);
        assert_eq!(pcp, Some(5), "outermost tag PCP returned, not inner");
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

    #[test]
    fn avdecc_adp_frame_not_classified_as_generic_avb() {
        // detect_protocol_unwrapped checks payload[0] == 0xFA (AVDECC ADP, cd=1
        // subtype=0x7A) before falling into the generic sv-bit AVTP path — pins
        // that ordering so a future edit can't let ADP frames fall through and
        // become phantom Avb streams with no stream_id.
        let mut adp = vec![0xFAu8, 0x00]; // byte0 = 0xFA, message_type = AVAILABLE
        adp.extend_from_slice(&[0u8; 62]); // pad past parse_adp's 49-byte minimum
        let frame = eth_frame(&[0x22, 0xF0], &[], &adp);
        let eth = EthernetPacket::new(&frame).unwrap();
        assert!(
            matches!(detect_protocol(&eth), Some(AvProtocol::AvdeccAdp(_))),
            "byte0=0xFA must be classified as AvdeccAdp, never generic AvProtocol::Avb"
        );
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

    // ── multicast Dante vs ST2110 classification ─────────────────────────────

    /// Build an Ethernet+IPv4+UDP+RTP frame for detect_protocol tests.
    fn eth_ip_udp_rtp(dst: Ipv4Addr, src_port: u16, dst_port: u16, pt: u8) -> Vec<u8> {
        let mut ip = vec![0u8; 20 + 8 + 12];
        ip[0] = 0x45;                                       // v4, IHL=5
        let total: u16 = (20 + 8 + 12) as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip[8] = 64;                                         // TTL
        ip[9] = 0x11;                                       // UDP
        ip[12..16].copy_from_slice(&[192, 168, 1, 10]);     // src ip
        ip[16..20].copy_from_slice(&dst.octets());          // dst ip
        ip[20..22].copy_from_slice(&src_port.to_be_bytes());
        ip[22..24].copy_from_slice(&dst_port.to_be_bytes());
        ip[24..26].copy_from_slice(&20u16.to_be_bytes());   // UDP length
        ip[28] = 0x80;                                      // RTP V=2
        ip[29] = pt & 0x7F;
        eth_frame(&[0x08, 0x00], &[], &ip) // EtherType IPv4
    }

    #[test]
    fn dante_multicast_with_ephemeral_src_classified_as_dante() {
        // 239.255.0.1:5004 with an out-of-range source port — the strict both-ports
        // rule would miss it, and the ST2110 catch-all must NOT claim it.
        let frame = eth_ip_udp_rtp(Ipv4Addr::new(239, 255, 0, 1), 41000, 5004, 96);
        let eth = EthernetPacket::new(&frame).unwrap();
        assert!(matches!(detect_protocol(&eth),
            Some(AvProtocol::Dante { kind: DanteKind::AudioStream, .. })),
            "multicast Dante must not be misclassified as ST2110");
    }

    #[test]
    fn dante_port_heuristic_wins_over_aes67_multicast_address() {
        // is_likely_dante_audio (parser.rs) checks only ports, never dst_ip — it
        // runs before the is_aes67_multicast check in detect_protocol_unwrapped.
        // A stream addressed to AES67's own 239.69.0.0/16 block, but using both
        // ports in Dante's strict 5000-6000-even range, is classified Dante, not
        // AES67. This pins that current, easy-to-miss ordering fact rather than
        // changing it — unlike the Dante/ST2110 zone documented in ADR-0001, this
        // collision has no device-discovery tie-breaker today.
        let frame = eth_ip_udp_rtp(Ipv4Addr::new(239, 69, 0, 1), 5002, 5004, 96);
        let eth = EthernetPacket::new(&frame).unwrap();
        assert!(matches!(detect_protocol(&eth),
            Some(AvProtocol::Dante { kind: DanteKind::AudioStream, .. })),
            "Dante's port-only heuristic takes priority over the AES67 IP block");
    }

    /// The Dante/AES67/ST2110 precedence lives in `AUDIO_CLASSIFICATION_RULES`'s
    /// order, not in if-statement position — pins the invariant structurally
    /// (the ST2110 catch-all is last) rather than only behaviorally, so a
    /// future reorder that happens to preserve today's specific test cases
    /// still gets caught if it moves the catch-all out of last place.
    #[test]
    fn st2110_catch_all_is_the_last_classification_rule() {
        let last = *AUDIO_CLASSIFICATION_RULES.last().expect("rule list must not be empty");
        assert_eq!(last as *const (), classify_st2110_stream as *const (),
            "the ST2110 catch-all must stay last — see docs/adr/0001-dante-st2110-classification.md");
    }

    #[test]
    fn st2110_multicast_outside_dante_block_unaffected() {
        // 239.1.2.3 is not Dante's block — stays ST2110 even on an even Dante-range port.
        let frame = eth_ip_udp_rtp(Ipv4Addr::new(239, 1, 2, 3), 41000, 5006, 96);
        let eth = EthernetPacket::new(&frame).unwrap();
        assert!(matches!(detect_protocol(&eth), Some(AvProtocol::St2110 { .. })));
    }

    /// Build an Ethernet+IPv4+UDP frame with an arbitrary UDP payload
    /// (for non-RTP protocols: ConMon, ATP).
    fn eth_ip_udp(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = (8 + payload.len()) as u16;
        let mut ip = vec![0u8; 20 + 8 + payload.len()];
        ip[0] = 0x45;                                       // v4, IHL=5
        let total = (20 + udp_len) as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip[8] = 64;                                         // TTL
        ip[9] = 0x11;                                       // UDP
        ip[12..16].copy_from_slice(&src.octets());
        ip[16..20].copy_from_slice(&dst.octets());
        ip[20..22].copy_from_slice(&src_port.to_be_bytes());
        ip[22..24].copy_from_slice(&dst_port.to_be_bytes());
        ip[24..26].copy_from_slice(&udp_len.to_be_bytes());
        ip[28..].copy_from_slice(payload);
        eth_frame(&[0x08, 0x00], &[], &ip)
    }

    /// Minimal valid ConMon payload: length field + sender MAC + "Audinate".
    fn conmon_payload(mac: [u8; 6]) -> Vec<u8> {
        let mut p = vec![0u8; 64];
        p[0] = 0xff; p[1] = 0xff;
        p[2..4].copy_from_slice(&(64u16).to_be_bytes());
        p[8..14].copy_from_slice(&mac);
        p[16..24].copy_from_slice(b"Audinate");
        p
    }

    // ── Dante ConMon detection ───────────────────────────────────────────────

    #[test]
    fn conmon_multicast_frame_classified_as_dante_conmon() {
        let mac = [0x00, 0x1d, 0xc1, 0x19, 0x86, 0x2a];
        let frame = eth_ip_udp(
            Ipv4Addr::new(169, 254, 81, 11), Ipv4Addr::new(224, 0, 0, 232),
            51340, 8705, &conmon_payload(mac),
        );
        let eth = EthernetPacket::new(&frame).unwrap();
        match detect_protocol(&eth) {
            Some(AvProtocol::Dante { kind: DanteKind::ConMon { device_mac, .. }, src, .. }) => {
                assert_eq!(device_mac, mac);
                assert_eq!(src, Ipv4Addr::new(169, 254, 81, 11));
            }
            other => panic!("expected Dante ConMon, got {:?}", other),
        }
    }

    #[test]
    fn port_8700_without_audinate_signature_stays_dante_control() {
        // 8700 overlaps DANTE_CTRL_PORTS — a non-ConMon payload on it must keep
        // the existing Control classification, not be dropped by the ConMon parse.
        let frame = eth_ip_udp(
            Ipv4Addr::new(192, 168, 1, 50), Ipv4Addr::new(192, 168, 1, 60),
            40000, 8700, &[0u8; 32],
        );
        let eth = EthernetPacket::new(&frame).unwrap();
        assert!(matches!(detect_protocol(&eth),
            Some(AvProtocol::Dante { kind: DanteKind::Control, .. })));
    }

    // ── Dante control-plane fingerprint (DVS / Via / FPGA ports) ────────────

    #[test]
    fn dvs_control_port_classified_as_control_plane_dvs() {
        use crate::protocols::TransmitterClass;
        let frame = eth_ip_udp(
            Ipv4Addr::new(192, 168, 1, 70), Ipv4Addr::new(192, 168, 1, 71),
            50000, 38700, &[0u8; 16],
        );
        let eth = EthernetPacket::new(&frame).unwrap();
        assert!(matches!(detect_protocol(&eth),
            Some(AvProtocol::Dante { kind: DanteKind::ControlPlane { class: TransmitterClass::Dvs }, .. })));
    }

    #[test]
    fn via_control_port_classified_as_control_plane_via() {
        use crate::protocols::TransmitterClass;
        let frame = eth_ip_udp(
            Ipv4Addr::new(192, 168, 1, 72), Ipv4Addr::new(192, 168, 1, 73),
            28700, 50000, &[0u8; 16],
        );
        let eth = EthernetPacket::new(&frame).unwrap();
        assert!(matches!(detect_protocol(&eth),
            Some(AvProtocol::Dante { kind: DanteKind::ControlPlane { class: TransmitterClass::Via }, .. })));
    }

    #[test]
    fn fpga_keepalive_port_classified_as_control_plane_hardware() {
        use crate::protocols::TransmitterClass;
        // FPGA keepalive fingerprints on the DESTINATION port (61440–61951 overlaps
        // the ephemeral source-port range, so a src port there must not match).
        let frame = eth_ip_udp(
            Ipv4Addr::new(192, 168, 1, 74), Ipv4Addr::new(192, 168, 1, 75),
            50000, 61500, &[0u8; 16],
        );
        let eth = EthernetPacket::new(&frame).unwrap();
        assert!(matches!(detect_protocol(&eth),
            Some(AvProtocol::Dante { kind: DanteKind::ControlPlane { class: TransmitterClass::Hardware }, .. })));
    }

    // ── Dante ATP audio (official ports, non-RTP framing) ───────────────────

    #[test]
    fn atp_multicast_port_4321_classified_as_dante_audio() {
        // Official multicast ATP audio: 239.255.0.0/16 dst port 4321, not RTP-framed.
        // Must be classified before the RTP gate would discard it.
        let frame = eth_ip_udp(
            Ipv4Addr::new(169, 254, 81, 11), Ipv4Addr::new(239, 255, 10, 1),
            14400, 4321, &[0u8; 64],
        );
        let eth = EthernetPacket::new(&frame).unwrap();
        assert!(matches!(detect_protocol(&eth),
            Some(AvProtocol::Dante { kind: DanteKind::AudioStream, .. })));
    }

    #[test]
    fn atp_unicast_official_range_classified_as_dante_audio() {
        // Official unicast audio/video flows: both endpoints in UDP 14336–15359.
        let frame = eth_ip_udp(
            Ipv4Addr::new(192, 168, 1, 50), Ipv4Addr::new(192, 168, 1, 60),
            14400, 15000, &[0u8; 64],
        );
        let eth = EthernetPacket::new(&frame).unwrap();
        assert!(matches!(detect_protocol(&eth),
            Some(AvProtocol::Dante { kind: DanteKind::AudioStream, .. })));
    }

    #[test]
    fn atp_unicast_classified_when_only_dst_port_in_range() {
        // Field-confirmed (2026-07-06): a Dante Virtual Soundcard uses an
        // arbitrary ephemeral source port while the hardware peer uses a
        // fixed in-range port — e.g. 49158 → 14337 in a real capture.
        let frame = eth_ip_udp(
            Ipv4Addr::new(169, 254, 123, 52), Ipv4Addr::new(169, 254, 52, 47),
            49158, 14337, &[0u8; 64],
        );
        let eth = EthernetPacket::new(&frame).unwrap();
        assert!(matches!(detect_protocol(&eth),
            Some(AvProtocol::Dante { kind: DanteKind::AudioStream, .. })));
    }

    #[test]
    fn atp_unicast_classified_when_only_src_port_in_range() {
        // The reverse direction of the same real flow: fixed in-range source
        // port replying to the ephemeral destination port.
        let frame = eth_ip_udp(
            Ipv4Addr::new(169, 254, 52, 47), Ipv4Addr::new(169, 254, 123, 52),
            14337, 49158, &[0u8; 64],
        );
        let eth = EthernetPacket::new(&frame).unwrap();
        assert!(matches!(detect_protocol(&eth),
            Some(AvProtocol::Dante { kind: DanteKind::AudioStream, .. })));
    }

    #[test]
    fn atp_unicast_neither_port_in_range_falls_through() {
        // Neither endpoint in 14336–15359 → not claimed as Dante ATP;
        // non-RTP payload then falls through to None.
        let frame = eth_ip_udp(
            Ipv4Addr::new(192, 168, 1, 50), Ipv4Addr::new(192, 168, 1, 60),
            40000, 40001, &[0u8; 64],
        );
        let eth = EthernetPacket::new(&frame).unwrap();
        assert!(detect_protocol(&eth).is_none());
    }

    #[test]
    fn dante_multicast_nonaudio_port_falls_through_to_st2110() {
        // 239.255.x.x but a non-Dante destination port → we only claim the Dante
        // port range, so this remains ST2110.
        let frame = eth_ip_udp_rtp(Ipv4Addr::new(239, 255, 1, 1), 41000, 50000, 96);
        let eth = EthernetPacket::new(&frame).unwrap();
        assert!(matches!(detect_protocol(&eth), Some(AvProtocol::St2110 { .. })));
    }

    // ── IGMP query with the IP Router Alert option (IHL=6) ───────────────────

    #[test]
    fn igmpv3_query_with_router_alert_option_detected() {
        // Real IGMP queries carry the IP Router Alert option (RFC 2113), making the
        // IP header 24 bytes (IHL=6), not 20 — so the IGMP type byte sits at offset
        // 24, not 20. This is the exact on-wire shape verified against a live Luminex
        // IGMPv3 querier (2026-05-30: 10.244.70.241 → 224.0.0.1, length 36, options RA).
        // The other IGMP fixtures only build IHL=5 headers, so this pins the real path.
        let mut ip = vec![0u8; 24 + 12];
        ip[0] = 0x46; // v4, IHL=6 (24-byte header with one 4-byte option)
        let total: u16 = (24 + 12) as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip[8] = 1; // TTL=1 (link-local query)
        ip[9] = 0x02; // proto IGMP
        ip[12..16].copy_from_slice(&[10, 244, 70, 241]); // querier src
        ip[16..20].copy_from_slice(&[224, 0, 0, 1]); // all-hosts (general query)
        ip[20..24].copy_from_slice(&[0x94, 0x04, 0x00, 0x00]); // IP Router Alert option
        ip[24] = 0x11; // IGMP Membership Query type

        let frame = eth_frame(&[0x08, 0x00], &[], &ip);
        let eth = EthernetPacket::new(&frame).unwrap();
        let proto = detect_protocol(&eth);
        assert!(
            matches!(
                proto,
                Some(AvProtocol::Igmp { igmp_type: crate::protocols::IgmpType::Query { .. }, .. })
            ),
            "IGMPv3 query with Router Alert (IHL=6) must be detected as a Query"
        );
        if let Some(AvProtocol::Igmp { group, src, .. }) = proto {
            assert_eq!(group, Ipv4Addr::new(224, 0, 0, 1));
            assert_eq!(src, Ipv4Addr::new(10, 244, 70, 241));
        }
    }

    #[test]
    fn igmpv3_membership_report_group_records_extracted() {
        // IGMPv3 Membership Report (type 0x22) sent to 224.0.0.22.
        // Contains two Group Records: one for 239.69.0.1 (AES67) and one for
        // 239.255.1.2 (Dante multicast). Verifies that parse_igmpv3_report correctly
        // walks the Group Record list and returns both groups.
        //
        // IGMP payload layout (RFC 3376 §4.2):
        //   [0]    type = 0x22
        //   [1]    reserved
        //   [2-3]  checksum (zeroed for test)
        //   [4-5]  reserved
        //   [6-7]  num_group_records = 2
        //   --- Record 1 ---
        //   [8]    record_type = 2 (MODE_IS_EXCLUDE — host IS joined)
        //   [9]    aux_data_len = 0
        //   [10-11] num_sources = 0
        //   [12-15] multicast_address = 239.69.0.1
        //   --- Record 2 ---
        //   [16]   record_type = 2
        //   [17]   aux_data_len = 0
        //   [18-19] num_sources = 0
        //   [20-23] multicast_address = 239.255.1.2
        let mut igmp_payload = vec![0u8; 24];
        igmp_payload[0] = 0x22; // IGMPv3 Membership Report
        igmp_payload[6] = 0x00; igmp_payload[7] = 0x02; // 2 group records
        // Record 1
        igmp_payload[8]  = 2; // MODE_IS_EXCLUDE
        igmp_payload[9]  = 0; // aux_data_len
        igmp_payload[10] = 0; igmp_payload[11] = 0; // 0 sources
        igmp_payload[12..16].copy_from_slice(&[239, 69, 0, 1]);
        // Record 2
        igmp_payload[16] = 2;
        igmp_payload[17] = 0;
        igmp_payload[18] = 0; igmp_payload[19] = 0;
        igmp_payload[20..24].copy_from_slice(&[239, 255, 1, 2]);

        // Build a minimal IPv4 frame (IHL=5, no options) with IGMP as the payload.
        let mut ip = vec![0u8; 20 + igmp_payload.len()];
        ip[0] = 0x45; // v4, IHL=5
        let total = (20 + igmp_payload.len()) as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip[8] = 1;    // TTL=1
        ip[9] = 0x02; // proto IGMP
        ip[12..16].copy_from_slice(&[10, 0, 0, 1]);       // src
        ip[16..20].copy_from_slice(&[224, 0, 0, 22]);     // dst (all IGMPv3 routers)
        ip[20..].copy_from_slice(&igmp_payload);

        let frame = eth_frame(&[0x08, 0x00], &[], &ip);
        let eth   = EthernetPacket::new(&frame).unwrap();
        let proto = detect_protocol(&eth);

        if let Some(AvProtocol::Igmp {
            igmp_type: crate::protocols::IgmpType::MembershipReportV3 { groups }, ..
        }) = proto {
            assert_eq!(groups.len(), 2, "expected 2 group records");
            assert!(groups.contains(&Ipv4Addr::new(239, 69,  0, 1)), "AES67 group missing");
            assert!(groups.contains(&Ipv4Addr::new(239, 255, 1, 2)), "Dante group missing");
        } else {
            panic!("expected MembershipReportV3, got {:?}", proto);
        }
    }

    // ── mDNS QR-bit guard ────────────────────────────────────────────────────

    /// Build a minimal Ethernet+IPv4+UDP frame carrying an mDNS payload.
    /// `qr` sets bit 7 of flags byte (payload[2]): true = response, false = query.
    fn mdns_frame(src_ip: [u8; 4], qr: bool, mdns_body: &[u8]) -> Vec<u8> {
        let udp_len = (8 + mdns_body.len()) as u16;
        let ip_total = (20 + udp_len) as u16;
        let mut ip = vec![0u8; 20 + 8 + mdns_body.len()];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&ip_total.to_be_bytes());
        ip[8] = 255; // TTL
        ip[9] = 0x11; // UDP
        ip[12..16].copy_from_slice(&src_ip);
        ip[16..20].copy_from_slice(&[224, 0, 0, 251]); // mDNS multicast
        ip[20..22].copy_from_slice(&5353u16.to_be_bytes()); // src port
        ip[22..24].copy_from_slice(&5353u16.to_be_bytes()); // dst port
        ip[24..26].copy_from_slice(&udp_len.to_be_bytes());
        let dns_start = 28usize;
        ip[dns_start..dns_start + mdns_body.len()].copy_from_slice(mdns_body);
        if qr { ip[dns_start + 2] |= 0x80; } // set QR bit = response
        eth_frame(&[0x08, 0x00], &[], &ip)
    }

    fn netaudio_response_payload() -> Vec<u8> {
        // Minimal mDNS DNS payload: 12-byte header + PTR record containing
        // \x09StageBox\x09_netaudio (instance + service label).
        let instance: &[u8] = b"StageBox";
        let mut p = vec![
            0x00, 0x00, // transaction id
            0x84, 0x00, // flags: QR=1 (response), Authoritative
            0x00, 0x00, // QDCOUNT = 0
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];
        p.push(instance.len() as u8);
        p.extend_from_slice(instance);
        p.extend_from_slice(b"\x09_netaudio");
        p
    }

    #[test]
    fn mdns_response_from_dante_device_classified_as_discovery() {
        let dante_ip = [192, 168, 1, 50];
        let body = netaudio_response_payload();
        let frame = mdns_frame(dante_ip, true, &body);
        let eth = EthernetPacket::new(&frame).unwrap();
        assert!(
            matches!(
                detect_protocol(&eth),
                Some(AvProtocol::Dante { kind: DanteKind::Discovery { .. }, .. })
            ),
            "mDNS response with _netaudio must be Dante Discovery"
        );
    }

    #[test]
    fn mdns_query_for_dante_service_suppressed_by_qr_bit() {
        // The local machine (192.168.1.108) browses for _netaudio. The outgoing
        // mDNS query contains the same _netaudio label bytes as a response, but
        // QR = 0. Without the QR-bit guard, src_ip (the local machine) would be
        // registered as a Dante device. With the guard this must return None.
        let local_ip = [192, 168, 1, 108];
        let mut body = netaudio_response_payload();
        body[2] &= 0x7F; // clear QR bit → query
        let frame = mdns_frame(local_ip, false, &body);
        let eth = EthernetPacket::new(&frame).unwrap();
        assert!(
            detect_protocol(&eth).is_none(),
            "mDNS query (QR=0) must not be classified as Dante Discovery"
        );
    }

    #[test]
    fn mdns_query_for_ndi_service_suppressed_by_qr_bit() {
        // Same false-positive path for NDI: a local browse query for _ndi must
        // not register the local machine as an NDI source.
        let local_ip = [192, 168, 1, 108];
        // Minimal body: header + instance + \x04_ndi
        let mut p = vec![
            0x00, 0x00, // transaction id
            0x00, 0x00, // flags: QR=0 (query)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, 0x00, 0x00,
        ];
        let instance: &[u8] = b"MyNDI";
        p.push(instance.len() as u8);
        p.extend_from_slice(instance);
        p.extend_from_slice(b"\x04_ndi");
        let frame = mdns_frame(local_ip, false, &p);
        let eth = EthernetPacket::new(&frame).unwrap();
        assert!(
            detect_protocol(&eth).is_none(),
            "mDNS query (QR=0) must not be classified as NDI Discovery"
        );
    }
}
