// AVStreamLens — src/parser/avb.rs
// AVTP stream-id extraction + MSRP/MVRP PDU parsers (IEEE 802.1Qat / 802.1Q).

use crate::protocols::{MsrpDeclType, MsrpDeclaration};

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
                // TalkerFailed FirstValue = 25-byte TalkerAdvertise body + FailureInformation
                // (FailureBridgeId 8 bytes at 25-32, FailureCode at 33).
                let failure    = first_value[33];
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

/// Parse an MVRP PDU (IEEE 802.1Q clause 10, EtherType 0x88F5).
/// Returns the list of registered VLAN IDs (deduped).
///
/// MVRP is an MRP application. An MRPDU is `ProtocolVersion(1)` followed by
/// Messages and a two-octet EndMark. Each Message is
/// `AttributeType(1) AttributeLength(1)` then a run of VectorAttributes ended by a
/// two-octet EndMark. **MVRP has no AttributeListLength field** — that is specific
/// to MSRP; treating the VectorHeader as a byte count (the previous bug) misreads
/// the VLAN ID and mis-advances the walker. Each VectorAttribute is
/// `VectorHeader(2)` = `LeaveAllEvent(3 bits) | NumberOfValues(13 bits)`, then
/// `FirstValue(AttributeLength)`, then `ceil(NumberOfValues/3)` ThreePackedEvents
/// octets. VLAN attribute values are consecutive, so a vector of N values declares
/// FirstValue, FirstValue+1, …, FirstValue+N-1.
pub fn parse_mvrp(payload: &[u8]) -> Vec<u16> {
    let mut vlans: Vec<u16> = Vec::new();
    if payload.is_empty() || payload[0] != 0x00 { return vlans; } // ProtocolVersion

    let mut pos = 1usize;
    while pos < payload.len() {
        let attr_type = payload[pos];
        if attr_type == 0x00 { break; }  // first octet of the MRPDU EndMark
        pos += 1;
        if pos >= payload.len() { break; }
        let attr_len = payload[pos] as usize;
        pos += 1;
        if attr_len == 0 { break; }      // malformed

        // VectorAttribute list, terminated by a two-octet EndMark (0x0000).
        loop {
            if pos + 2 > payload.len() { return vlans; }
            let vector_header = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
            pos += 2;
            if vector_header == 0 { break; }  // EndMark for this attribute's vectors
            let num_values = (vector_header & 0x1FFF) as usize;
            if num_values == 0 { continue; }  // LeaveAll-only: no FirstValue, no vector

            if pos + attr_len > payload.len() { return vlans; }
            if attr_type == 1 && attr_len == 2 {
                let base = u16::from_be_bytes([payload[pos], payload[pos + 1]]) & 0x0FFF;
                for i in 0..num_values {
                    let vid = base.wrapping_add(i as u16) & 0x0FFF;
                    if vid > 0 && !vlans.contains(&vid) { vlans.push(vid); }
                }
            }
            pos += attr_len;                 // consume FirstValue

            let packed = num_values.div_ceil(3);
            if pos + packed > payload.len() { return vlans; }
            pos += packed;                   // consume ThreePackedEvents
        }
    }
    vlans
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(matches!(d.decl_type, MsrpDeclType::TalkerAdvertise));
        assert_eq!(d.stream_id,           [0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x01]);
        assert_eq!(d.vlan_id,             Some(100));
        assert_eq!(d.max_frame_size,      Some(1500));
        assert_eq!(d.max_interval_frames, Some(8));
        assert_eq!(d.priority,            Some(3));
    }

    fn msrp_talker_failed_pdu() -> Vec<u8> {
        // FirstValue is 34 bytes: 25-byte TalkerAdvertise body + FailureBridgeId(8) + FailureCode(1).
        let mut p = vec![
            0x00,       // MSRP version
            0x02,       // attr_type = TalkerFailed
            0x22,       // attr_len = 34
            0x00, 0x24, // list_len = 36 (= 2 VectorHeader + 34 FirstValue)
            0x00, 0x01, // VectorHeader (NumberOfValues=1)
        ];
        p.extend_from_slice(&[0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x01]); // stream_id (0-7)
        p.extend_from_slice(&[0x01,0x02,0x03,0x04,0x05,0x06]);            // dest_mac (8-13)
        p.extend_from_slice(&[0x00, 0x64]);  // vlan_id = 100 (14-15)
        p.extend_from_slice(&[0x05, 0xDC]);  // max_frame_size (16-17)
        p.extend_from_slice(&[0x00, 0x08]);  // max_interval_frames (18-19)
        p.push(0x60);                         // priority byte (20)
        p.extend_from_slice(&[0x00; 4]);     // accumulated latency (21-24)
        p.extend_from_slice(&[0x00; 8]);     // FailureBridgeId (25-32)
        p.push(0x01);                         // FailureCode = 1 (insufficient bandwidth) (33)
        p
    }

    #[test]
    fn msrp_talker_failed_decodes_failure_code() {
        let decls = parse_msrp(&msrp_talker_failed_pdu());
        assert_eq!(decls.len(), 1);
        let d = &decls[0];
        assert!(matches!(d.decl_type, MsrpDeclType::TalkerFailed));
        assert_eq!(d.stream_id,    [0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x01]);
        assert_eq!(d.failure_code, Some(1), "FailureCode is at FirstValue offset 33");
    }

    #[test]
    fn msrp_failure_reason_maps_known_and_unknown_codes() {
        use crate::protocols::msrp_failure_reason;
        // Code 8 was observed on a live AVB talker (egress port not AVB-capable) —
        // the old 1/2/3-only table rendered it as a useless "(failure)".
        assert_eq!(msrp_failure_reason(8), "egress port is not AVB-capable");
        assert_eq!(msrp_failure_reason(1), "insufficient bandwidth");
        assert_eq!(msrp_failure_reason(6), "stream pre-empted by a higher-rank stream");
        assert_eq!(msrp_failure_reason(200), "unknown failure");
    }

    #[test]
    fn msrp_empty_payload_returns_empty() {
        assert!(parse_msrp(&[]).is_empty());
    }

    #[test]
    fn msrp_wrong_version_returns_empty() {
        assert!(parse_msrp(&[0x01, 0x00]).is_empty());
    }

    #[test]
    fn mvrp_single_vlan_id_parsed() {
        // Spec-correct MVRP MRPDU (IEEE 802.1Q clause 10) — NO AttributeListLength
        // field (that is an MSRP-only field). Layout:
        //   ProtocolVersion(1) AttributeType(1) AttributeLength(1)
        //   VectorHeader(2) FirstValue(2) ThreePackedEvents(ceil(N/3)) EndMark(2)
        let p = [
            0x00,       // ProtocolVersion
            0x01,       // AttributeType = VID
            0x02,       // AttributeLength = 2
            0x00, 0x01, // VectorHeader: LeaveAll=0, NumberOfValues=1
            0x00, 0x64, // FirstValue = VLAN 100
            0x00,       // ThreePackedEvents (1 value → 1 octet; content ignored)
            0x00, 0x00, // EndMark
        ];
        assert_eq!(parse_mvrp(&p), vec![100]);
    }

    #[test]
    fn mvrp_multi_value_vector_yields_consecutive_vids() {
        // A VectorAttribute with NumberOfValues=3 declares VLANs FirstValue,
        // FirstValue+1, FirstValue+2 (VLAN attribute values are consecutive).
        let p = [
            0x00,       // ProtocolVersion
            0x01,       // AttributeType = VID
            0x02,       // AttributeLength = 2
            0x00, 0x03, // VectorHeader: NumberOfValues=3
            0x00, 0x64, // FirstValue = VLAN 100
            0x00,       // ThreePackedEvents (ceil(3/3)=1 octet)
            0x00, 0x00, // EndMark
        ];
        assert_eq!(parse_mvrp(&p), vec![100, 101, 102]);
    }

    #[test]
    fn mvrp_leave_all_only_vector_has_no_vid() {
        // A LeaveAll-only VectorAttribute (NumberOfValues=0) carries no FirstValue
        // and no packed-events octets — it must not fabricate a VLAN ID.
        let p = [
            0x00,       // ProtocolVersion
            0x01,       // AttributeType = VID
            0x02,       // AttributeLength = 2
            0x20, 0x00, // VectorHeader: LeaveAll=1, NumberOfValues=0
            0x00, 0x00, // EndMark
        ];
        assert!(parse_mvrp(&p).is_empty());
    }

    #[test]
    fn mvrp_empty_returns_empty() {
        assert!(parse_mvrp(&[]).is_empty());
    }
}
