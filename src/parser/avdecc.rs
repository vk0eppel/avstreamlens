// AVStreamLens — src/parser/avdecc.rs
// AVDECC (IEEE 1722.1) ADP frame parser.
//
// ADP (AVDECC Discovery Protocol) frames are AVTP control PDUs:
//   EtherType 0x22F0, byte 0 = 0xFA (cd=1, subtype=0x7A)
//   Destination MAC 91:E0:F0:01:00:00 — globally registered, bridges MUST forward.
//
// This is the discovery mechanism that Milan Manager / Hive uses to enumerate
// all devices on the network without a SPAN port. Unlike gPTP (link-local, not
// forwarded), ADP announcements reach every switch port.

use crate::protocols::AvdeccAdp;

/// Parse an AVDECC ADP frame from the AVTP payload (l2_payload, starting at byte 0
/// of the AVTP header). Returns None if the payload is too short or the subtype
/// byte doesn't match ADP (0xFA).
///
/// Wire layout:
///   [0]     subtype with cd bit = 0xFA
///   [1]     sv(0) | version(0,0,0) | message_type(4 bits)
///   [2-3]   valid_time(5) | control_data_length(11) — big-endian
///   [4-11]  entity_id (EUI-64)
///   [12-19] entity_model_id (EUI-64)
///   [20-23] entity_capabilities (u32 big-endian)
///   [24-25] talker_stream_sources (u16)
///   [26-27] talker_capabilities (u16)
///   [28-29] listener_stream_sinks (u16)
///   [30-31] listener_capabilities (u16)
///   [32-35] controller_capabilities (deprecated, ignored)
///   [36-39] available_index (u32)
///   [40-47] gptp_grandmaster_id (EUI-64)
///   [48]    gptp_domain_number
pub fn parse_adp(payload: &[u8]) -> Option<AvdeccAdp> {
    if payload.len() < 49 || payload[0] != 0xFA {
        return None;
    }
    let message_type = payload[1] & 0x0F;
    // valid_time is the upper 5 bits of the big-endian u16 at bytes 2-3.
    let hdr_u16     = u16::from_be_bytes([payload[2], payload[3]]);
    let valid_time_raw = (hdr_u16 >> 11) & 0x1F;
    let valid_time_secs = valid_time_raw as u64 * 2;

    let entity_id: [u8; 8] = payload[4..12].try_into().ok()?;

    let entity_model_id: [u8; 8] = payload[12..20].try_into().ok()?;
    let entity_capabilities = u32::from_be_bytes(payload[20..24].try_into().ok()?);
    let talker_stream_sources = u16::from_be_bytes(payload[24..26].try_into().ok()?);
    let talker_capabilities   = u16::from_be_bytes(payload[26..28].try_into().ok()?);
    let listener_stream_sinks = u16::from_be_bytes(payload[28..30].try_into().ok()?);
    let listener_capabilities = u16::from_be_bytes(payload[30..32].try_into().ok()?);
    let available_index       = u32::from_be_bytes(payload[36..40].try_into().ok()?);
    let gptp_grandmaster_id: [u8; 8] = payload[40..48].try_into().ok()?;
    let gptp_domain_number = payload[48];

    Some(AvdeccAdp {
        message_type,
        entity_id,
        entity_model_id,
        entity_capabilities,
        talker_stream_sources,
        talker_capabilities,
        listener_stream_sinks,
        listener_capabilities,
        gptp_grandmaster_id,
        gptp_domain_number,
        valid_time_secs,
        available_index,
    })
}

/// Format an EUI-64 (8 bytes) as colon-separated lowercase hex.
pub fn fmt_eui64(b: &[u8; 8]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7])
}

/// Summary of what media types an entity can source or sink, derived from the
/// talker/listener capability bitmask (AUDIO=0x0200, VIDEO=0x0400).
pub fn media_type_summary(caps: u16) -> &'static str {
    match (caps & 0x0200 != 0, caps & 0x0400 != 0) {
        (true,  true)  => "audio+video",
        (true,  false) => "audio",
        (false, true)  => "video",
        (false, false) => "other",
    }
}

/// SR class flags from entity_capabilities (CLASS_A=bit8=0x100, CLASS_B=bit9=0x200).
pub fn sr_class_str(entity_caps: u32) -> &'static str {
    match (entity_caps & 0x100 != 0, entity_caps & 0x200 != 0) {
        (true,  true)  => "Class A+B",
        (true,  false) => "Class A",
        (false, true)  => "Class B",
        (false, false) => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adp_payload() -> Vec<u8> {
        // Minimal well-formed ADP payload (ENTITY_AVAILABLE, 49 bytes).
        // Matches the IEEE 1722.1 wire layout described above.
        let mut p = vec![0u8; 69];
        p[0]  = 0xFA;             // subtype 0x7A with cd=1
        p[1]  = 0x00;             // sv=0, version=0, message_type=0 (ENTITY_AVAILABLE)
        // valid_time=5 (→10s), control_data_length=56 → u16 = (5<<11)|56 = 0x2838
        p[2]  = 0x28; p[3] = 0x38;
        // entity_id
        p[4..12].copy_from_slice(&[0x48, 0x0B, 0xB2, 0xFF, 0xFE, 0xD0, 0x04, 0xEA]);
        // entity_model_id
        p[12..20].copy_from_slice(&[0x48, 0x0B, 0xB2, 0xFF, 0xFE, 0x00, 0x00, 0x01]);
        // entity_capabilities: AEM_SUPPORTED(bit3) + CLASS_A(bit8) = 0x00000108
        p[20] = 0x00; p[21] = 0x00; p[22] = 0x01; p[23] = 0x08;
        // talker_stream_sources = 1
        p[24] = 0x00; p[25] = 0x01;
        // talker_capabilities: IMPLEMENTED(0x01) | AUDIO_SOURCE(0x200) = 0x0201
        p[26] = 0x02; p[27] = 0x01;
        // listener_stream_sinks = 0
        p[28] = 0x00; p[29] = 0x00;
        // listener_capabilities: 0
        p[30] = 0x00; p[31] = 0x00;
        // available_index = 3
        p[36] = 0x00; p[37] = 0x00; p[38] = 0x00; p[39] = 0x03;
        // gptp_grandmaster_id
        p[40..48].copy_from_slice(&[0x28, 0x6F, 0x7F, 0xFF, 0xFE, 0x11, 0x22, 0x33]);
        // gptp_domain_number = 0
        p[48] = 0x00;
        p
    }

    #[test]
    fn adp_entity_available_parsed() {
        let p = adp_payload();
        let adp = parse_adp(&p).expect("should parse");
        assert_eq!(adp.message_type, 0); // ENTITY_AVAILABLE
        assert_eq!(adp.entity_id, [0x48, 0x0B, 0xB2, 0xFF, 0xFE, 0xD0, 0x04, 0xEA]);
        assert_eq!(adp.entity_model_id, [0x48, 0x0B, 0xB2, 0xFF, 0xFE, 0x00, 0x00, 0x01]);
        assert_eq!(adp.entity_capabilities, 0x00000108);
        assert_eq!(adp.talker_stream_sources, 1);
        assert_eq!(adp.talker_capabilities, 0x0201);
        assert_eq!(adp.listener_stream_sinks, 0);
        assert_eq!(adp.available_index, 3);
        assert_eq!(adp.gptp_grandmaster_id, [0x28, 0x6F, 0x7F, 0xFF, 0xFE, 0x11, 0x22, 0x33]);
        assert_eq!(adp.gptp_domain_number, 0);
        assert_eq!(adp.valid_time_secs, 10); // valid_time=5 → 10s
    }

    #[test]
    fn adp_wrong_subtype_returns_none() {
        let mut p = adp_payload();
        p[0] = 0x00; // IEC 61883, not ADP
        assert!(parse_adp(&p).is_none());
    }

    #[test]
    fn adp_too_short_returns_none() {
        assert!(parse_adp(&[0xFA; 48]).is_none()); // 48 bytes, need 49
    }

    #[test]
    fn adp_entity_departing_message_type() {
        let mut p = adp_payload();
        p[1] = 0x01; // message_type=1 (ENTITY_DEPARTING)
        let adp = parse_adp(&p).unwrap();
        assert_eq!(adp.message_type, 1);
    }

    #[test]
    fn sr_class_str_class_a_only() {
        assert_eq!(sr_class_str(0x00000108), "Class A"); // AEM + CLASS_A
    }

    #[test]
    fn media_type_audio_only() {
        assert_eq!(media_type_summary(0x0201), "audio"); // IMPLEMENTED + AUDIO_SOURCE
    }
}
