// AVStreamLens — src/parser/ptp.rs
// PTPv1 (IEEE 1588-2002) and PTPv2 (IEEE 1588-2008) message parser.
// Used for L2 gPTP (EtherType 0x88F7) and UDP PTP (ports 319/320).

use crate::protocols::{PtpInfo, PTP_VERSION_V1, PTP_VERSION_V2};

/// PTPv1 subdomain → domain number mapping.
/// IEEE 1588-2002 uses 16-byte ASCII subdomain names instead of a numeric domain.
/// The four well-known names map to 0–3; anything else maps to 0 (unknown = default).
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
/// Three wire encodings exist, distinguished by `hdr_shift`:
///
/// Separate-byte (hdr_shift=0, e.g. ptpd, byte[0]=0x01):
///   [0]     versionPTP = 0x01
///   [1]     versionNetwork = 0x01
///   [2-17]  subdomain (16 bytes)
///   [20-25] sourceUuid   [26-27] sourcePortId   [28-29] sequenceId
///   [30]    control      [31]    logMessagePeriod
///
/// Nibble-packed (hdr_shift=2, byte[0]=0x11, Audinate Dante):
///   [0]     (versionPTP=1)<<4 | versionNetwork=1  = 0x11
///   [1]     (messageType)<<4  | sourceCT          = 0x11 for Sync/UDP
///   [2-3]   flags
///   [4-19]  subdomain (16 bytes)
///   [22-27] sourceUuid   [28-29] sourcePortId   [30-31] sequenceId
///   [32]    control      [33]    logMessagePeriod
///
/// Standard IEEE 1588-2002 (hdr_shift=2, byte[0]=0x00):
///   [0-1]   versionPTP = 0x0001 (big-endian UInteger16)
///   [2-3]   versionNetwork = 0x0001
///   [4-19]  subdomain (16 bytes)
///   [20]    messageType   [21] sourceCommunicationTechnology
///   [22-27] sourceUuid   [28-29] sourcePortId   [30-31] sequenceId
///   [32]    control      [33]    reserved
///
/// Sync body (same absolute offsets for all encodings):
///   [34-43] originTimestamp   [44-47] epochNumber/utcOffset
///   [48] pad  [49] grandmasterCommunicationTechnology
///   [50-55] grandmasterClockUuid (6 bytes)
///   [56-57] grandmasterPortId   [58-59] grandmasterSequenceId
///   [60] pad  [61] grandmasterClockStratum
///   [62-65] grandmasterClockIdentifier (4 bytes ASCII, e.g. "ATOM", "GPS ")
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
            let raw_ident = &payload[62..66];
            let ident = if let Ok(s) = std::str::from_utf8(raw_ident) {
                let s = s.trim_end_matches('\0').trim();
                if !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                    s.to_string()
                } else {
                    String::new()
                }
            } else {
                String::new()
            };
            let class_str = match stratum {
                0 => "Preferred grandmaster".to_string(),
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
        message_name:                message_name.to_string(),
        port_id,
        sequence_id,
        log_sync_interval,
        log_min_pdelay_req_interval: 0,
        protocol_kind:               None,
        src_ip:                      None, // set by caller
    })
}

/// Parses a PTP message payload (PTPv1 or PTPv2 — auto-detected from header bytes).
pub fn parse_ptp(payload: &[u8]) -> Option<PtpInfo> {
    if payload.len() < 2 { return None; }

    // PTPv2 has one reliable wire marker: versionPTP = 2 in the low nibble of byte 1.
    // Anything that doesn't match is PTPv1 (we are already in a PTP context: port 319/320
    // or EtherType 0x88F7, so non-PTP traffic is not a concern here).
    if payload[1] & 0x0F != PTP_VERSION_V2 {
        // All known PTPv1 encodings share the same field layout:
        //   uuid at 22, control at 32, subdomain at 4.
        // The only variation is what bytes 0-3 contain (packed nibbles, big-endian
        // UInteger16, or single-byte), but the body offsets are identical in every case.
        let hdr_shift = 2;
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

    // IEEE 1588-2008 §13.3.2: sourcePortIdentity = clockIdentity(8) + portNumber(2).
    // clockIdentity occupies bytes 20–27; portNumber occupies bytes 28–29.
    let clock_id = if payload.len() >= 28 {
        Some(format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            payload[20], payload[21], payload[22], payload[23],
            payload[24], payload[25], payload[26], payload[27]))
    } else {
        None
    };

    let port_id = if payload.len() >= 30 {
        Some(u16::from_be_bytes([payload[28], payload[29]]))
    } else {
        None
    };

    let log_min_pdelay_req_interval = if payload.len() >= 55 {
        payload[54] as i8
    } else {
        0
    };

    // Grandmaster (Announce only): identity at bytes 53-60, quality at 48-49.
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
        message_name,
        port_id,
        sequence_id,
        log_sync_interval,
        log_min_pdelay_req_interval,
        protocol_kind:     None,  // set by caller
        src_ip:            None,  // set by caller
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // ── PTPv2 ────────────────────────────────────────────────────────────────

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

    // ── PTPv1 ────────────────────────────────────────────────────────────────

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
    fn ptpv1_single_byte_version_detected() {
        // payload[0]=0x01 (single-byte versionPTP): same hdr_shift=2 layout as all PTPv1
        // control at 32, subdomain at 4
        let mut p = vec![0u8; 40];
        p[0]  = 0x01;
        p[1]  = 0x01;
        p[32] = 0x00; // control = Sync
        let info = parse_ptp(&p).unwrap();
        assert_eq!(info.version,      1);
        assert_eq!(info.message_type, 0x00);
    }

    #[test]
    fn ptpv1_standard_ieee1588_extracts_grandmaster() {
        // Standard IEEE 1588-2002: versionPTP = 0x0001 big-endian → payload[0]=0x00
        // hdr_shift=2: subdomain at 4, sourceUuid at 22, control at 32
        // Body layout same as nibble-packed: gmUuid at 50-55, stratum at 61, ident at 62-65
        let mut p = vec![0u8; 66];
        p[0]  = 0x00; p[1]  = 0x01; // versionPTP = 1 (big-endian)
        p[2]  = 0x00; p[3]  = 0x01; // versionNetwork = 1
        p[4..9].copy_from_slice(b"_DFLT");  // subdomain → domain 0
        p[20] = 0x01;                // messageType = Sync
        p[21] = 0x01;                // sourceCommunicationTechnology = UDP_IP
        p[22..28].copy_from_slice(&[0x00, 0x1d, 0xc1, 0x8e, 0xb1, 0x75]); // sourceUuid
        p[32] = 0x00;                // control = Sync
        p[50..56].copy_from_slice(&[0x00, 0x1d, 0xc1, 0x8e, 0xb1, 0x75]); // grandmasterClockUuid
        p[61] = 1;                   // grandmasterClockStratum = Primary reference
        p[62..66].copy_from_slice(b"GPS ");
        let info = parse_ptp(&p).unwrap();
        assert_eq!(info.version, 1);
        assert_eq!(info.domain,  0);
        assert_eq!(info.clock_id.as_deref(),       Some("00:1d:c1:8e:b1:75"));
        assert_eq!(info.grandmaster_id.as_deref(), Some("00:1d:c1:8e:b1:75"));
        assert!(info.clock_quality.as_deref().unwrap_or("").contains("Primary reference"));
        assert!(info.clock_quality.as_deref().unwrap_or("").contains("GPS"));
    }

    #[test]
    fn ptpv1_alt1_subdomain_maps_to_domain_1() {
        let mut p = vec![0u8; 40];
        p[0] = 0x01;
        p[1] = 0x01;
        p[4..9].copy_from_slice(b"_ALT1"); // hdr_shift=2, sd=4
        p[32] = 0x01; // Delay_Req
        let info = parse_ptp(&p).unwrap();
        assert_eq!(info.domain, 1);
    }

    #[test]
    fn ptpv1_non_ascii_ident_suppressed() {
        // Dante's gmClockIdentifier bytes are non-ASCII proprietary values (confirmed
        // field data 2026-05-30). Any ident that isn't all printable ASCII is suppressed.
        let p = ptpv1_nibble_sync(
            [0x00, 0x00, 0x00, 0x01, 0x00, 0x1d],
            0,
            &[0xa9, 0xfe, 0x68, 0x56], // invalid UTF-8 (0xa9 is a continuation byte)
        );
        let q = parse_ptp(&p).unwrap().clock_quality.unwrap();
        assert!(!q.contains("????"), "should not contain ????, got: {}", q);
        assert!(!q.contains(':'), "should not contain hex bytes, got: {}", q);
        assert_eq!(q, "Preferred grandmaster", "non-ASCII ident should be suppressed, got: {}", q);
    }

    #[test]
    fn ptpv1_high_byte_ident_suppressed() {
        // Audinate-proprietary ident bytes (all non-null ≥ 0x80) should be silently
        // suppressed — they carry no meaning for an AV engineer (not GPS/ATOM/etc.).
        let p = ptpv1_nibble_sync(
            [0x00, 0x00, 0x00, 0x01, 0x00, 0x1d],
            0,
            &[0xcd, 0x9f, 0x00, 0x00], // real bytes seen on Dante network 2026-05-30
        );
        let q = parse_ptp(&p).unwrap().clock_quality.unwrap();
        assert_eq!(q, "Preferred grandmaster", "high-byte ident should be suppressed, got: {}", q);
    }

    #[test]
    fn ptpv1_null_ident_omitted_from_quality() {
        let p = ptpv1_nibble_sync(
            [0x00, 0x1d, 0xc1, 0x8e, 0xb1, 0x75],
            1,
            &[0x00, 0x00, 0x00, 0x00],
        );
        let q = parse_ptp(&p).unwrap().clock_quality.unwrap();
        assert_eq!(q, "Primary reference");
    }

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
