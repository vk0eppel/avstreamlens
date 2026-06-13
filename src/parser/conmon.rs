// AVStreamLens — src/parser/conmon.rs
// Dante ConMon (control & monitoring) frame parser.
//
// ConMon rides UDP multicast on 224.0.0.230–233, ports 8700–8708 — inside the
// link-local 224.0.0.0/24 block that IGMP snooping never prunes, so these
// frames reach every switch port with no join and no SPAN. The metering
// channel (port 8705) runs at ~33 packets/s per device, making ConMon a
// continuous liveness signal for every Dante device on the segment — even
// when all audio flows are unicast and invisible from a non-mirror port.
//
// Framing observed on-wire (2026-06-12, Audinate Brooklyn-class device +
// Yamaha console, ports 8705 and 8708 — see TODO.md "ConMon content"):
//   [0-1]    flags/version  (0xffff seen on 8705, 0xfffe on 8708)
//   [2-3]    u16 BE payload length — matches the UDP payload exactly
//   [4-5]    u16 BE sequence number, monotonic per device
//   [8-13]   sender MAC address (matches the Ethernet source)
//   [16-23]  ASCII "Audinate" — protocol signature
//
// Metering frames (port 8705) additionally carry an "MBC" tag at [0x2a..0x2d],
// the channel count at [0x44], and one meter byte per channel from [0x47].
// The meter byte scale/encoding is unverified — only the count is extracted.

/// Fields extracted from a validated ConMon frame.
#[derive(Debug, Clone, PartialEq)]
pub struct ConmonInfo {
    pub device_mac: [u8; 6],
    /// Channel count from a metering ("MBC") frame; None for other message types.
    pub channels: Option<u8>,
}

/// Parse a ConMon payload. Returns None unless the "Audinate" signature is
/// present and the declared length field is consistent with the payload
/// (tolerating trailing Ethernet padding).
pub fn parse_conmon(payload: &[u8]) -> Option<ConmonInfo> {
    if payload.len() < 24 {
        return None;
    }
    if &payload[16..24] != b"Audinate" {
        return None;
    }
    let declared_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if declared_len < 24 || declared_len > payload.len() {
        return None;
    }

    let mut device_mac = [0u8; 6];
    device_mac.copy_from_slice(&payload[8..14]);

    // Metering frame: "MBC" tag, channel count, then one meter byte per channel.
    // The bounds check ties the count to the declared frame size so a stray
    // "MBC" in another message type can't yield a garbage channel count.
    //
    // Audinate Brooklyn-class devices repeat their own sender MAC at [0x30..0x36]
    // in the MBC block. Yamaha-proprietary devices (DSP cards, RX-HY1) put a
    // *different* sub-device MAC there — their MBC layout differs and [0x44] is
    // not the channel count. Suppress rather than display a wrong value.
    let mbc_mac_matches = payload.get(0x30..0x36)
        .is_some_and(|m| m == device_mac);
    let channels = (payload.get(0x2a..0x2d) == Some(&b"MBC"[..]) && mbc_mac_matches)
        .then(|| payload.get(0x44).copied())
        .flatten()
        .filter(|&c| c > 0 && 0x47 + c as usize <= declared_len);

    Some(ConmonInfo {
        device_mac,
        channels,
    })
}

// ═════════════════════════════════════════════════════════════════
// TESTS
// ═════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact 104-byte ConMon metering payload captured on-wire (2026-06-12)
    /// from an Audinate Brooklyn-class device, 169.254.81.11 → 224.0.0.232:8705.
    fn metering_frame() -> Vec<u8> {
        vec![
            0xff, 0xff, 0x00, 0x68, 0xbf, 0xa4, 0x00, 0x00, 0x00, 0x1d, 0xc1, 0x19, 0x86, 0x2a,
            0x00, 0x00, 0x41, 0x75, 0x64, 0x69, 0x6e, 0x61, 0x74, 0x65, 0x07, 0x2e, 0x10, 0x02,
            0x00, 0x00, 0x00, 0x00, 0xbf, 0xa4, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x3f, 0xc0,
            0x4d, 0x42, 0x43, 0x01, 0x00, 0x2a, 0x00, 0x1d, 0xc1, 0x19, 0x86, 0x2a, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x2a, 0x13, 0x07, 0x42, 0x00, 0x00, 0x20, 0x00,
            0x00, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21,
            0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x51, 0x55, 0x51, 0x20, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x59, 0x5e, 0xcd,
        ]
    }

    /// Minimal status-style frame (port 8708 shape): valid header, no "MBC" tag.
    fn status_frame(mac: [u8; 6]) -> Vec<u8> {
        let mut p = vec![0u8; 64];
        p[0] = 0xff;
        p[1] = 0xfe;
        p[2..4].copy_from_slice(&(64u16).to_be_bytes());
        p[4..6].copy_from_slice(&0xb986u16.to_be_bytes());
        p[8..14].copy_from_slice(&mac);
        p[16..24].copy_from_slice(b"Audinate");
        p
    }

    #[test]
    fn metering_frame_extracts_mac_and_channel_count() {
        let info = parse_conmon(&metering_frame()).expect("valid ConMon frame");
        assert_eq!(info.device_mac, [0x00, 0x1d, 0xc1, 0x19, 0x86, 0x2a]);
        assert_eq!(
            info.channels,
            Some(32),
            "channel count byte at 0x44 is 0x20"
        );
    }

    #[test]
    fn status_frame_without_mbc_has_no_channel_count() {
        let mac = [0xac, 0x44, 0xf2, 0x84, 0x1e, 0x60];
        let info = parse_conmon(&status_frame(mac)).expect("valid ConMon frame");
        assert_eq!(info.device_mac, mac);
        assert_eq!(info.channels, None);
    }

    #[test]
    fn wrong_signature_rejected() {
        let mut p = metering_frame();
        p[16..24].copy_from_slice(b"NotDante");
        assert!(parse_conmon(&p).is_none());
    }

    #[test]
    fn declared_length_longer_than_payload_rejected() {
        let mut p = metering_frame();
        p[2..4].copy_from_slice(&(200u16).to_be_bytes());
        assert!(parse_conmon(&p).is_none());
    }

    #[test]
    fn trailing_padding_tolerated() {
        // Ethernet minimum-frame padding can extend the captured payload past
        // the declared ConMon length — the frame must still parse.
        let mut p = metering_frame();
        p.extend_from_slice(&[0u8; 8]);
        let info = parse_conmon(&p).expect("padded frame must still parse");
        assert_eq!(info.channels, Some(32));
    }

    #[test]
    fn short_payload_rejected() {
        assert!(parse_conmon(&metering_frame()[..20]).is_none());
    }

    /// The exact 72-byte ConMon metering payload captured on-wire (2026-06-12)
    /// from a Yamaha DSP/RX-HY1 device, 169.254.149.65 → 224.0.0.232:8705.
    /// The MBC block contains a sub-device MAC (ac:44:f2:6e:04:ec) rather than
    /// the sender's own MAC (ac:44:f2:84:1e:60), indicating a Yamaha-proprietary
    /// layout where [0x44] is NOT the channel count.
    fn yamaha_dsp_mbc_frame() -> Vec<u8> {
        vec![
            0xff, 0xff, 0x00, 0x48, 0xc0, 0x8f, 0x00, 0x00, 0xac, 0x44, 0xf2, 0x84, 0x1e, 0x60,
            0x00, 0x00, 0x41, 0x75, 0x64, 0x69, 0x6e, 0x61, 0x74, 0x65, 0x07, 0x2e, 0x10, 0x02,
            0x00, 0x00, 0x00, 0x00, 0xc0, 0x8f, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x1f, 0xc0,
            0x4d, 0x42, 0x43, 0x01, 0x00, 0x0a, 0xac, 0x44, 0xf2, 0x6e, 0x04, 0xec, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x0a, 0x01, 0x07, 0x1f, 0x06, 0x00, 0x01, 0x00,
            0x00, 0xf0,
        ]
    }

    #[test]
    fn yamaha_dsp_mbc_sub_device_mac_suppresses_channel_count() {
        // MBC present but sub-device MAC ≠ sender MAC → channel count suppressed
        let info = parse_conmon(&yamaha_dsp_mbc_frame()).expect("valid ConMon frame");
        assert_eq!(info.device_mac, [0xac, 0x44, 0xf2, 0x84, 0x1e, 0x60]);
        assert_eq!(info.channels, None, "sub-device MAC mismatch must suppress channel count");
    }

    #[test]
    fn channel_count_exceeding_frame_bounds_suppressed() {
        // A corrupt count larger than the meter block must yield None, not garbage.
        let mut p = metering_frame();
        p[0x44] = 200;
        let info = parse_conmon(&p).expect("header still valid");
        assert_eq!(info.channels, None);
    }
}
