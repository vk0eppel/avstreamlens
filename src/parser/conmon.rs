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
//   [8-15]   sender identity — 8 bytes; see below for the two wire formats seen
//   [16-23]  ASCII "Audinate" — protocol signature
//   [24-25]  sub-header (byte 24 = 0x07 on metering, 0x00 on status; byte 25 varies)
//   [26-27]  u16 BE message class. Observed 0x1002 = metering (8705), 0x0001 =
//            status (8702/8708) — stable within a message type, differs across
//            types. Confirmed from a live 8705+8702+8708 capture (2026-06-15),
//            cross-referenced against the Yamaha DM7 naio-dante `conmon_cmm`
//            binary's `size=0x%04x class=0x%04x` log format. Gates the metering
//            channel-count path so a stray "MBC" in a status frame can't yield a
//            bogus count.
//
// Sender identity at [8-15] has two observed encodings, and which one a device
// uses is per-firmware, not per-vendor — a live 14-device capture (2026-07-04)
// showed both encodings from devices sharing the same Audinate OUI (00:1d:c1).
// Some firmware (e.g. an Audinate Brooklyn-class Rio3224-D2) writes a plain
// 6-byte MAC in [8-13] with [14-15] unused. Other firmware (confirmed on both
// a Yamaha Rio1608-D3 and an Audinate-OUI device in the same capture) instead
// writes a *modified EUI-64* — the standard `OUI + FF:FE + NIC-bytes` 8-byte
// expansion of a MAC, the same convention used for 802.1AS/gPTP clock
// identities elsewhere in this codebase. Truncating that to 6 bytes (as the
// parser used to) keeps only `OUI + FF:FE + <high NIC byte>`, which collides
// across two devices sharing an OUI and high NIC byte — e.g. `f4:d5:80:22:24:82`
// and `f4:d5:80:22:34:42` both truncate to `f4:d5:80:ff:fe:22`, producing a
// false "Dante redundancy bridged" alert (`check_conmon_bridge` in capture.rs).
// Detecting the `FF:FE` filler at bytes [11-12] and stripping it recovers the
// real MAC in both encodings.
//
// Metering frames (port 8705) additionally carry an "MBC" tag at [0x2a..0x2d],
// the channel count at [0x44], and one meter byte per channel from [0x47].
// The meter byte scale/encoding is unverified — only the count is extracted.

/// ConMon message class at payload[26..28] (BE). Observed values from a live
/// capture: metering frames (port 8705) carry `0x1002`, status frames (8702/8708)
/// carry `0x0001`. Not an exhaustive enum — only the classes seen on-wire.
pub const CONMON_CLASS_METERING: u16 = 0x1002;

/// Fields extracted from a validated ConMon frame.
#[derive(Debug, Clone, PartialEq)]
pub struct ConmonInfo {
    pub device_mac: [u8; 6],
    /// ConMon message class (payload[26..28], BE) — see [`CONMON_CLASS_METERING`].
    pub message_class: u16,
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

    let message_class = payload
        .get(26..28)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .unwrap_or(0);

    let identity = &payload[8..16];
    let device_mac = if identity[3] == 0xff && identity[4] == 0xfe {
        // Modified EUI-64 (OUI + FF:FE + NIC bytes) — strip the filler to
        // recover the real burned-in MAC. See the file header for why this
        // matters: without it, devices sharing an OUI and high NIC byte
        // collide when truncated to 6 bytes.
        [identity[0], identity[1], identity[2], identity[5], identity[6], identity[7]]
    } else {
        [identity[0], identity[1], identity[2], identity[3], identity[4], identity[5]]
    };

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
    let channels = (message_class == CONMON_CLASS_METERING
        && payload.get(0x2a..0x2d) == Some(&b"MBC"[..])
        && mbc_mac_matches)
        .then(|| payload.get(0x44).copied())
        .flatten()
        .filter(|&c| c > 0 && 0x47 + c as usize <= declared_len);

    Some(ConmonInfo {
        device_mac,
        message_class,
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
        assert_eq!(info.message_class, CONMON_CLASS_METERING, "8705 metering class is 0x1002");
        assert_eq!(
            info.channels,
            Some(32),
            "channel count byte at 0x44 is 0x20"
        );
    }

    /// The exact 172-byte ConMon **status** payload captured on-wire (2026-06-15,
    /// `pcapdanteTHV`) from 169.254.142.19:8700 → 224.0.0.233:8708 — a different
    /// message family from metering. Message class is 0x0001 (not 0x1002); the
    /// body is a TLV chain (0x8001, 0x8002, … type tags), not an MBC meter block.
    fn status_frame_8708_real() -> Vec<u8> {
        vec![
            0xff, 0xfe, 0x00, 0xac, 0x24, 0x74, 0x00, 0x00, 0x00, 0x1d, 0xc1, 0xff, 0xfe, 0x80,
            0x13, 0x8d, 0x41, 0x75, 0x64, 0x69, 0x6e, 0x61, 0x74, 0x65, 0x00, 0x08, 0x00, 0x01,
            0x10, 0x00, 0x00, 0x00, 0x00, 0x10, 0x80, 0x01, 0x00, 0x04, 0x00, 0x04, 0x18, 0x9b,
            0x00, 0x00, 0x00, 0x00, 0x3f, 0x35, 0x00, 0x24, 0x80, 0x00, 0x00, 0x04, 0x00, 0x04,
            0x18, 0x9b, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00,
            0x03, 0xfc, 0x00, 0x00, 0x5a, 0x57, 0x00, 0x00, 0x00, 0x99, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x1c, 0x80, 0x02, 0x00, 0x04, 0x00, 0x10, 0x18, 0x9b, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0xfe, 0xfe, 0xfd, 0xfd,
            0x00, 0x20, 0x80, 0x03, 0x00, 0x04, 0x00, 0x14, 0x18, 0x9b, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0xbb, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x80, 0x04, 0x00, 0x04, 0x00, 0x10, 0x18, 0x9b,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]
    }

    #[test]
    fn status_frame_has_status_class_and_no_channel_count() {
        let info = parse_conmon(&status_frame_8708_real()).expect("valid ConMon status frame");
        assert_eq!(info.device_mac, [0x00, 0x1d, 0xc1, 0x80, 0x13, 0x8d]);
        assert_eq!(info.message_class, 0x0001, "8708 status class is 0x0001, not metering");
        assert_eq!(info.channels, None, "status frame carries no MBC meter block");
    }

    #[test]
    fn metering_class_gate_suppresses_channel_count_on_non_metering_frame() {
        // A status-class frame that nonetheless contains the bytes "MBC" + a
        // matching MAC at the metering offsets must NOT yield a channel count —
        // the message-class gate (0x1002) is what distinguishes metering.
        let mut p = metering_frame(); // has real MBC block + class 0x1002
        p[26] = 0x00;
        p[27] = 0x01; // rewrite class to status
        let info = parse_conmon(&p).expect("still a valid ConMon frame");
        assert_eq!(info.message_class, 0x0001);
        assert_eq!(info.channels, None, "non-metering class must gate out the MBC count");
    }

    #[test]
    fn status_frame_without_mbc_has_no_channel_count() {
        let mac = [0xac, 0x44, 0xf2, 0x84, 0x1e, 0x60];
        let info = parse_conmon(&status_frame(mac)).expect("valid ConMon frame");
        assert_eq!(info.device_mac, mac);
        assert_eq!(info.channels, None);
    }

    /// Minimal status-style frame carrying an 8-byte modified-EUI-64 identity
    /// (`OUI + FF:FE + NIC bytes`) at [8-15] instead of a plain 6-byte MAC.
    fn eui64_status_frame(identity: [u8; 8]) -> Vec<u8> {
        let mut p = vec![0u8; 64];
        p[0] = 0xff;
        p[1] = 0xfe;
        p[2..4].copy_from_slice(&(64u16).to_be_bytes());
        p[4..6].copy_from_slice(&0xb986u16.to_be_bytes());
        p[8..16].copy_from_slice(&identity);
        p[16..24].copy_from_slice(b"Audinate");
        p
    }

    #[test]
    fn eui64_identity_stripped_to_real_mac() {
        // f4:d5:80:22:24:82 expanded to modified EUI-64: f4:d5:80:ff:fe:22:24:82
        let info = parse_conmon(&eui64_status_frame([0xf4, 0xd5, 0x80, 0xff, 0xfe, 0x22, 0x24, 0x82]))
            .expect("valid ConMon frame");
        assert_eq!(info.device_mac, [0xf4, 0xd5, 0x80, 0x22, 0x24, 0x82]);
    }

    #[test]
    fn eui64_identity_disambiguates_devices_sharing_oui_and_high_nic_byte() {
        // Real bug report (2026-07-04): two Yamaha Rio1608-D3 devices whose
        // real MACs both truncate to the same 6-byte value under the old
        // (plain-MAC) parsing, causing a false "redundancy bridged" alert.
        let a = parse_conmon(&eui64_status_frame([0xf4, 0xd5, 0x80, 0xff, 0xfe, 0x22, 0x24, 0x82]))
            .expect("valid ConMon frame");
        let b = parse_conmon(&eui64_status_frame([0xf4, 0xd5, 0x80, 0xff, 0xfe, 0x22, 0x34, 0x42]))
            .expect("valid ConMon frame");
        assert_eq!(a.device_mac, [0xf4, 0xd5, 0x80, 0x22, 0x24, 0x82]);
        assert_eq!(b.device_mac, [0xf4, 0xd5, 0x80, 0x22, 0x34, 0x42]);
        assert_ne!(a.device_mac, b.device_mac);
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
