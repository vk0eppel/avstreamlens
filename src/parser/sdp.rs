// AVStreamLens — src/parser/sdp.rs
// SAP envelope (RFC 2974) + SDP body (RFC 4566) + ts-refclk normalisation.

use crate::protocols::{SdpMedia, SdpSession, DEFAULT_CLOCK_HZ};

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

    // T bit (byte 0, bit 2): 0 = session announcement, 1 = session deletion.
    // A deletion carries the SDP of a session that is going away — parsing it as an
    // announcement would re-cache / re-apply that session's media, so ignore it.
    let is_deletion = (payload[0] >> 2) & 0b1 == 1;
    if is_deletion { return None; }

    let addr_type = (payload[0] >> 4) & 0b1;    // 0=IPv4, 1=IPv6
    let auth_len  = payload[1] as usize;
    let addr_len  = if addr_type == 0 { 4 } else { 16 };
    let header    = 4 + addr_len + auth_len * 4;

    if payload.len() <= header { return None; }

    let mut body = &payload[header..];

    // Optional: MIME type "application/sdp\0" before SDP body
    if body.starts_with(b"application/sdp")
        && let Some(pos) = body.iter().position(|&b| b == 0)
    {
        body = &body[pos + 1..];
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

            'i' if cur_media.is_none() => { session.info = value.to_string(); }

            'm' => {
                if let Some(m) = cur_media.take() { session.media.push(m); }
                // m=<type> <port> <proto> <fmt...>
                let parts: Vec<&str> = value.split_whitespace().collect();
                if parts.len() >= 4 {
                    let payload_types = parts[3..].iter()
                        .filter_map(|s| s.parse::<u8>().ok())
                        .collect();
                    cur_media = Some(SdpMedia {
                        media_type: parts[0].to_string(),
                        port: parts[1].parse().unwrap_or(0),
                        payload_types,
                        ..SdpMedia::default()
                    });
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
                        if enc.len() >= 2 { media.clock_hz = enc[1].parse().unwrap_or(DEFAULT_CLOCK_HZ); }
                        if enc.len() >= 3 { media.channels = enc[2].parse().unwrap_or(1); }
                    }

                } else if let Some(rest) = value.strip_prefix("ptime:") {
                    media.ptime_ms = rest.trim().parse().unwrap_or(1.0);

                } else if let Some(rest) = value.strip_prefix("framecount:") {
                    // a=framecount:<n>  (ST 2110) → converted to ptime
                    if let Ok(fc) = rest.trim().parse::<u32>()
                        && media.clock_hz > 0.0
                    {
                        media.ptime_ms = fc as f64 / media.clock_hz * 1000.0;
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

/// Parse a `ts-refclk` SDP attribute value into `(normalized_grandmaster_id, domain)`.
///
/// Handles:
/// - `ptp=IEEE1588-2008:<eui64>:<domain>` — PTPv2, 8-byte EUI-64 (dashes or colons)
/// - `ptp=IEEE1588-2002:<uuid>:<domain>`  — PTPv1, 6-byte MAC
///
/// Returns `None` for non-PTP types (`localmac=...`, etc.).
/// The returned ID uses lowercase colon-separated bytes, matching `PtpStats::last_grandmaster`.
pub fn parse_ts_refclk(s: &str) -> Option<(String, u8)> {
    let rest = s.strip_prefix("ptp=IEEE1588-2008:")
        .or_else(|| s.strip_prefix("ptp=IEEE1588-2002:"))?;

    // The last colon-separated token is the domain number; everything before is the clock ID.
    let last_colon = rest.rfind(':')?;
    let id_part    = &rest[..last_colon];
    let domain_str = &rest[last_colon + 1..];
    let domain: u8 = domain_str.trim().parse().ok()?;

    // Normalize: replace '-' with ':', lowercase
    let normalized = id_part.replace('-', ":").to_lowercase();

    Some((normalized, domain))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // ── SAP envelope: announcement vs deletion (T bit) ───────────────────────

    fn sap_packet(t_bit: bool, sdp: &str) -> Vec<u8> {
        // Byte 0: V=1 (bits 7-5), T (bit 2) = 1 for a session deletion.
        let flags = 0x20 | if t_bit { 0x04 } else { 0x00 };
        let mut pkt = vec![flags, 0x00, 0x00, 0x00, 1, 2, 3, 4]; // flags, auth_len=0, hash, src IPv4
        pkt.extend_from_slice(sdp.as_bytes());
        pkt
    }

    #[test]
    fn sap_deletion_message_returns_none() {
        // A SAP packet with the T bit set is a session *deletion*, not an
        // announcement. Parsing it as an announcement would re-cache / re-apply the
        // SDP for a session that is going away, so it must return None.
        let sdp = "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\ns=X\r\nm=audio 5004 RTP/AVP 96\r\n";
        assert!(parse_sap_packet(&sap_packet(true, sdp)).is_none(),
            "SAP deletion (T=1) must not parse as an announcement");
    }

    #[test]
    fn sap_announcement_message_parses() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\ns=X\r\nm=audio 5004 RTP/AVP 96\r\n";
        let s = parse_sap_packet(&sap_packet(false, sdp)).expect("announcement should parse");
        assert_eq!(s.media.len(), 1);
        assert_eq!(s.media[0].port, 5004);
    }
}
