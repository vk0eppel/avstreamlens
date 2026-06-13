// AVStreamLens — src/parser/mdns.rs
// mDNS service-instance name extraction (Dante `_netaudio`, NDI `_ndi`).

/// Return true if `payload` contains the byte-encoded mDNS service string `service`.
pub fn mdns_contains(payload: &[u8], service: &[u8]) -> bool {
    payload.windows(service.len()).any(|w| w == service)
}

/// Extract an mDNS service-instance name — the label immediately preceding a given
/// DNS-encoded service label (e.g. `\x04_ndi` for NDI, `\x09_netaudio` for Dante).
/// Works for spontaneous announcements where all labels are inline (uncompressed).
fn extract_mdns_instance_name(payload: &[u8], service_needle: &[u8]) -> Option<String> {
    let pos = payload.windows(service_needle.len())
        .position(|w| w == service_needle)?;
    if pos == 0 { return None; }
    // Iterate from longest to shortest so the first valid match is also the longest.
    // The DNS label preceding the service is length-prefixed; in well-formed mDNS
    // there is exactly one valid match, but coincidental shorter matches can occur
    // when arbitrary bytes upstream happen to equal a small length value.
    for name_len in (1usize..=63).rev() {
        if pos < name_len + 1 { continue; }
        let len_pos = pos - name_len - 1;
        if payload[len_pos] as usize != name_len { continue; }
        let name_bytes = &payload[len_pos + 1..pos];
        if let Ok(s) = std::str::from_utf8(name_bytes) {
            let s = s.trim();
            if !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Skip a DNS name at `off`, following compression pointers. Returns the offset
/// immediately after the name, or None on malformed input.
fn skip_dns_name(packet: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let b = *packet.get(off)?;
        if b == 0 { return Some(off + 1); }                // root label
        if b & 0xC0 == 0xC0 { return Some(off + 2); }     // compression pointer — name ends here
        if b & 0xC0 != 0 { return None; }                  // extended label type (EDNS0 etc.)
        off += 1 + (b as usize);
    }
}

/// Read the first (instance) label of a DNS name at `off`.
/// Instance names are never compressed (they're always new), so this is a plain
/// length-prefixed read. Returns None if the first byte is a compression pointer
/// (meaning the entire name is a pointer, which shouldn't happen for instance labels)
/// or the label content is not printable ASCII.
fn first_dns_label(packet: &[u8], off: usize) -> Option<String> {
    let len = *packet.get(off)? as usize;
    if len == 0 || len & 0xC0 != 0 || len > 63 { return None; }
    let end = off + 1 + len;
    if end > packet.len() { return None; }
    let s = std::str::from_utf8(&packet[off + 1..end]).ok()?.trim();
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        Some(s.to_string())
    } else {
        None
    }
}

/// Fallback name extraction for compressed PTR responses (responses to our startup probe).
/// When a device responds to our PTR query from a non-5353 source port, it sends a
/// unicast DNS response where `_netaudio-arc._udp.local` is replaced by a compression
/// pointer, so the service needle doesn't appear literally in the RDATA. We parse the
/// DNS structure properly instead: skip the question section, then walk the answer
/// records, and for the first PTR record extract the first label (= instance name).
fn extract_instance_from_ptr_response(payload: &[u8]) -> Option<String> {
    if payload.len() < 12 { return None; }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;

    let mut off = 12usize;

    for _ in 0..qdcount {
        off = skip_dns_name(payload, off)?;
        off = off.checked_add(4)?; // QTYPE + QCLASS
    }

    for _ in 0..ancount {
        off = skip_dns_name(payload, off)?;
        if off + 10 > payload.len() { return None; }
        let rtype = u16::from_be_bytes([payload[off], payload[off + 1]]);
        off += 8; // type(2) + class(2) + ttl(4)
        let rdlen = u16::from_be_bytes([payload[off], payload[off + 1]]) as usize;
        off += 2;

        if rtype == 12 { // PTR — RDATA first label is the instance name
            if let Some(name) = first_dns_label(payload, off) {
                return Some(name);
            }
        }

        off = off.checked_add(rdlen)?;
        if off > payload.len() { return None; }
    }
    None
}

/// Extract the Dante device instance name from an mDNS payload.
/// Tries the byte-search approach first (works for spontaneous uncompressed announcements),
/// then falls back to proper DNS PTR parsing for compressed probe responses.
pub fn extract_dante_name(payload: &[u8]) -> Option<String> {
    extract_mdns_instance_name(payload, b"\x0d_netaudio-cmc")
        .or_else(|| extract_mdns_instance_name(payload, b"\x0d_netaudio-arc"))
        .or_else(|| extract_mdns_instance_name(payload, b"\x09_netaudio"))
        .or_else(|| extract_instance_from_ptr_response(payload))
}

/// Extract the NDI source instance name from an mDNS payload.
pub fn extract_ndi_name(payload: &[u8]) -> Option<String> {
    extract_mdns_instance_name(payload, b"\x04_ndi")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dante_name_extracted_from_mdns_label() {
        // DNS label encoding: \x05Stage + \x09_netaudio  (legacy firmware)
        let mut p = vec![0x05, b'S', b't', b'a', b'g', b'e'];
        p.extend_from_slice(b"\x09_netaudio");
        assert_eq!(extract_dante_name(&p), Some("Stage".to_string()));
    }

    #[test]
    fn dante_name_extracted_from_netaudio_cmc_label() {
        // DNS label encoding: \x0fY001-Yamaha-DM7 + \x0d_netaudio-cmc  (modern firmware 4.x+)
        let instance = b"Y001-Yamaha-DM7";
        let mut p = vec![instance.len() as u8];
        p.extend_from_slice(instance);
        p.extend_from_slice(b"\x0d_netaudio-cmc");
        assert_eq!(extract_dante_name(&p), Some("Y001-Yamaha-DM7".to_string()));
    }

    #[test]
    fn dante_name_extracted_from_netaudio_arc_label() {
        // DNS label encoding: instance + \x0d_netaudio-arc  (Dante ARC service)
        let instance = b"TASCAM";
        let mut p = vec![instance.len() as u8];
        p.extend_from_slice(instance);
        p.extend_from_slice(b"\x0d_netaudio-arc");
        assert_eq!(extract_dante_name(&p), Some("TASCAM".to_string()));
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

    // ── PTR response (compressed) path ──────────────────────────────────────

    /// Build a minimal mDNS PTR response packet as a Dante device would send
    /// in reply to a PTR query for `_netaudio-arc._udp.local`.
    /// Layout:
    ///   12-byte DNS header (QR=1, ANCOUNT=1)
    ///   Question: _netaudio-arc._udp.local PTR? (inline labels)
    ///   Answer:   _netaudio-arc._udp.local PTR  DeviceName._netaudio-arc._udp.local
    ///             RDATA uses compression pointer for the service part.
    fn build_ptr_response(instance: &str) -> Vec<u8> {
        let mut p: Vec<u8> = Vec::new();
        // Header: ID=0, QR=1(response), QDCOUNT=1, ANCOUNT=1
        p.extend_from_slice(&[0x00, 0x00]); // ID
        p.extend_from_slice(&[0x84, 0x00]); // flags: QR=1, AA=1
        p.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        p.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
        p.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        p.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

        // Question name offset will be 12. Labels: _netaudio-arc._udp.local
        let qname_offset = p.len() as u16; // = 12
        p.extend_from_slice(b"\x0d_netaudio-arc\x04_udp\x05local\x00");
        p.extend_from_slice(&[0x00, 0x0C]); // QTYPE=PTR
        p.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

        // Answer: name = compression pointer back to question name (offset 12)
        p.push(0xC0);
        p.push(qname_offset as u8);
        p.extend_from_slice(&[0x00, 0x0C]); // TYPE=PTR
        p.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]); // TTL=120

        // RDATA: instance label (inline) + compression pointer for service
        let mut rdata: Vec<u8> = Vec::new();
        rdata.push(instance.len() as u8);
        rdata.extend_from_slice(instance.as_bytes());
        rdata.push(0xC0);
        rdata.push(qname_offset as u8); // points back to _netaudio-arc._udp.local
        p.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
        p.extend_from_slice(&rdata);
        p
    }

    #[test]
    fn extract_name_from_compressed_ptr_response() {
        let pkt = build_ptr_response("Y001-Yamaha-DSP-RX-HY1");
        // The needle \x0d_netaudio-arc appears in the question section only —
        // the inline search returns None; the PTR parser fallback should succeed.
        assert_eq!(extract_dante_name(&pkt), Some("Y001-Yamaha-DSP-RX-HY1".to_string()));
    }

    #[test]
    fn extract_name_from_compressed_ptr_response_long_name() {
        let name = "Y009-Yamaha-Rio3224-D2-19862a";
        let pkt = build_ptr_response(name);
        assert_eq!(extract_dante_name(&pkt), Some(name.to_string()));
    }

    #[test]
    fn skip_dns_name_plain_labels() {
        // _netaudio-arc._udp.local = 0x0d + 13 bytes + 0x04 + 3 bytes + 0x05 + 5 bytes + 0x00
        let name = b"\x0d_netaudio-arc\x04_udp\x05local\x00";
        assert_eq!(skip_dns_name(name, 0), Some(name.len()));
    }

    #[test]
    fn skip_dns_name_compression_pointer() {
        // A 2-byte compression pointer 0xC0 0x0C
        let data = b"\xc0\x0c";
        assert_eq!(skip_dns_name(data, 0), Some(2));
    }

    #[test]
    fn first_dns_label_extracts_instance() {
        // "Y001-Yamaha-DSP-RX-HY1" = 22 bytes = 0x16
        let data = b"\x16Y001-Yamaha-DSP-RX-HY1\xc0\x0c";
        assert_eq!(first_dns_label(data, 0), Some("Y001-Yamaha-DSP-RX-HY1".to_string()));
    }
}
