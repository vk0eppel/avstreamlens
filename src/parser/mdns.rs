// AVStreamLens — src/parser/mdns.rs
// mDNS service-instance name extraction (Dante `_netaudio`, NDI `_ndi`).

/// Return true if `payload` contains the byte-encoded mDNS service string `service`.
pub fn mdns_contains(payload: &[u8], service: &[u8]) -> bool {
    payload.windows(service.len()).any(|w| w == service)
}

/// Extract an mDNS service-instance name — the label immediately preceding a given
/// DNS-encoded service label (e.g. `\x04_ndi` for NDI, `\x09_netaudio` for Dante).
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

/// Extract the Dante device instance name from an mDNS payload.
/// Tries modern service types first (firmware 4.x+), then the legacy `_netaudio` service.
pub fn extract_dante_name(payload: &[u8]) -> Option<String> {
    extract_mdns_instance_name(payload, b"\x0d_netaudio-cmc")
        .or_else(|| extract_mdns_instance_name(payload, b"\x0d_netaudio-arc"))
        .or_else(|| extract_mdns_instance_name(payload, b"\x09_netaudio"))
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
}
