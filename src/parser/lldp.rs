// AVStreamLens — src/parser/lldp.rs
// LLDP TLV walker that surfaces the IEEE 802.3az EEE TLV.
//
// LLDP TLV encoding: `[type(7 bits) | length(9 bits)][value]`
// EEE TLV: type=127 (org-specific), OUI=00-12-0F, subtype=0x05
// Value layout: Tw_sys_tx(2) Tw_sys_rx(2) Fallback_tw(2) Tx_tw_echo(2) Rx_tw_echo(2)

use crate::protocols::AvProtocol;

/// Parse an LLDP frame (EtherType 0x88CC) looking for the IEEE 802.3az EEE TLV.
///
/// Returns Some only when EEE TLV is present and at least one wake-up time is non-zero.
pub fn parse_lldp_eee(payload: &[u8]) -> Option<AvProtocol> {
    let mut pos = 0usize;
    let mut chassis_id = String::new();
    let mut port_id    = String::new();
    let mut tx_wake: u16 = 0;
    let mut rx_wake: u16 = 0;
    let mut eee_found  = false;

    while pos + 2 <= payload.len() {
        let header   = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let tlv_type = (header >> 9) as u8;
        let tlv_len  = (header & 0x01FF) as usize;
        pos += 2;

        if tlv_type == 0 { break; } // End of LLDPDU
        if pos + tlv_len > payload.len() { break; }

        let value = &payload[pos..pos + tlv_len];

        match tlv_type {
            1 if tlv_len >= 2 => { chassis_id = format_lldp_id(&value[1..]); } // Chassis ID
            2 if tlv_len >= 2 => { port_id    = format_lldp_id(&value[1..]); } // Port ID
            127 if tlv_len >= 4 => { // Organizationally Specific
                let oui     = (value[0] as u32) << 16 | (value[1] as u32) << 8 | value[2] as u32;
                let subtype = value[3];
                // IEEE 802.3 OUI = 0x00120F, EEE subtype = 0x05
                if oui == 0x00120F && subtype == 0x05 && tlv_len >= 14 {
                    tx_wake   = u16::from_be_bytes([value[4],  value[5]]);
                    rx_wake   = u16::from_be_bytes([value[6],  value[7]]);
                    eee_found = true;
                }
            }
            _ => {}
        }

        pos += tlv_len;
    }

    if eee_found && (tx_wake > 0 || rx_wake > 0) {
        Some(AvProtocol::LldpEee {
            chassis_id,
            port_id,
            tx_wake_us: tx_wake,
            rx_wake_us: rx_wake,
        })
    } else {
        None
    }
}

fn format_lldp_id(bytes: &[u8]) -> String {
    // Try UTF-8 first (port descriptions are often ASCII)
    if let Ok(s) = std::str::from_utf8(bytes)
        && s.chars().all(|c| c.is_ascii_graphic() || c == ' ')
    {
        return s.trim().to_string();
    }
    // Fall back to colon-separated hex
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lldp_with_eee(tx: u16, rx: u16) -> Vec<u8> {
        let mut p = Vec::new();
        // Chassis ID TLV: type=1, len=7 → header = (1<<9)|7 = 0x0207
        p.extend_from_slice(&[0x02, 0x07, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        // Port ID TLV: type=2, len=7 → header = (2<<9)|7 = 0x0407
        p.extend_from_slice(&[0x04, 0x07, 0x03, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        // EEE TLV: type=127, len=14 → header = (127<<9)|14 = 0xFE0E
        // Value: OUI(3) + subtype(1) + Tw_sys_tx(2) + Tw_sys_rx(2) + zeros(8)
        p.extend_from_slice(&[0xFE, 0x0E, 0x00, 0x12, 0x0F, 0x05]);
        p.extend_from_slice(&tx.to_be_bytes());
        p.extend_from_slice(&rx.to_be_bytes());
        p.extend_from_slice(&[0x00; 8]);
        // End of LLDPDU
        p.extend_from_slice(&[0x00, 0x00]);
        p
    }

    #[test]
    fn lldp_eee_detected_with_wake_times() {
        let proto = parse_lldp_eee(&lldp_with_eee(16, 16)).unwrap();
        match proto {
            AvProtocol::LldpEee { tx_wake_us, rx_wake_us, .. } => {
                assert_eq!(tx_wake_us, 16);
                assert_eq!(rx_wake_us, 16);
            }
            _ => panic!("expected LldpEee variant"),
        }
    }

    #[test]
    fn lldp_eee_zero_wake_times_ignored() {
        // EEE TLV present but both wake times are 0 — should not report as EEE
        assert!(parse_lldp_eee(&lldp_with_eee(0, 0)).is_none());
    }

    #[test]
    fn lldp_no_eee_tlv_returns_none() {
        let p = [
            0x02, 0x07, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // chassis
            0x04, 0x07, 0x03, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // port
            0x00, 0x00, // end
        ];
        assert!(parse_lldp_eee(&p).is_none());
    }
}
