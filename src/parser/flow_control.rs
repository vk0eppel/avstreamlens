// AVStreamLens — src/parser/flow_control.rs
// IEEE 802.3x PAUSE and 802.1Qbb Priority Flow Control (PFC) — EtherType 0x8808.
//
// When upstream congestion triggers link-layer flow control, downstream NICs
// stop transmitting for the requested quanta. This causes brief freezes that
// show up as audio glitches and video micro-stutter — invisible to L3+ tools.
//
// IMPORTANT LIMITATION: many NICs/drivers consume pause frames at the MAC layer
// before pcap sees them. Detection only works on NICs that pass them to userspace.
// Absence of these alerts therefore does NOT prove pause/PFC isn't happening.

use crate::protocols::{AvProtocol, FlowControlKind};

/// Parse the payload of an 0x8808 frame and classify it as PAUSE or PFC.
/// Returns None for opcodes we don't recognise.
pub fn parse_flow_control(payload: &[u8]) -> Option<AvProtocol> {
    // The first 2 bytes after the EtherType are the MAC control opcode.
    //   0x0001 = PAUSE  (802.3x)
    //   0x0101 = PFC    (802.1Qbb)
    if payload.len() < 2 { return None; }
    let opcode = u16::from_be_bytes([payload[0], payload[1]]);
    let kind = match opcode {
        0x0001 => FlowControlKind::Pause,
        0x0101 => FlowControlKind::PriorityFlowControl,
        _      => return None,
    };
    Some(AvProtocol::FlowControl { kind })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pause_frame_detected() {
        // opcode 0x0001 + pause_quanta(2) + padding
        let p = [0x00, 0x01, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00];
        match parse_flow_control(&p) {
            Some(AvProtocol::FlowControl { kind: FlowControlKind::Pause }) => {}
            other => panic!("expected Pause, got {:?}", other),
        }
    }

    #[test]
    fn pfc_frame_detected() {
        // opcode 0x0101 + priority_enable_vector(2) + 8 × quanta(2)
        let mut p = vec![0x01, 0x01, 0x00, 0xFF];
        p.extend_from_slice(&[0x00; 16]);
        match parse_flow_control(&p) {
            Some(AvProtocol::FlowControl { kind: FlowControlKind::PriorityFlowControl }) => {}
            other => panic!("expected PFC, got {:?}", other),
        }
    }

    #[test]
    fn unknown_opcode_returns_none() {
        assert!(parse_flow_control(&[0xFF, 0xFF]).is_none());
    }

    #[test]
    fn truncated_payload_returns_none() {
        assert!(parse_flow_control(&[0x00]).is_none());
    }
}
