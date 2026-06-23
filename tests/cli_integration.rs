// Integration test for AVStreamLens's CLI behavior under a broken pipe.
//
// Spawns the compiled binary against a small synthetic pcap (offline replay,
// no root required) and closes the read end of its stdout early — mimicking
// `avstreamlens -r capture.pcap | head -c 64`. Before the SIGPIPE fix, the
// next write to the closed pipe panicked inside `println!`
// ("failed printing to stdout: Broken pipe (os error 32)") instead of the
// process exiting cleanly.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Build a minimal valid pcap (global header + N Ethernet/IPv4/UDP/RTP
/// packets) with many distinct multicast destinations, all at the same
/// timestamp. Many distinct stream keys means a single report renders many
/// lines — enough to exceed the OS pipe buffer so the child is forced to
/// write after we've already closed our end.
fn build_sample_pcap(stream_count: u16) -> Vec<u8> {
    let mut out = Vec::new();
    // pcap global header (little-endian, version 2.4, Ethernet linktype).
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());

    for i in 0..stream_count {
        let frame = build_aes67_frame(i);
        out.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
        out.extend_from_slice(&(i as u32).to_le_bytes()); // ts_usec (just for uniqueness)
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // incl_len
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // orig_len
        out.extend_from_slice(&frame);
    }
    out
}

/// One AES67-style multicast RTP frame: Ethernet + IPv4 + UDP + RTP. The
/// destination IP's last octet varies with `i` so each packet becomes a
/// distinct stream key in `CaptureState`.
fn build_aes67_frame(i: u16) -> Vec<u8> {
    let dst_ip = [239, 69, (i >> 8) as u8, (i & 0xff) as u8];
    let src_ip = [10, 0, 1, 20];
    let dst_port: u16 = 5004;
    let src_port: u16 = 50000u16.wrapping_add(i); // ephemeral — avoids the Dante port gate

    let mut rtp = Vec::new();
    rtp.push(0x80); // version 2
    rtp.push(97); // payload type 97 (dynamic)
    rtp.extend_from_slice(&i.to_be_bytes()); // sequence number
    rtp.extend_from_slice(&((i as u32) * 48).to_be_bytes()); // timestamp
    rtp.extend_from_slice(&0xdead_beefu32.to_be_bytes()); // SSRC
    rtp.extend_from_slice(&[0u8; 16]); // payload

    let udp_len = 8 + rtp.len();
    let mut udp = Vec::new();
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes()); // checksum (unchecked by the parser)
    udp.extend_from_slice(&rtp);

    let ip_total_len = 20 + udp.len();
    let mut ip = Vec::new();
    ip.push(0x45); // version 4, header length 5 words
    ip.push(0); // DSCP/ECN
    ip.extend_from_slice(&(ip_total_len as u16).to_be_bytes());
    ip.extend_from_slice(&1u16.to_be_bytes()); // identification
    ip.extend_from_slice(&0u16.to_be_bytes()); // flags/fragment offset
    ip.push(32); // TTL
    ip.push(17); // protocol: UDP
    ip.extend_from_slice(&0u16.to_be_bytes()); // header checksum (unchecked by the parser)
    ip.extend_from_slice(&src_ip);
    ip.extend_from_slice(&dst_ip);
    ip.extend_from_slice(&udp);

    let mut eth = Vec::new();
    eth.extend_from_slice(&[0x01, 0x00, 0x5e, 0x45, dst_ip[2], dst_ip[3]]); // multicast dst MAC
    eth.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x01, 0x14]); // src MAC
    eth.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType IPv4
    eth.extend_from_slice(&ip);
    eth
}

#[test]
fn broken_pipe_exits_without_panicking() {
    let pcap_bytes = build_sample_pcap(800);
    let mut pcap_path = std::env::temp_dir();
    pcap_path.push(format!("avstreamlens_test_{}.pcap", std::process::id()));
    std::fs::write(&pcap_path, &pcap_bytes).expect("write sample pcap");

    let mut child = Command::new(env!("CARGO_BIN_EXE_avstreamlens"))
        .arg("--read")
        .arg(&pcap_path)
        .arg("--no-color")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn avstreamlens");

    // Read a small amount (mimics `head -c 64`), then close our end of the
    // pipe while the child likely still has many more lines queued up.
    let mut stdout = child.stdout.take().expect("child stdout");
    let mut buf = [0u8; 64];
    let _ = stdout.read(&mut buf);
    drop(stdout);

    let mut stderr_pipe = child.stderr.take().expect("child stderr");

    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("child did not exit within 10s after closing stdout");
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    let mut stderr_buf = String::new();
    let _ = stderr_pipe.read_to_string(&mut stderr_buf);

    let _ = std::fs::remove_file(&pcap_path);

    assert!(
        !stderr_buf.contains("panicked at"),
        "child panicked on broken pipe (status: {:?}):\n{}",
        status,
        stderr_buf
    );

    let _ = std::io::stdout().flush();
}
