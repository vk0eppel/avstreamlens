// AVStreamLens — src/stats.rs
// Contains all statistical tracking structs and their associated calculation methods.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

// ═════════════════════════════════════════════════════════════════
// SECTION 2 — STREAM STATISTICS (RTP/AV/Audio)
// ════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct StreamStats {
    pub protocol:          String,
    pub packets:           u64,
    pub lost_packets:      u64,
    pub last_seq:          Option<u16>,
    pub jitter:            f64,        // seconds, RFC 3550
    pub last_rtp_ts:       Option<u32>,
    pub last_arrival:      Option<Instant>,
    pub clock_hz:          f64,
    pub sdp_name:          Option<String>,
    pub sdp_rtpmap:        Option<String>,
    // Enhanced information
    pub is_multicast:      bool,
    pub dst_ip:            Option<Ipv4Addr>,
    pub dst_port:          u16,
    pub media_type:        String,    // "audio", "video", "ancillary" or "unknown"
    pub channels:          u8,         // for audio
    pub bitrate_bps:       u64,        // calculated bitrate
    pub last_bitrate_check: Instant,
    pub packets_at_check:  u64,
    // Timestamp discontinuity detection
    pub ts_discontinuities: u64,
    pub last_ts_diff:       Option<i64>,
    // ptime SDP (ms) — tolerance for TS discontinuity detection
    pub ptime_ms:           f64,
    // Exact bitrate: accumulator of actual UDP bytes
    pub bytes_total:        u64,
    pub bytes_at_check:     u64,
    // SSRC tracking — change = RTP source interruption
    pub last_ssrc:          Option<u32>,
    pub ssrc_changes:       u64,
    // Last packet received — to detect dead streams (silence)
    pub last_packet_time:   Option<Instant>,
    // Flag: avoids repeating the "stream dead" alert in each report
    pub dead_alerted:       bool,
}

impl StreamStats {
    pub fn new(protocol: &str, clock_hz: f64) -> Self {
        Self {
            protocol:            protocol.to_string(),
            packets:             0,
            lost_packets:        0,
            last_seq:            None,
            jitter:              0.0,
            last_rtp_ts:         None,
            last_arrival:        None,
            clock_hz,
            sdp_name:            None,
            sdp_rtpmap:          None,
            is_multicast:        false,
            dst_ip:              None,
            dst_port:            0,
            media_type:          "unknown".to_string(),
            channels:            0,
            bitrate_bps:         0,
            last_bitrate_check:  Instant::now(),
            packets_at_check:    0,
            ts_discontinuities:  0,
            last_ts_diff:        None,
            ptime_ms:            0.0,
            bytes_total:         0,
            bytes_at_check:      0,
            last_ssrc:           None,
            ssrc_changes:        0,
            last_packet_time:    None,
            dead_alerted:        false,
        }
    }
    // Constructor with enhanced info — useful when SDP is available at stream start
    pub fn new_with_info(protocol: &str, clock_hz: f64, is_multicast: bool, dst_ip: Ipv4Addr, dst_port: u16) -> Self {
        let mut stats = Self::new(protocol, clock_hz);
        stats.is_multicast = is_multicast;
        stats.dst_ip = Some(dst_ip);
        stats.dst_port = dst_port;
        stats
    }

    /// `udp_payload_len`: actual length of UDP payload (without IP/UDP header),
    /// used for exact bitrate calculation.
    pub fn update(&mut self, seq: u16, rtp_ts: u32, ssrc: u32, udp_payload_len: usize) {
        self.packets += 1;

        // ── Losses (16-bit wrapping) ──────────────────
        if let Some(last) = self.last_seq {
            let expected = last.wrapping_add(1);
            if seq != expected {
                self.lost_packets += seq.wrapping_sub(expected) as u64;
            }
        }
        self.last_seq = Some(seq);

        // ── Timestamp discontinuity detection ────────
        if let Some(last_ts) = self.last_rtp_ts {
            let expected_diff = if self.clock_hz > 0.0 {
                let ptime_ms = if self.ptime_ms > 0.0 { self.ptime_ms } else { 1.0 };
                (self.clock_hz * ptime_ms / 1000.0) as i64
            } else {
                48 // fallback : 1 ms @ 48 kHz
            };
            let actual_diff = rtp_ts.wrapping_sub(last_ts) as i64;
            // Tolerance ±50% around expected ptime
            if expected_diff > 0 &&
               ((actual_diff as f64) < (expected_diff as f64 * 0.5) ||
                (actual_diff as f64) > (expected_diff as f64 * 1.5))
            {
                self.ts_discontinuities += 1;
            }
            self.last_ts_diff = Some(actual_diff);
        }

        // ── RFC 3550 §6.4.1 Jitter ────────────────────
        let now = Instant::now();
        if let (Some(last_ts), Some(last_time)) = (self.last_rtp_ts, self.last_arrival) {
            let arrival_diff = now.duration_since(last_time).as_secs_f64();
            let rtp_diff     = rtp_ts.wrapping_sub(last_ts) as f64 / self.clock_hz;
            let d            = (arrival_diff - rtp_diff).abs();
            self.jitter     += (d - self.jitter) / 16.0;
        }
        self.last_rtp_ts  = Some(rtp_ts);
        self.last_arrival = Some(now);

        // ── SSRC tracking ────────────────────────────
        if let Some(prev_ssrc) = self.last_ssrc {
            if prev_ssrc != ssrc {
                self.ssrc_changes += 1;
            }
        }
        self.last_ssrc = Some(ssrc);
        self.last_packet_time = Some(now);
        self.dead_alerted = false; // Stream alive — reset alert flag
            // Accumulate actual bytes (UDP payload) and calculate
            // throughput every second.
            self.bytes_total += udp_payload_len as u64;
            if self.last_bitrate_check.elapsed() > Duration::from_secs(1) {
                let bytes_delta = self.bytes_total.saturating_sub(self.bytes_at_check);
                self.bitrate_bps = bytes_delta * 8; // bits/s in the last second
                self.bytes_at_check  = self.bytes_total;
                self.packets_at_check = self.packets;
                self.last_bitrate_check = now;
            }
    }

    pub fn loss_pct(&self) -> f64 {
        let total = self.packets + self.lost_packets;
        if total == 0 { 0.0 } else { 100.0 * self.lost_packets as f64 / total as f64 }
    }

    pub fn jitter_ms(&self) -> f64 { self.jitter * 1000.0 }
}

// ═════════════════════──══════════════════──═════════════════════════
// SECTION 3 — TCP STREAM STATISTICS
// ═════════════════════──══════════════════──═════════════════════════

#[derive(Debug, Clone)]
pub struct TcpStreamStats {
    pub key: String,
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub packets: u64,
    pub bytes: u64,
    pub retransmissions: u64,
    pub fin_packets: u64,
    pub rst_packets: u64,
    pub last_seen: Instant,
    pub stream_quality: StreamQuality,
    pub bitrate_bps: u64,
    pub last_bitrate_check: Instant,
    pub bytes_at_check: u64,
    // Tracking of last TCP seq seen — true retransmission detection
    pub last_seq: Option<u32>,
    pub last_ack: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StreamQuality {
    Healthy,
    Degrading,      // Growing retransmissions
    Critical,       // High retransmission rate or FIN/RST
    Terminated,
}

impl TcpStreamStats {
    pub fn new(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Self {
        let key = format!("TCP {}:{} → {}:{}", src_ip, src_port, dst_ip, dst_port);
        Self {
            key,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            packets: 0,
            bytes: 0,
            retransmissions: 0,
            fin_packets: 0,
            rst_packets: 0,
            last_seen: Instant::now(),
            stream_quality: StreamQuality::Healthy,
            bitrate_bps: 0,
            last_bitrate_check: Instant::now(),
            bytes_at_check: 0,
            last_seq: None,
            last_ack: None,
        }
    }

    pub fn update_bitrate(&mut self) {
        if self.last_bitrate_check.elapsed() > Duration::from_secs(1) {
            let bytes_delta = self.bytes - self.bytes_at_check;
            self.bitrate_bps = bytes_delta * 8;
            self.bytes_at_check = self.bytes;
            self.last_bitrate_check = Instant::now();
        }
    }

    pub fn update_quality(&mut self) {
        if self.rst_packets > 0 || self.fin_packets > 2 {
            self.stream_quality = StreamQuality::Terminated;
        } else if self.retransmissions > 10 {
            self.stream_quality = StreamQuality::Critical;
        } else if self.retransmissions > 2 {
            self.stream_quality = StreamQuality::Degrading;
        } else {
            self.stream_quality = StreamQuality::Healthy;
        }
    }
}

// ═════════════════════──══════════════════──═════════════════════════
// SECTION 4 — GLOBAL NETWORK HEALTH STATISTICS
// ═════════════════════──══════════════════──═════════════════════════

#[derive(Debug, Clone)]
pub struct NetworkHealth {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub multicast_packets: u64,
    pub unicast_packets: u64,
    pub packet_loss_streams: u64,        // count of streams with loss
    pub high_jitter_streams: u64,
    pub aes67_discontinuities: u64,
    pub timestamp_errors: u64,
    pub tcp_retransmissions: u64,
    pub detected_duplicates: u64,        // multicast duplicates
    pub congestion_events: u64,
    pub saturation_warnings: u64,
    pub network_score: f64,              // 0-100
}

impl NetworkHealth {
    pub fn new() -> Self {
        Self {
            total_packets: 0,
            total_bytes: 0,
            multicast_packets: 0,
            unicast_packets: 0,
            packet_loss_streams: 0,
            high_jitter_streams: 0,
            aes67_discontinuities: 0,
            timestamp_errors: 0,
            tcp_retransmissions: 0,
            detected_duplicates: 0,
            congestion_events: 0,
            saturation_warnings: 0,
            network_score: 100.0,
        }
    }

    pub fn calculate_score(&mut self, streams: &std::collections::HashMap<String, StreamStats>, tcp_streams: &std::collections::HashMap<String, TcpStreamStats>) {
        let mut score = 100.0;

        // Deduct for packet loss
        for stats in streams.values() {
            if stats.loss_pct() > 0.0 {
                score -= stats.loss_pct().min(10.0);
            }
        }

        // Deduct for jitter
        for stats in streams.values() {
            if stats.jitter_ms() > 20.0 {
                score -= 5.0;
            } else if stats.jitter_ms() > 10.0 {
                score -= 2.0;
            }
        }

        // Deduct for timestamp discontinuities
        for stats in streams.values() {
            if stats.ts_discontinuities > 0 {
                score -= 3.0 * (stats.ts_discontinuities as f64).min(5.0);
            }
        }

        // Deduct for TCP issues
        for tcp_stats in tcp_streams.values() {
            match tcp_stats.stream_quality {
                StreamQuality::Healthy => {},
                StreamQuality::Degrading => score -= 5.0,
                StreamQuality::Critical => score -= 15.0,
                StreamQuality::Terminated => score -= 25.0,
            }
        }

        // Deduct for detected issues
        score -= (self.detected_duplicates as f64).min(10.0);
        score -= (self.congestion_events as f64 * 0.5).min(15.0);

        self.network_score = score.max(0.0);
    }
}

// ═════════════════════──══════════════════──═════════════════════════
// SECTION 5 — PTP DOMAIN STATISTICS
// ═════════════════════──══════════════════──═════════════════════════

#[derive(Debug, Clone)]
pub struct PtpStats {
    pub domain:            u8,
    pub version:           u8,
    pub packets:           u64,
    pub masters:           std::collections::HashSet<String>,
    pub last_seen:         Instant,
    pub last_grandmaster:  Option<String>,
    pub grandmaster_changes: u64,
    pub clock_valid:       bool,              // Clock is currently present and valid
    pub clock_presence_duration: Duration,    // Time since last valid clock activity
    pub timeout_secs:      u64,               // Configurable timeout (default: 5s)
    pub last_quality:      Option<String>,
    pub last_offset_ns:    Option<i64>,
    pub last_path_delay_ns: Option<i64>,
}

impl PtpStats {
    pub fn new(domain: u8, version: u8) -> Self {
        Self {
            domain,
            version,
            packets: 0,
            masters: std::collections::HashSet::new(),
            last_seen: Instant::now(),
            last_grandmaster: None,
            grandmaster_changes: 0,
            clock_valid: false,
            clock_presence_duration: Duration::ZERO,
            timeout_secs: 5,
            last_quality: None,
            last_offset_ns: None,
            last_path_delay_ns: None,
        }
    }

    pub fn update(&mut self, info: &crate::protocols::PtpInfo) {
        self.packets += 1;
        self.last_seen = Instant::now();

        // Track master clocks from clock_id or grandmaster_id
        if let Some(clock_id) = info.clock_id.as_deref().or(info.grandmaster_id.as_deref()) {
            self.masters.insert(clock_id.to_string());
        }

        // ── Announce message: Detect new grandmaster ───
        if info.message_type == 0x0B {
            if let Some(gm) = &info.grandmaster_id {
                // Check for grandmaster change
                if let Some(current) = &self.last_grandmaster {
                    if current != gm {
                        self.grandmaster_changes += 1;
                        println!(
                            "\x1b[33m⚠️  GRANDMASTER CHANGED (Domain {}): {} → {}\x1b[0m",
                            self.domain, current, gm
                        );
                        self.last_grandmaster = Some(gm.clone());
                    }
                } else {
                    // First time seeing this grandmaster
                    println!(
                        "\x1b[32m✓️  GRANDMASTER DETECTED (Domain {}): {}",
                        self.domain, gm
                    );
                    self.last_grandmaster = Some(gm.clone());
                }

                // Mark clock as valid and reset timer
                self.clock_valid = true;
                self.clock_presence_duration = Duration::ZERO;
            }
            if let Some(q) = &info.clock_quality {
                self.last_quality = Some(q.clone());
            }
        }

        // ── Sync/Follow_Up: Clock still present ────────
        if info.message_type == 0x00 || info.message_type == 0x08 {
            // Clock is still active
            self.clock_presence_duration = Instant::now().duration_since(self.last_seen);
            if self.clock_valid {
                println!(
                    "\x1b[92m✔️  PTP Clock Present (Domain {})\x1b[0m",
                    self.domain
                );
            }
            self.last_offset_ns = info.correction_ns;
        }

        // ── Check timeout ────────────────────────
        if !self.clock_valid {
            let timeout = Duration::from_secs(self.timeout_secs as u64);
            if self.clock_presence_duration > timeout {
                println!(
                    "\x1b[31m❌ PTP Clock LOST (Domain {})\x1b[0m",
                    self.domain
                );
                self.clock_valid = false;
                self.clock_presence_duration = Duration::ZERO;
            }
        }

        if info.message_type == 0x09 {
            self.last_path_delay_ns = info.path_delay_ns;
        }
    }
}