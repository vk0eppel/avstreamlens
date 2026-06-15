// AVStreamLens — src/stats.rs
// Contains all statistical tracking structs and their associated calculation methods.

use std::collections::HashMap;
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
    pub src_ip:            Option<Ipv4Addr>, // sender — set for Dante (drives retroactive mDNS naming)
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
    // Payload type validation (from SDP a=rtpmap)
    pub expected_pt:        Option<u8>,  // declared by SDP; None = no SDP received yet
    pub pt_mismatches:      u64,         // packets with payload type ≠ expected
    // Clock rate confirmation
    pub clock_hz_confirmed: bool,        // true when clock_hz came from SDP (not default 48kHz)
    // IAT burst detection (EEE / switch queuing fingerprint)
    pub gap_events:         u64,         // IAT > 50ms in the current 5s window
    pub max_iat_ms:         f64,         // worst-case inter-arrival time (ms)
    // Per-stream DSCP validation
    pub dscp_violations:    u64,         // packets with wrong DSCP for this protocol
    // Per-window deltas — drive alert deduplication. Cumulative counters above
    // (lost_packets, ts_discontinuities) keep growing; alerts fire only when
    // the per-window delta is non-zero, so an old loss does not re-alert every
    // 5s forever.
    pub lost_this_window:               u64,
    pub ts_discontinuities_this_window: u64,
    // Out-of-order packets (negative seq delta). Distinct from loss: indicates
    // path instability or per-packet ECMP load-balancing rather than drops.
    pub reorders_this_window:           u64,
    // True once at least one packet parsed as RTP. Dante ATP flows (official
    // ports 4321 / 14336–15359) are not RTP-framed — they are tracked via
    // update_non_rtp and must not render 0% loss / 0 ms jitter as if measured,
    // nor fire the "not announced (no SAP)" alert.
    pub rtp_seen:                       bool,
    // Minimum IP TTL observed across all packets in this stream's lifetime.
    // Used for Dante routing detection: Dante is L2-only, so any TTL < 64 means
    // a router decremented it — a misconfiguration that should alert the engineer.
    pub min_ttl:                        Option<u8>,
    // Scratch buffer for clock-rate inference from RTP timestamp deltas.
    // Cleared once clock_hz_confirmed is set; empty thereafter.
    pub ts_delta_samples:               Vec<i64>,
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
            src_ip:              None,
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
            expected_pt:         None,
            pt_mismatches:       0,
            clock_hz_confirmed:  false,
            gap_events:          0,
            max_iat_ms:          0.0,
            dscp_violations:     0,
            lost_this_window:               0,
            ts_discontinuities_this_window: 0,
            reorders_this_window:           0,
            rtp_seen:                       false,
            min_ttl:                        None,
            ts_delta_samples:               Vec::new(),
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
        self.rtp_seen = true;

        // ── Losses (16-bit wrapping) ──────────────────
        if let Some(last) = self.last_seq {
            let expected = last.wrapping_add(1);
            if seq != expected {
                // RFC 3550 §A.3: treat large negative delta as reorder/reset, not loss
                let delta = seq.wrapping_sub(expected) as i16;
                if delta > 0 {
                    self.lost_packets += delta as u64;
                    self.lost_this_window += delta as u64;
                } else {
                    // Negative delta = packet arrived out of order. Distinct from
                    // loss; high reorder rate suggests per-packet ECMP load-balancing.
                    self.reorders_this_window += 1;
                }
            }
        }
        self.last_seq = Some(seq);

        // ── Timestamp discontinuity detection ────────
        // Only runs when clock rate is confirmed from SDP — default 48 kHz would produce
        // false positives on 96 kHz or 44.1 kHz streams.
        if self.clock_hz_confirmed
            && let Some(last_ts) = self.last_rtp_ts
        {
            let expected_diff = if self.clock_hz > 0.0 {
                let ptime_ms = if self.ptime_ms > 0.0 { self.ptime_ms } else { 1.0 };
                (self.clock_hz * ptime_ms / 1000.0) as i64
            } else {
                48 // fallback: 1 ms @ 48 kHz
            };
            // Cast through i32 first to preserve sign — u32::wrapping_sub
            // returns u32, and `as i64` would always be non-negative.
            let actual_diff = rtp_ts.wrapping_sub(last_ts) as i32 as i64;
            if expected_diff > 0 &&
               ((actual_diff as f64) < (expected_diff as f64 * 0.5) ||
                (actual_diff as f64) > (expected_diff as f64 * 1.5))
            {
                self.ts_discontinuities += 1;
                self.ts_discontinuities_this_window += 1;
            }
            self.last_ts_diff = Some(actual_diff);
        }

        // ── Clock-rate inference from RTP timestamp delta ─────────
        // Collects consecutive positive deltas until we accumulate enough to take
        // a mode and match against known (clock_hz, ptime_ms) pairs. Stops once
        // clock_hz_confirmed is set (either by SDP or by this inference).
        if !self.clock_hz_confirmed
            && let Some(last_ts) = self.last_rtp_ts
        {
            let delta = rtp_ts.wrapping_sub(last_ts) as i32 as i64;
            if delta > 0 {
                self.ts_delta_samples.push(delta);
                if self.ts_delta_samples.len() >= 8 {
                    self.try_infer_clock_hz();
                    self.ts_delta_samples.clear();
                }
            }
        }

        // ── RFC 3550 §6.4.1 Jitter + IAT burst detection ──────────
        let now = Instant::now();

        // IAT burst: ptime_ms > 0 means SDP confirmed the expected packet interval
        if self.ptime_ms > 0.0
            && let Some(last_time) = self.last_arrival
        {
            let iat_ms = now.duration_since(last_time).as_secs_f64() * 1000.0;
            if iat_ms > self.max_iat_ms { self.max_iat_ms = iat_ms; }
            if iat_ms > 50.0 { self.gap_events += 1; }
        }

        if let (Some(last_ts), Some(last_time)) = (self.last_rtp_ts, self.last_arrival) {
            let arrival_diff = now.duration_since(last_time).as_secs_f64();
            // Preserve sign on wrap: RTP timestamps may rarely go backward (reorder).
            let rtp_diff     = (rtp_ts.wrapping_sub(last_ts) as i32) as f64 / self.clock_hz;
            let d            = (arrival_diff - rtp_diff).abs();
            self.jitter     += (d - self.jitter) / 16.0;
        }
        self.last_rtp_ts  = Some(rtp_ts);
        self.last_arrival = Some(now);

        // ── SSRC tracking ────────────────────────────
        if self.last_ssrc.is_some_and(|prev| prev != ssrc) {
            self.ssrc_changes += 1;
        }
        self.last_ssrc = Some(ssrc);
        self.last_packet_time = Some(now);

        // Accumulate actual bytes (UDP payload) and calculate throughput every second.
        self.bytes_total += udp_payload_len as u64;
        let elapsed = self.last_bitrate_check.elapsed();
        if elapsed > Duration::from_secs(1) {
            let bytes_delta = self.bytes_total.saturating_sub(self.bytes_at_check);
            self.bitrate_bps = (bytes_delta as f64 * 8.0 / elapsed.as_secs_f64()) as u64;
            self.bytes_at_check   = self.bytes_total;
            self.packets_at_check = self.packets;
            self.last_bitrate_check = now;
        }
    }

    /// Presence/bitrate tracking for flows whose payload is not RTP (Dante ATP).
    /// No sequence, timestamp, or jitter analysis — those need RTP fields.
    pub fn update_non_rtp(&mut self, udp_payload_len: usize, now: Instant) {
        self.packets += 1;
        self.last_packet_time = Some(now);
        self.bytes_total += udp_payload_len as u64;
        let elapsed = self.last_bitrate_check.elapsed();
        if elapsed > Duration::from_secs(1) {
            let bytes_delta = self.bytes_total.saturating_sub(self.bytes_at_check);
            self.bitrate_bps = (bytes_delta as f64 * 8.0 / elapsed.as_secs_f64()) as u64;
            self.bytes_at_check   = self.bytes_total;
            self.packets_at_check = self.packets;
            self.last_bitrate_check = now;
        }
    }

    fn try_infer_clock_hz(&mut self) {
        // Known (clock_hz, ptime_ms) pairs that produce integer RTP timestamp
        // deltas. 48 kHz is checked first — it is the dominant rate on AES67 and
        // Dante networks and shares delta values with 96 kHz at the same ptimes.
        const KNOWN: &[(f64, f64)] = &[
            (48000.0, 1.0),   // Δ 48  — most common AES67 / Dante
            (48000.0, 0.5),   // Δ 24
            (48000.0, 2.0),   // Δ 96
            (48000.0, 4.0),   // Δ 192
            (48000.0, 8.0),   // Δ 384
            (48000.0, 10.0),  // Δ 480
            (48000.0, 20.0),  // Δ 960
            (48000.0, 0.25),  // Δ 12
            (48000.0, 0.125), // Δ 6
            (44100.0, 10.0),  // Δ 441
            (44100.0, 20.0),  // Δ 882
        ];

        let mut sorted = self.ts_delta_samples.clone();
        sorted.sort_unstable();

        let mut best = sorted[0];
        let mut best_count = 1usize;
        let mut cur = sorted[0];
        let mut cur_count = 1usize;
        for &v in sorted.iter().skip(1) {
            if v == cur { cur_count += 1; } else { cur = v; cur_count = 1; }
            if cur_count > best_count { best = cur; best_count = cur_count; }
        }
        let mode = best;

        for &(hz, ptime) in KNOWN {
            let expected = (hz * ptime / 1000.0).round() as i64;
            if expected == mode {
                self.clock_hz = hz;
                self.ptime_ms = ptime;
                self.clock_hz_confirmed = true;
                return;
            }
        }
    }

    pub fn loss_pct(&self) -> f64 {
        let total = self.packets + self.lost_packets;
        if total == 0 { 0.0 } else { 100.0 * self.lost_packets as f64 / total as f64 }
    }

    pub fn jitter_ms(&self) -> f64 { self.jitter * 1000.0 }
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 2b — AVDECC ENTITY STATE (per entity_id)
// ═══════════════════════════════════════════════════════════════════

/// Live state for one AVDECC entity discovered via ADP announcements.
/// Pruned from CaptureState when `last_seen` exceeds `valid_time_secs + 10`.
#[derive(Debug, Clone)]
pub struct AvdeccEntity {
    pub entity_id:             [u8; 8],
    pub entity_model_id:       [u8; 8],
    pub entity_capabilities:   u32,
    pub talker_stream_sources: u16,
    pub talker_capabilities:   u16,
    pub listener_stream_sinks: u16,
    pub listener_capabilities: u16,
    pub gptp_grandmaster_id:   [u8; 8],
    pub gptp_domain_number:    u8,
    pub valid_time_secs:       u64,
    pub available_index:       u32,
    pub last_seen:             Instant,
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 2b' — DANTE CONMON DEVICE STATE (per source IP)
// ═══════════════════════════════════════════════════════════════════

/// Live state for one Dante device observed via ConMon multicast
/// (224.0.0.230–233, ports 8700–8708). ConMon is in the link-local 224.0.0.0/24
/// block that IGMP snooping never prunes, so it proves device liveness from any
/// switch port — even when all audio flows are unicast and invisible without SPAN.
/// Pruned from CaptureState when silent (metering runs at ~33 Hz, so a short
/// timeout is safe).
#[derive(Debug, Clone)]
pub struct ConmonDevice {
    pub mac:       [u8; 6],     // sender MAC carried in the ConMon payload
    pub channels:  Option<u8>,  // channel count from 8705 metering frames (scale unverified)
    pub packets:   u64,
    pub last_seen: Instant,
}

// ═════════════════════──══════════════════──═════════════════════════
// SECTION 2c — AVTP STREAM STATISTICS (per stream_id)
// ═════════════════════──══════════════════──═════════════════════════

#[derive(Debug, Clone)]
pub struct AvtpStreamStats {
    pub stream_id:          [u8; 8],
    pub subtype:            u8,
    pub packets:            u64,
    pub lost_frames:        u64,         // AVTP sequence counter drops
    pub last_seq:           Option<u8>,  // last AVTP sequence byte (byte 2 of header)
    pub last_seen:          Instant,
    pub bytes_total:        u64,
    pub bytes_at_check:     u64,
    pub bitrate_bps:        u64,
    pub last_bitrate_check: Instant,
}

impl AvtpStreamStats {
    pub fn new(stream_id: [u8; 8], subtype: u8) -> Self {
        Self {
            stream_id,
            subtype,
            packets:            0,
            lost_frames:        0,
            last_seq:           None,
            last_seen:          Instant::now(),
            bytes_total:        0,
            bytes_at_check:     0,
            bitrate_bps:        0,
            last_bitrate_check: Instant::now(),
        }
    }

    pub fn update_bitrate(&mut self, frame_bytes: u64, now: Instant) {
        self.bytes_total += frame_bytes;
        let elapsed = self.last_bitrate_check.elapsed();
        if elapsed > Duration::from_secs(1) {
            let delta = self.bytes_total.saturating_sub(self.bytes_at_check);
            self.bitrate_bps = (delta as f64 * 8.0 / elapsed.as_secs_f64()) as u64;
            self.bytes_at_check = self.bytes_total;
            self.last_bitrate_check = now;
        }
    }

    /// Update sequence-loss tracking from the AVTP sequence_num byte (8-bit wrapping).
    /// Negative signed delta = reorder/reset, not loss (mirrors the RTP fix).
    pub fn update_seq(&mut self, seq: u8) {
        if let Some(last) = self.last_seq {
            let expected = last.wrapping_add(1);
            if seq != expected {
                let delta = seq.wrapping_sub(expected) as i8;
                if delta > 0 {
                    self.lost_frames += delta as u64;
                }
            }
        }
        self.last_seq = Some(seq);
    }

    pub fn loss_pct(&self) -> f64 {
        let total = self.packets + self.lost_frames;
        if total == 0 { 0.0 } else { 100.0 * self.lost_frames as f64 / total as f64 }
    }

    pub fn stream_id_str(&self) -> String {
        let id = &self.stream_id;
        format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:04x}",
            id[0], id[1], id[2], id[3], id[4], id[5],
            u16::from_be_bytes([id[6], id[7]]))
    }
}

// ═════════════════════──══════════════════──═════════════════════════
// SECTION 3 — TCP STREAM STATISTICS
// ═════════════════════──══════════════════──═════════════════════════

#[derive(Debug, Clone)]
pub struct TcpStreamStats {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
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
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Self {
        Self {
            src_ip,
            dst_ip,
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
        let elapsed = self.last_bitrate_check.elapsed();
        if elapsed > Duration::from_secs(1) {
            let bytes_delta = self.bytes.saturating_sub(self.bytes_at_check);
            self.bitrate_bps = (bytes_delta as f64 * 8.0 / elapsed.as_secs_f64()) as u64;
            self.bytes_at_check = self.bytes;
            self.last_bitrate_check = Instant::now();
        }
    }

    pub fn update_quality(&mut self) {
        if self.rst_packets > 0 || self.fin_packets >= 2 {
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
    pub multicast_packets: u64,
    pub unicast_packets: u64,
    pub tcp_retransmissions: u64,
    pub network_score: f64,
    // Congestion (ECN)
    pub ecn_congestion_marks: u64,
    // IGMP / snooping
    pub last_igmp_query: Option<Instant>,
    pub igmp_querier_ip: Option<std::net::Ipv4Addr>,
    pub igmp_querier_mac: Option<[u8; 6]>,
    pub igmp_query_interval_secs: Option<u64>, // computed from last two queries
    // Set by check_igmp_multiple_queriers when ≥2 distinct querier IPs seen this window.
    pub multiple_queriers_this_window: bool,
}

impl NetworkHealth {
    pub fn new() -> Self {
        Self {
            total_packets: 0,
            multicast_packets: 0,
            unicast_packets: 0,
            tcp_retransmissions: 0,
            network_score: 100.0,
            ecn_congestion_marks: 0,
            last_igmp_query: None,
            igmp_querier_ip: None,
            igmp_querier_mac: None,
            igmp_query_interval_secs: None,
            multiple_queriers_this_window: false,
        }
    }

    /// Seconds of querier silence after which the IGMP querier is considered gone.
    /// Per RFC 3376 the "Other Querier Present Interval" is ≈ 2× the query interval
    /// (Robustness 2 × QueryInterval + ½ QueryResponseInterval). We mirror that:
    /// 2× the observed interval plus a small margin, falling back to 260 s (2× the
    /// RFC default of 125 s + margin) until two queries have established the interval.
    /// A fixed 130 s threshold left only ~5 s of headroom on a default 125 s querier,
    /// so a single missed query produced a false "querier silent" alert.
    pub fn querier_silent_after_secs(&self) -> u64 {
        self.igmp_query_interval_secs.map(|i| i * 2 + 10).unwrap_or(260)
    }

    pub fn calculate_score(
        &mut self,
        streams: &std::collections::HashMap<String, StreamStats>,
        tcp_streams: &std::collections::HashMap<String, TcpStreamStats>,
        ptp_domains: &std::collections::HashMap<(u8, u8), PtpStats>,
        msrp_state: &std::collections::HashMap<[u8; 8], crate::protocols::MsrpDeclaration>,
        eee_ports: &std::collections::HashMap<(String, String), (u16, u16)>,
    ) {
        let mut score = 100.0;
        let mut has_active_multicast = false;

        for stats in streams.values() {
            if stats.is_multicast && stats.packets > 0 {
                has_active_multicast = true;
            }
            if stats.loss_pct() > 0.0 {
                score -= stats.loss_pct().min(10.0);
            }
            if stats.jitter_ms() > 20.0 {
                score -= 5.0;
            } else if stats.jitter_ms() > 10.0 {
                score -= 2.0;
            }
            if stats.ts_discontinuities_this_window > 0 {
                score -= 3.0 * (stats.ts_discontinuities_this_window as f64).min(5.0);
            }
            if stats.ssrc_changes > 0 {
                score -= 10.0 * (stats.ssrc_changes as f64).min(3.0);
            }
            if stats.last_packet_time.is_some_and(|t| t.elapsed() > Duration::from_secs(crate::protocols::STREAM_TIMEOUT_SECS)) {
                score -= 30.0;
            }
            if stats.gap_events >= 2 {
                score -= 10.0;  // repeated 50ms+ gaps in the current 5s window
            }
        }

        // ── TCP quality ───────────────────────────────────────────────────────
        for tcp_stats in tcp_streams.values() {
            match tcp_stats.stream_quality {
                StreamQuality::Healthy    => {}
                StreamQuality::Degrading  => score -= 5.0,
                StreamQuality::Critical   => score -= 15.0,
                StreamQuality::Terminated => score -= 25.0,
            }
        }
        score -= (self.tcp_retransmissions as f64 * 0.5).min(10.0);

        // ── QoS / DSCP (per-stream) ──────────────────────────────────────────
        // Each stream validates DSCP against protocol-appropriate expected values.
        // Any stream with violations counts as misconfigured.
        let dscp_bad = streams.values().filter(|s| s.dscp_violations > 0).count();
        if dscp_bad > 0 {
            score -= (dscp_bad as f64 * 5.0).min(20.0);
        }

        // ── Congestion (ECN Congestion Experienced marks) ─────────────────────
        // ECN=CE is set by routers when they are experiencing congestion mid-path.
        score -= (self.ecn_congestion_marks as f64 * 2.0).min(20.0);

        // ── IGMP / Snooping ───────────────────────────────────────────────────
        // Multicast snooping requires a live IGMP Querier. If multicast streams are
        // active but no Query has been seen within the "other querier present" window
        // (≈ 2× the query interval, see querier_silent_after_secs), managed switches
        // may start flooding multicast.
        if has_active_multicast {
            let silent_after = self.querier_silent_after_secs();
            match self.last_igmp_query {
                None => score -= 10.0,
                Some(t) if t.elapsed().as_secs() > silent_after => score -= 10.0,
                _ => {}
            }
        }
        if self.multiple_queriers_this_window {
            score -= 15.0;
        }

        // ── PTP clock health ──────────────────────────────────────────────────
        for ptp in ptp_domains.values() {
            if !ptp.clock_valid {
                if ptp.protocol_clock_lost {
                    score -= 25.0;  // grandmaster confirmed then lost
                } else if ptp.packets > 0 {
                    score -= 15.0;  // PTP traffic seen but no grandmaster yet
                }
            }
            if ptp.grandmaster_changes > 0 {
                score -= 10.0 * (ptp.grandmaster_changes as f64).min(3.0);
            }
        }

        // ── MSRP / AVB bandwidth reservations ────────────────────────────────
        for decl in msrp_state.values() {
            if matches!(decl.decl_type, crate::protocols::MsrpDeclType::TalkerFailed) {
                score -= 20.0;
            }
        }

        // ── EEE (Energy Efficient Ethernet) ──────────────────────────────────
        // EEE causes micro-bursting (packets held during sleep, released on wake-up)
        // directly threatening jitter-sensitive AV streams.
        score -= (eee_ports.len() as f64 * 15.0).min(30.0);

        self.network_score = score.max(0.0);
    }
}

// ═════════════════════──══════════════════──═════════════════════════
// SECTION 5 — PTP DOMAIN STATISTICS
// ═════════════════════──══════════════════──═════════════════════════

/// PTP stats for a specific (domain, version, protocol_kind) combination
/// Note: masters set is removed - use clock_id/grandmaster_id directly from PtpInfo
#[derive(Debug, Clone)]
pub struct PtpStats {
    pub domain:            u8,
    pub version:           u8,
    pub packets:           u64,
    pub protocol_kind:     Option<String>,           // Parent AV protocol (AES67, ST2110, Dante, AVB)
    pub last_seen:         Instant,
    pub last_grandmaster:  Option<String>,
    pub grandmaster_changes: u64,
    pub clock_valid:       bool,                     // Clock is currently present and valid
    pub timeout_secs:      u64,                      // Configurable timeout (default: 5s)
    pub last_quality:      Option<String>,
    pub last_offset_ns:    Option<i64>,
    pub last_path_delay_ns: Option<i64>,
    // Path-delay drift tracking: high spread = unstable link (EEE, half-duplex,
    // dodgy cable). High absolute value = extra hops. Cumulative since startup.
    pub min_path_delay_ns: Option<i64>,
    pub max_path_delay_ns: Option<i64>,
    // Protocol-specific tracking
    pub protocol_grandmaster_detected: bool,         // Was grandmaster detected for this protocol
    pub protocol_clock_lost:           bool,          // Was clock lost for this protocol
    pub protocol_changes_count:        u64,           // Grandmaster changes for this protocol
    pub last_src_ip:                   Option<std::net::Ipv4Addr>, // Source IP of last PTP packet (any sender in the domain)
    pub grandmaster_src_ip:            Option<std::net::Ipv4Addr>, // Source IP of the message that carried the grandmaster (Sync v1 / Announce v2) — the GM itself, not a follower
    pub last_clock_id:                 Option<String>,             // Source EUI-64 from most recent PTP message
    pub seen_sync:                     bool,                       // A real Sync (msgType 0x00) has arrived — distinguishes a clock from a Pdelay-only endpoint
    // PTPv1 Sync sender census — cleared each 5s window by CaptureState::reset_window().
    // Maps source IP → stratum (0=preferred master in Dante). If more than one entry
    // survives a full window, multiple devices competed to be master. Two entries with
    // stratum 0 is the "multiple preferred masters" misconfiguration.
    pub sync_senders_this_window:      HashMap<std::net::Ipv4Addr, u8>,
}

/// Side-effect-free signal emitted by `PtpStats::update` / `check_timeout`.
/// The caller (main loop) handles printing and logging.
#[derive(Debug, Clone, PartialEq)]
pub enum PtpEvent {
    GrandmasterDetected,
    GrandmasterChanged { from: String },
    ClockLost,
}

impl PtpStats {
    pub fn new(domain: u8, version: u8) -> Self {
        Self {
            domain,
            version,
            packets: 0,
            protocol_kind: None,
            last_seen: Instant::now(),
            last_grandmaster: None,
            grandmaster_changes: 0,
            clock_valid: false,
            timeout_secs: 5,
            last_quality: None,
            last_offset_ns: None,
            last_path_delay_ns: None,
            min_path_delay_ns: None,
            max_path_delay_ns: None,
            protocol_grandmaster_detected: false,
            protocol_clock_lost: false,
            protocol_changes_count: 0,
            last_src_ip: None,
            grandmaster_src_ip: None,
            last_clock_id: None,
            seen_sync: false,
            sync_senders_this_window: HashMap::new(),
        }
    }

    /// Update from a freshly-parsed PTP message.
    /// Returns an event when grandmaster state changes, so the caller can print/log it.
    pub fn update(&mut self, info: &crate::protocols::PtpInfo, protocol_kind: &Option<String>) -> Option<PtpEvent> {
        self.packets += 1;
        self.last_seen = Instant::now();
        self.protocol_kind = protocol_kind.as_ref().map(|s| s.to_string());
        if let Some(ip) = info.src_ip { self.last_src_ip = Some(ip); }
        if let Some(ref id) = info.clock_id { self.last_clock_id = Some(id.clone()); }

        let mut event = None;

        // ── Grandmaster detection (PTPv2: Announce 0x0B, PTPv1: Sync 0x00) ────
        // Fires whenever grandmaster_id is populated, regardless of message type.
        if let Some(gm) = &info.grandmaster_id {
            match &self.last_grandmaster {
                Some(current) if current == gm => {
                    // Same grandmaster — just keep the clock valid.
                }
                Some(current) => {
                    self.grandmaster_changes += 1;
                    self.protocol_changes_count += 1;
                    event = Some(PtpEvent::GrandmasterChanged { from: current.clone() });
                    self.last_grandmaster = Some(gm.clone());
                    self.protocol_grandmaster_detected = true;
                    // New grandmaster → path-delay history from the previous
                    // master is meaningless; reset so the spread metric reflects
                    // the new clock's stability.
                    self.min_path_delay_ns = None;
                    self.max_path_delay_ns = None;
                }
                None => {
                    event = Some(PtpEvent::GrandmasterDetected);
                    self.last_grandmaster = Some(gm.clone());
                    self.protocol_grandmaster_detected = true;
                }
            }
            self.clock_valid = true;
            // This message carried the grandmaster (Sync v1 / Announce v2), so its
            // source IP is the grandmaster itself — capture it here so a follower's
            // Delay_Req can't overwrite the IP we attribute to the GM.
            if let Some(ip) = info.src_ip { self.grandmaster_src_ip = Some(ip); }
            // Clock is back — clear the "lost" sticky flag so the report stops
            // showing the stale "grandmaster disappeared" alert after recovery.
            self.protocol_clock_lost = false;
            self.last_seen = Instant::now();
            if let Some(q) = &info.clock_quality {
                self.last_quality = Some(q.clone());
            }
        }

        // ── Sync/Follow_Up: update last_seen and offset for timeout/reporting ────
        if info.message_type == 0x00 || info.message_type == 0x08 {
            self.last_seen = Instant::now();
            self.last_offset_ns = info.correction_ns;
        }
        // A real Sync (0x00) marks an actual clock/grandmaster attempt — as opposed
        // to a node that only emits P_Delay_Req link-measurement traffic.
        if info.message_type == 0x00 {
            self.seen_sync = true;
            // Track every PTPv1 Sync sender this window so we can detect multiple
            // competing masters. stratum is only populated for PTPv1 Sync messages;
            // use 255 as a sentinel when unavailable.
            if info.version == crate::protocols::PTP_VERSION_V1
                && let Some(ip) = info.src_ip
            {
                self.sync_senders_this_window.insert(ip, info.stratum.unwrap_or(255));
            }
        }

        // Delay_Resp (0x09) and P_Delay_Resp (0x03) carry path_delay in correction field.
        if info.message_type == 0x09 || info.message_type == 0x03 {
            self.last_path_delay_ns = info.path_delay_ns;
            if let Some(d) = info.path_delay_ns {
                // Track absolute value — sign just indicates direction of measurement.
                let abs_d = d.abs();
                self.min_path_delay_ns = Some(self.min_path_delay_ns.map_or(abs_d, |m| m.min(abs_d)));
                self.max_path_delay_ns = Some(self.max_path_delay_ns.map_or(abs_d, |m| m.max(abs_d)));
            }
        }

        event
    }

    /// Call from the periodic report cycle (not from packet handlers).
    /// Returns `Some(ClockLost)` if the clock just transitioned to LOST this call.
    pub fn check_timeout(&mut self) -> Option<PtpEvent> {
        if self.clock_valid && self.last_seen.elapsed() > Duration::from_secs(self.timeout_secs) {
            self.clock_valid = false;
            self.protocol_clock_lost = true;
            self.last_grandmaster = None; // reset so re-detection fires DETECTED again
            Some(PtpEvent::ClockLost)
        } else {
            None
        }
    }
}
// ═════════════════════════════════════════════════════════════════
// TESTS
// ═════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn aes67() -> StreamStats {
        StreamStats::new("AES67", 48_000.0)
    }

    // ── Loss counter ─────────────────────────────────────────────────────────

    #[test]
    fn no_loss_on_sequential_packets() {
        let mut s = aes67();
        s.update(0, 0,  1, 100);
        s.update(1, 48, 1, 100);
        s.update(2, 96, 1, 100);
        assert_eq!(s.lost_packets, 0);
        assert_eq!(s.packets, 3);
    }

    #[test]
    fn loss_counted_on_seq_gap() {
        let mut s = aes67();
        s.update(0, 0,   1, 100);
        s.update(3, 144, 1, 100); // skipped seq 1 and 2 → 2 lost
        assert_eq!(s.lost_packets, 2);
    }

    #[test]
    fn no_loss_on_seq_number_wrap() {
        // 0xFFFF → 0x0000 is the normal 16-bit wrap, not a loss
        let mut s = aes67();
        s.update(0xFFFE, 0,  1, 100);
        s.update(0xFFFF, 48, 1, 100);
        s.update(0x0000, 96, 1, 100);
        assert_eq!(s.lost_packets, 0);
    }

    #[test]
    fn backward_seq_not_counted_as_loss() {
        // Out-of-order / reordered packet — should be ignored, not add 65000+ to lost_packets
        let mut s = aes67();
        s.update(10, 0, 1, 100);
        s.update(5,  0, 1, 100); // backward
        assert_eq!(s.lost_packets, 0);
    }

    #[test]
    fn backward_seq_counted_as_reorder() {
        // The packet is not lost — it arrived, just out of order. Track it
        // separately so high reorder rates surface (typical fingerprint of
        // per-packet ECMP/LAG load-balancing).
        let mut s = aes67();
        s.update(10, 0, 1, 100);
        s.update(5,  0, 1, 100);
        assert_eq!(s.reorders_this_window, 1);
        assert_eq!(s.lost_packets, 0);
    }

    #[test]
    fn lost_this_window_tracks_per_window_drops() {
        let mut s = aes67();
        s.update(0, 0,   1, 100);
        s.update(3, 144, 1, 100); // 2 lost in this window
        assert_eq!(s.lost_this_window, 2);
        assert_eq!(s.lost_packets,     2);
        // Caller (CaptureState::reset_window) zeros this_window after each report;
        // simulate that and verify cumulative loss survives.
        s.lost_this_window = 0;
        s.update(4, 192, 1, 100); // sequential — no new loss
        assert_eq!(s.lost_this_window, 0, "no new loss this window");
        assert_eq!(s.lost_packets,     2, "cumulative loss preserved");
    }

    // ── AVTP 8-bit sequence wrap ────────────────────────────────────────────

    fn avtp() -> AvtpStreamStats {
        AvtpStreamStats::new([0u8; 8], 0x00)
    }

    #[test]
    fn avtp_no_loss_on_seq_wrap() {
        // 255 → 0 is the normal 8-bit wrap, not a 255-packet loss
        let mut s = avtp();
        s.update_seq(254);
        s.update_seq(255);
        s.update_seq(0);
        s.update_seq(1);
        assert_eq!(s.lost_frames, 0);
    }

    #[test]
    fn avtp_backward_seq_not_counted_as_loss() {
        // Reorder within the 128-frame window: last=100, seq=90 → signed delta < 0, ignored
        let mut s = avtp();
        s.update_seq(100);
        s.update_seq(90);
        assert_eq!(s.lost_frames, 0);
    }

    #[test]
    fn avtp_gap_counted_as_loss() {
        // Skipped seq 1 and 2 → 2 frames lost
        let mut s = avtp();
        s.update_seq(0);
        s.update_seq(3);
        assert_eq!(s.lost_frames, 2);
    }

    #[test]
    fn avtp_gap_across_wrap_counted_as_loss() {
        // last=253, seq=1 → expected=254, delta=3 → 3 frames lost across the wrap
        let mut s = avtp();
        s.update_seq(253);
        s.update_seq(1);
        assert_eq!(s.lost_frames, 3);
    }

    // ── SSRC tracking ────────────────────────────────────────────────────────

    #[test]
    fn ssrc_change_increments_counter() {
        let mut s = aes67();
        s.update(0, 0,  0xAAAA, 100);
        s.update(1, 48, 0xBBBB, 100); // source changed
        assert_eq!(s.ssrc_changes, 1);
    }

    #[test]
    fn stable_ssrc_no_change_counted() {
        let mut s = aes67();
        s.update(0, 0,  0xAAAA, 100);
        s.update(1, 48, 0xAAAA, 100);
        s.update(2, 96, 0xAAAA, 100);
        assert_eq!(s.ssrc_changes, 0);
    }

    // ── clock-rate inference ─────────────────────────────────────────────────

    #[test]
    fn clock_rate_inferred_48k_1ms() {
        let mut s = aes67();
        assert!(!s.clock_hz_confirmed);
        // 9 packets: first establishes baseline, next 8 produce deltas of 48
        for i in 0..9u16 {
            s.update(i, i as u32 * 48, 1, 100);
        }
        assert!(s.clock_hz_confirmed, "should confirm 48 kHz from delta=48");
        assert!((s.clock_hz - 48000.0).abs() < 1.0);
        assert!((s.ptime_ms - 1.0).abs() < 0.01);
    }

    #[test]
    fn clock_rate_inferred_48k_4ms() {
        let mut s = aes67();
        for i in 0..9u16 {
            s.update(i, i as u32 * 192, 1, 100);
        }
        assert!(s.clock_hz_confirmed);
        assert!((s.clock_hz - 48000.0).abs() < 1.0);
        assert!((s.ptime_ms - 4.0).abs() < 0.01);
    }

    #[test]
    fn clock_rate_inferred_44k1_10ms() {
        let mut s = aes67();
        for i in 0..9u16 {
            s.update(i, i as u32 * 441, 1, 100);
        }
        assert!(s.clock_hz_confirmed);
        assert!((s.clock_hz - 44100.0).abs() < 1.0);
        assert!((s.ptime_ms - 10.0).abs() < 0.01);
    }

    #[test]
    fn clock_rate_not_inferred_from_unknown_delta() {
        let mut s = aes67();
        for i in 0..9u16 {
            s.update(i, i as u32 * 100, 1, 100); // 100 doesn't match any known pair
        }
        assert!(!s.clock_hz_confirmed, "should not confirm on unrecognised delta");
    }

    #[test]
    fn clock_rate_inferred_despite_one_noisy_sample() {
        let mut s = aes67();
        // 7 normal packets (delta=48), then 1 late arrival (delta=96), then normal again
        let ts_sequence = [0u32, 48, 96, 144, 192, 240, 288, 384, 432];
        for (i, &ts) in ts_sequence.iter().enumerate() {
            s.update(i as u16, ts, 1, 100);
        }
        // deltas collected: 48,48,48,48,48,48,96,48 → mode=48 → 48 kHz
        assert!(s.clock_hz_confirmed);
        assert!((s.clock_hz - 48000.0).abs() < 1.0);
    }

    #[test]
    fn clock_rate_inference_stops_after_sdp_confirms() {
        let mut s = aes67();
        s.clock_hz = 96000.0;
        s.ptime_ms = 1.0;
        s.clock_hz_confirmed = true; // SDP set this
        // Feed packets that would infer 48 kHz — inference should not run
        for i in 0..9u16 {
            s.update(i, i as u32 * 48, 1, 100);
        }
        assert!((s.clock_hz - 96000.0).abs() < 1.0, "SDP value should be preserved");
    }

    // ── loss_pct ─────────────────────────────────────────────────────────────

    #[test]
    fn loss_pct_zero_when_no_packets() {
        assert_eq!(aes67().loss_pct(), 0.0);
    }

    #[test]
    fn loss_pct_correct_with_gap() {
        let mut s = aes67();
        s.update(0, 0,   1, 100); // received
        s.update(3, 144, 1, 100); // received — but 2 lost
        // received=2, lost=2, total=4 → 50%
        let pct = s.loss_pct();
        assert!((pct - 50.0).abs() < 0.1, "expected 50%, got {:.1}%", pct);
    }

    // ── TS discontinuity sign fix ─────────────────────────────────────────────

    #[test]
    fn ts_discontinuity_not_fired_on_first_packet() {
        let mut s = aes67();
        s.clock_hz_confirmed = true;
        s.ptime_ms = 1.0;
        s.update(0, 0, 1, 100); // baseline — no previous ts to compare
        assert_eq!(s.ts_discontinuities, 0);
    }

    #[test]
    fn ts_discontinuity_fired_on_double_interval() {
        let mut s = aes67();
        s.clock_hz_confirmed = true;
        s.ptime_ms = 1.0; // expected diff = 48 samples
        s.update(0, 0,   1, 100);
        s.update(1, 96,  1, 100); // diff=96 = 2× expected → discontinuity
        assert_eq!(s.ts_discontinuities, 1);
    }

    #[test]
    fn ts_discontinuity_not_fired_on_normal_increment() {
        let mut s = aes67();
        s.clock_hz_confirmed = true;
        s.ptime_ms = 1.0;
        s.update(0, 0,  1, 100);
        s.update(1, 48, 1, 100); // exactly on time
        assert_eq!(s.ts_discontinuities, 0);
    }
}
