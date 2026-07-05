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
    // Packets received this window (not lost). Denominator for the window-scoped
    // loss percentage that drives the PacketLoss diagnostic's score deduction —
    // kept separate from the lifetime `packets` count so a stream that stops
    // losing recovers its score next Window instead of staying penalised forever
    // by its lifetime loss ratio.
    pub packets_this_window:            u64,
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
    // Transmitter Class verdict (Dante audio only) — Hardware / DVS / Via with a
    // confidence level, recomputed as signals accumulate. None for non-Dante and
    // until any signal is observed.
    pub transmitter:                    Option<crate::protocols::TransmitterVerdict>,
    // Recent inter-arrival times (ms), bounded ring. Drives the timing-regularity
    // signal for Transmitter Class: hardware/FPGA sources are metronomic (low
    // variance), general-purpose-OS software (DVS/Via) is scheduler-noisy.
    pub iat_samples:                    Vec<f64>,
    // DSCP observed on the first packet — set once, never reset. Distinguishes a
    // software source intentionally sending Best Effort (DSCP 0) from misconfigured
    // hardware (wrong non-zero DSCP); used to gate the Dante DSCP violation.
    pub observed_dscp:                  Option<u8>,
    // PCP (802.1p) violations in the current 5 s window. Reset each window.
    // AVB: mismatch against MSRP TalkerAdvertise declared priority.
    // AES67/ST2110: any non-6 value (advisory only).
    pub pcp_violations:                 u64,
    // Outermost VLAN tag PCP observed on the first tagged packet. Set once,
    // never reset. Used in the AES67/ST2110 PcpAdvisory diagnostic message.
    pub observed_pcp:                   Option<u8>,
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
            packets_this_window:            0,
            rtp_seen:                       false,
            min_ttl:                        None,
            ts_delta_samples:               Vec::new(),
            transmitter:                    None,
            iat_samples:                    Vec::new(),
            observed_dscp:                  None,
            pcp_violations:                 0,
            observed_pcp:                   None,
        }
    }

    /// Push an inter-arrival sample (ms) into the bounded ring used for the
    /// timing-regularity signal. Shared by RTP and ATP update paths.
    fn push_iat(&mut self, iat_ms: f64) {
        const MAX_IAT_SAMPLES: usize = 64;
        if iat_ms > 0.0 {
            self.iat_samples.push(iat_ms);
            if self.iat_samples.len() > MAX_IAT_SAMPLES {
                self.iat_samples.remove(0);
            }
        }
    }

    /// Timing-regularity signal for Transmitter Class. Returns `Some(true)` when
    /// the source is metronomic (low coefficient of variation → hardware/FPGA),
    /// `Some(false)` when clearly noisy (→ software), and `None` while there are
    /// too few samples or the regularity is ambiguous. Independent of QoS marking,
    /// so it disambiguates a re-marked hardware source from genuine software.
    pub fn timing_metronomic(&self) -> Option<bool> {
        const MIN_SAMPLES: usize = 16;
        if self.iat_samples.len() < MIN_SAMPLES { return None; }
        let n = self.iat_samples.len() as f64;
        let mean = self.iat_samples.iter().sum::<f64>() / n;
        if mean <= 0.0 { return None; }
        let var = self.iat_samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
        let cv = var.sqrt() / mean; // coefficient of variation
        if cv < 0.10 { Some(true) }        // metronomic — hardware
        else if cv > 0.30 { Some(false) }  // noisy — software
        else { None }                      // ambiguous
    }
    // Constructor with enhanced info — useful when SDP is available at stream start
    pub fn new_with_info(protocol: &str, clock_hz: f64, is_multicast: bool, dst_ip: Ipv4Addr, dst_port: u16) -> Self {
        let mut stats = Self::new(protocol, clock_hz);
        stats.is_multicast = is_multicast;
        stats.dst_ip = Some(dst_ip);
        stats.dst_port = dst_port;
        stats
    }

    /// Apply Session Announcement metadata to this stream. The single seam for
    /// SDP → StreamStats field transfer, called both when a stream is created
    /// and a cached SDP already matches its port, and retroactively from
    /// `handle_sap` for every existing stream a new announcement matches —
    /// previously these were two independently-maintained copies that had
    /// already drifted (one skipped `ptime_ms`, the other skipped `channels`).
    /// `sdp_name` is written once — re-announcements never overwrite a name
    /// already shown, avoiding display flicker on a session rename. Every
    /// technical field always re-applies, so a mid-run codec change (sample
    /// rate, ptime, payload type) takes effect immediately. Returns whether
    /// this call confirmed the clock rate, for protocol-specific fallbacks
    /// (e.g. ST2110 video is always clock-confirmed regardless of SDP).
    pub fn apply_sdp(&mut self, media: &crate::protocols::SdpMedia, session_name: &str) -> bool {
        if self.sdp_name.is_none() {
            self.sdp_name = Some(session_name.to_string());
        }
        self.sdp_rtpmap = Some(media.rtpmap.clone());
        if media.clock_hz > 0.0 {
            self.clock_hz = media.clock_hz;
            self.clock_hz_confirmed = true;
        }
        if media.ptime_ms > 0.0 { self.ptime_ms = media.ptime_ms; }
        if media.channels > 0   { self.channels = media.channels; }
        if let Some(pt) = media.payload_types.first().copied() {
            self.expected_pt = Some(pt);
        }
        media.clock_hz > 0.0
    }

    /// AES67/ST2110 PCP advisory: PCP=6 is the IEEE 802.1p priority recommended
    /// for these protocols on managed switches. Untagged frames (`pcp = None`)
    /// produce no violation. The single seam for this check — previously
    /// hand-copied identically in `handle_aes67` and `handle_st2110`. AVB's PCP
    /// mismatch is unrelated (scored against MSRP-declared priority on
    /// `AvtpStreamStats`, not this advisory) and Dante's PCP handling is
    /// DSCP/Transmitter-Class-driven — neither belongs in this function.
    pub fn apply_pcp_advisory(&mut self, pcp: Option<u8>) {
        if let Some(p) = pcp && p != 6 {
            self.pcp_violations += 1;
            self.observed_pcp.get_or_insert(p);
        }
    }

    /// `udp_payload_len`: actual length of UDP payload (without IP/UDP header),
    /// used for exact bitrate calculation.
    pub fn update(&mut self, seq: u16, rtp_ts: u32, ssrc: u32, udp_payload_len: usize) {
        self.packets += 1;
        self.packets_this_window += 1;
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

        // Timing-regularity sampling (Transmitter Class) — before last_arrival is
        // overwritten below.
        if let Some(last_time) = self.last_arrival {
            self.push_iat(now.duration_since(last_time).as_secs_f64() * 1000.0);
        }

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
        self.packets_this_window += 1;
        // Timing-regularity sampling (Transmitter Class) for ATP flows.
        if let Some(last) = self.last_arrival {
            self.push_iat(now.duration_since(last).as_secs_f64() * 1000.0);
        }
        self.last_arrival = Some(now);
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

    /// Loss percentage for the current Window only (denominator resets each
    /// Window, unlike `loss_pct`'s lifetime ratio). Drives the PacketLoss
    /// diagnostic's score deduction so a stream that stops losing recovers.
    fn loss_pct_this_window(&self) -> f64 {
        let total = self.packets_this_window + self.lost_this_window;
        if total == 0 { 0.0 } else { 100.0 * self.lost_this_window as f64 / total as f64 }
    }

    pub fn jitter_ms(&self) -> f64 { self.jitter * 1000.0 }

    /// Every per-stream Diagnostic for this Window, scored and informational
    /// alike. The single seam both `NetworkHealth::collect_penalties` (scoring)
    /// and the report's Streams section (rendering) read from — previously each
    /// re-evaluated the same StreamStats fields independently and the thresholds
    /// had already drifted (Dante's combined loss/jitter check used different
    /// numbers than the generic jitter penalty). Order matches the previous
    /// inline checks in report.rs so rendered output is unchanged.
    pub fn diagnostics(&self) -> Vec<StreamDiagnostic> {
        let mut d = Vec::new();

        if self.ts_discontinuities_this_window > 0 {
            d.push(StreamDiagnostic::TsDiscontinuity { window_count: self.ts_discontinuities_this_window });
        }
        if self.lost_this_window > 0 {
            d.push(StreamDiagnostic::PacketLoss {
                window_count: self.lost_this_window,
                window_pct:   self.loss_pct_this_window(),
                lifetime_pct: self.loss_pct(),
            });
        }
        if self.reorders_this_window > 0 {
            let total = (self.packets + self.lost_packets).max(1);
            let pct = 100.0 * self.reorders_this_window as f64 / total as f64;
            if pct > 1.0 {
                d.push(StreamDiagnostic::Reorder { window_count: self.reorders_this_window, pct });
            }
        }
        if self.dscp_violations > 0 {
            let expected = if self.protocol == "2110-20" { "EF (46), AF41 (34), or CS5 (40)" } else { "EF (46)" };
            d.push(StreamDiagnostic::DscpViolation { count: self.dscp_violations, expected });
        }
        if self.protocol == "Dante" && self.min_ttl.is_some_and(|t| t < 64) {
            d.push(StreamDiagnostic::TtlRouted { ttl: self.min_ttl.unwrap() });
        }
        if self.jitter_ms() > 10.0 {
            d.push(StreamDiagnostic::HighJitter { jitter_ms: self.jitter_ms() });
        }
        if self.protocol == "AES67" && self.jitter_ms() > 10.0 {
            d.push(StreamDiagnostic::Aes67PtpLockHint);
        }
        if self.protocol == "Dante" && (self.loss_pct() > 0.1 || self.jitter_ms() > 15.0) {
            d.push(StreamDiagnostic::DanteClockOrSubscriptionHint);
        }
        if self.ssrc_changes > 0 {
            d.push(StreamDiagnostic::SsrcChange { count: self.ssrc_changes });
        }
        if self.pt_mismatches > 0 {
            d.push(StreamDiagnostic::PtMismatch { count: self.pt_mismatches });
        }
        let expects_sdp = (self.protocol == "AES67" || self.protocol == "Dante" || self.protocol.starts_with("2110-"))
            && self.rtp_seen;
        if expects_sdp && !self.clock_hz_confirmed && self.packets > 10 {
            d.push(StreamDiagnostic::NotAnnounced);
        }
        if self.protocol == "2110-??" {
            d.push(StreamDiagnostic::UnknownStreamType);
        }
        if self.gap_events >= 2 {
            d.push(StreamDiagnostic::SignalGap { window_count: self.gap_events, max_iat_ms: self.max_iat_ms });
        }
        if let Some(last_time) = self.last_packet_time
            && last_time.elapsed() > Duration::from_secs(crate::protocols::STREAM_TIMEOUT_SECS)
        {
            d.push(StreamDiagnostic::Dead { silent_secs: last_time.elapsed().as_secs_f64() });
        }
        // AVB PCP mismatch is scored/rendered straight off `AvtpStreamStats` (see
        // `NetworkHealth::collect_penalties` and `report.rs`'s AVTP render block) —
        // no `StreamStats` entry with `protocol == "AVB"` is ever constructed, so
        // this diagnostic only applies to the AES67/ST2110 advisory.
        if self.pcp_violations > 0 && (self.protocol == "AES67" || self.protocol.starts_with("2110-")) {
            d.push(StreamDiagnostic::PcpAdvisory { observed: self.observed_pcp.unwrap_or(0) });
        }

        d
    }
}

/// A persistent, per-stream condition re-evaluated every Window (see CONTEXT.md
/// "Diagnostic"). Some variants carry a Health Score deduction (`deduction() >
/// 0.0`) and are aggregated by `NetworkHealth::collect_penalties`; others are
/// informational only and exist solely to render under their stream in the
/// report. One source of truth for both consumers — see `StreamStats::diagnostics`.
#[derive(Debug, Clone, Copy)]
pub enum StreamDiagnostic {
    PacketLoss { window_count: u64, window_pct: f64, lifetime_pct: f64 },
    HighJitter { jitter_ms: f64 },
    TsDiscontinuity { window_count: u64 },
    SsrcChange { count: u64 },
    SignalGap { window_count: u64, max_iat_ms: f64 },
    DscpViolation { count: u64, expected: &'static str },
    Dead { silent_secs: f64 },
    Reorder { window_count: u64, pct: f64 },
    TtlRouted { ttl: u8 },
    PtMismatch { count: u64 },
    NotAnnounced,
    UnknownStreamType,
    Aes67PtpLockHint,
    DanteClockOrSubscriptionHint,
    // AES67/ST2110: frame not marked PCP 6. Advisory only — no score penalty.
    // (AVB's PCP mismatch is scored/rendered off AvtpStreamStats, not StreamStats
    // — see NetworkHealth::collect_penalties and report.rs's AVTP render block.)
    PcpAdvisory { observed: u8 },
}

impl StreamDiagnostic {
    /// Health Score deduction this single stream's instance of the Diagnostic
    /// contributes (already capped where the original per-stream cap applied —
    /// e.g. loss at 10.0, ts-discontinuity count at 5, ssrc count at 3). Any
    /// aggregate-level cap across all affected streams (currently DSCP, at 20)
    /// is applied by the caller, not here.
    pub fn deduction(&self) -> f64 {
        match self {
            StreamDiagnostic::PacketLoss { window_pct, .. } => window_pct.min(10.0),
            StreamDiagnostic::HighJitter { jitter_ms } => if *jitter_ms > 20.0 { 5.0 } else { 2.0 },
            StreamDiagnostic::TsDiscontinuity { window_count } => 3.0 * (*window_count as f64).min(5.0),
            StreamDiagnostic::SsrcChange { count } => 10.0 * (*count as f64).min(3.0),
            StreamDiagnostic::SignalGap { .. } => 10.0,
            StreamDiagnostic::DscpViolation { .. } => 5.0,
            StreamDiagnostic::Dead { .. } => 30.0,
            StreamDiagnostic::Reorder { .. }
            | StreamDiagnostic::TtlRouted { .. }
            | StreamDiagnostic::PtMismatch { .. }
            | StreamDiagnostic::NotAnnounced
            | StreamDiagnostic::UnknownStreamType
            | StreamDiagnostic::Aes67PtpLockHint
            | StreamDiagnostic::DanteClockOrSubscriptionHint
            | StreamDiagnostic::PcpAdvisory { .. } => 0.0,
        }
    }

    /// `true` for the one variant rendered in red (💀) rather than yellow (⚠).
    pub fn is_critical(&self) -> bool { matches!(self, StreamDiagnostic::Dead { .. }) }

    /// Short human-facing category name — the one place a Diagnostic's name is
    /// written. `NetworkHealth::collect_penalties`'s aggregate Health Summary
    /// bullet builds from this instead of independently re-authoring the same
    /// name; `message()`'s per-stream prose is free to phrase it differently
    /// but both trace back to the same variant here, not two hand-written
    /// strings that can silently drift apart.
    pub fn category(&self) -> &'static str {
        match self {
            StreamDiagnostic::PacketLoss { .. } => "packet loss",
            StreamDiagnostic::HighJitter { .. } => "high jitter",
            StreamDiagnostic::TsDiscontinuity { .. } => "timestamp discontinuities",
            StreamDiagnostic::SsrcChange { .. } => "SSRC changes",
            StreamDiagnostic::SignalGap { .. } => "signal gaps",
            StreamDiagnostic::DscpViolation { .. } => "incorrect DSCP",
            StreamDiagnostic::Dead { .. } => "silent",
            StreamDiagnostic::Reorder { .. } => "packet reorder",
            StreamDiagnostic::TtlRouted { .. } => "routed traffic (TTL)",
            StreamDiagnostic::PtMismatch { .. } => "payload type mismatch",
            StreamDiagnostic::NotAnnounced => "no SAP announcement",
            StreamDiagnostic::UnknownStreamType => "unknown stream type",
            StreamDiagnostic::Aes67PtpLockHint => "PTP lock",
            StreamDiagnostic::DanteClockOrSubscriptionHint => "clock or subscription issue",
            StreamDiagnostic::PcpAdvisory { .. } => "PCP advisory",
        }
    }

    /// Full report line, including leading indent and glyph — matches the
    /// pre-deepening report.rs text exactly so output is unchanged. `None` for
    /// `HighJitter` in the 10–20ms band: scored (2.0, see `deduction`) but, as
    /// before this deepening, silent in the per-stream Streams section — only
    /// the aggregate Health Summary bullet surfaces it.
    pub fn message(&self) -> Option<String> {
        let s = match self {
            StreamDiagnostic::TsDiscontinuity { window_count } => format!(
                "    ⚠  Audio glitch risk — timing discontinuity detected ({} in last 5s)", window_count
            ),
            StreamDiagnostic::PacketLoss { window_count, lifetime_pct, .. } => format!(
                "    ⚠  Packet loss detected ({} in last 5s, {:.2}% cumulative)", window_count, lifetime_pct
            ),
            StreamDiagnostic::Reorder { window_count, pct } => format!(
                "    ⚠  Packet reorder {:.1}% ({} in last 5s) — possible per-packet load-balancing", pct, window_count
            ),
            StreamDiagnostic::DscpViolation { count, expected } => format!(
                "    ⚠  QoS: {} packet(s) not marked {} — may be deprioritised by switches", count, expected
            ),
            StreamDiagnostic::TtlRouted { ttl } => format!(
                "    ⚠  Dante traffic routed (TTL {}) — Dante is L2-only; a router is in the path", ttl
            ),
            StreamDiagnostic::HighJitter { jitter_ms } if *jitter_ms > 20.0 =>
                "    ⚠  High jitter — stream quality at risk".to_string(),
            StreamDiagnostic::HighJitter { .. } => return None,
            StreamDiagnostic::Aes67PtpLockHint =>
                "    ⚠  AES67 timing issue — check PTP lock".to_string(),
            StreamDiagnostic::DanteClockOrSubscriptionHint =>
                "    ⚠  Dante clock or subscription issue".to_string(),
            StreamDiagnostic::SsrcChange { count } => format!(
                "    ⚠  Source interrupted and reconnected ({} time(s))", count
            ),
            StreamDiagnostic::PtMismatch { count } => format!(
                "    ⚠  RTP payload type mismatch ({} packet(s)) — encoder/SDP misconfiguration", count
            ),
            StreamDiagnostic::NotAnnounced =>
                "    ⚠  Stream not announced (no SAP) — audio glitch detection unavailable".to_string(),
            StreamDiagnostic::UnknownStreamType =>
                "    ⚠  Stream type unknown — SDP required to classify as video/audio/ancillary".to_string(),
            StreamDiagnostic::SignalGap { window_count, max_iat_ms } => format!(
                "    ⚠  Signal gap detected ({} in last 5s, worst {:.1} ms) — stream interrupted", window_count, max_iat_ms
            ),
            StreamDiagnostic::Dead { silent_secs } => format!(
                "    💀 No signal for {:.0}s", silent_secs
            ),
            StreamDiagnostic::PcpAdvisory { observed } =>
                format!("    ⚠  Stream uses PCP {} — PCP 6 recommended for AES67/ST2110 on managed switches", observed),
        };
        Some(s)
    }
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
    // PCP (802.1p) vs. MSRP TalkerAdvertise priority — per stream_id, never shared
    // across other AVTP streams of the same subtype label. See CLAUDE.md AVB PCP note.
    pub pcp_violations:     u64,
    pub observed_pcp:       Option<u8>,
    pub msrp_declared_pcp:  Option<u8>,
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
            pcp_violations:     0,
            observed_pcp:       None,
            msrp_declared_pcp:  None,
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

/// A single factor deducting from the Health Score this Window.
/// `PerStream` represents a stream-level issue (aggregated across all affected streams);
/// `Infrastructure` represents a network or protocol infrastructure issue.
pub enum ScorePenalty {
    PerStream    { total_deduction: f64, bullet: String },
    Infrastructure { deduction: f64,    bullet: String },
}

impl ScorePenalty {
    pub fn deduction(&self) -> f64 {
        match self {
            ScorePenalty::PerStream    { total_deduction, .. } => *total_deduction,
            ScorePenalty::Infrastructure { deduction, .. }     => *deduction,
        }
    }
    pub fn into_bullet(self) -> String {
        match self {
            ScorePenalty::PerStream    { bullet, .. } => bullet,
            ScorePenalty::Infrastructure { bullet, .. } => bullet,
        }
    }
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

    /// Count an ECN Congestion-Experienced mark (ECN field value 3 — RFC 3168).
    /// The single seam for this check — previously hand-copied identically in
    /// `handle_aes67`, `handle_st2110`, and `handle_dante`.
    pub fn record_ecn_mark_if_congested(&mut self, ecn: u8) {
        if ecn == 3 {
            self.ecn_congestion_marks += 1;
        }
    }

    /// Collect every active penalty this Window. Both `calculate_score` and
    /// `build_health_summary` are thin consumers of this function, so the
    /// score and the summary are always derived from the same source of truth.
    pub fn collect_penalties(
        &self,
        streams:     &HashMap<String, StreamStats>,
        tcp_streams: &HashMap<String, TcpStreamStats>,
        ptp_domains: &HashMap<(u8, u8), PtpStats>,
        msrp_state:  &HashMap<[u8; 8], crate::protocols::MsrpDeclaration>,
        eee_ports:   &HashMap<(String, String), (u16, u16)>,
        avtp_streams: &HashMap<[u8; 8], AvtpStreamStats>,
    ) -> Vec<ScorePenalty> {
        let mut p: Vec<ScorePenalty> = Vec::new();

        // ── Per-stream penalties (aggregated by category) ─────────────────────
        // Sourced from StreamStats::diagnostics() — the same per-stream evaluation
        // the Streams section renders from, so score and inline alert text can no
        // longer drift apart the way the old, independently-authored copies did.
        let mut has_multicast       = false;
        let mut loss_count          = 0usize; let mut loss_total          = 0.0f64; let mut loss_category   = "";
        let mut jitter_count        = 0usize; let mut jitter_total        = 0.0f64; let mut jitter_category = "";
        let mut tsd_count           = 0usize; let mut tsd_total           = 0.0f64; let mut tsd_category    = "";
        let mut ssrc_count          = 0usize; let mut ssrc_total          = 0.0f64; let mut ssrc_category   = "";
        let mut dead_count          = 0usize; let mut dead_category      = "";
        let mut gap_count           = 0usize; let mut gap_category       = "";
        let mut dscp_count          = 0usize; let mut dscp_category      = "";

        for s in streams.values() {
            if s.is_multicast && s.packets > 0 { has_multicast = true; }

            for diag in s.diagnostics() {
                match diag {
                    StreamDiagnostic::PacketLoss { .. }      => { loss_count   += 1; loss_total   += diag.deduction(); loss_category   = diag.category(); }
                    StreamDiagnostic::HighJitter { .. }      => { jitter_count += 1; jitter_total += diag.deduction(); jitter_category = diag.category(); }
                    StreamDiagnostic::TsDiscontinuity { .. } => { tsd_count    += 1; tsd_total    += diag.deduction(); tsd_category    = diag.category(); }
                    StreamDiagnostic::SsrcChange { .. }      => { ssrc_count   += 1; ssrc_total   += diag.deduction(); ssrc_category   = diag.category(); }
                    StreamDiagnostic::Dead { .. }            => { dead_count   += 1; dead_category = diag.category(); }
                    StreamDiagnostic::SignalGap { .. }       => { gap_count    += 1; gap_category  = diag.category(); }
                    StreamDiagnostic::DscpViolation { .. }   => { dscp_count   += 1; dscp_category = diag.category(); }
                    // Informational-only: deduction() is 0.0, no score/bullet contribution.
                    // Listed explicitly (no wildcard) so a future StreamDiagnostic variant
                    // with a nonzero deduction() can't compile in silently unhandled here.
                    StreamDiagnostic::Reorder { .. }
                    | StreamDiagnostic::TtlRouted { .. }
                    | StreamDiagnostic::PtMismatch { .. }
                    | StreamDiagnostic::NotAnnounced
                    | StreamDiagnostic::UnknownStreamType
                    | StreamDiagnostic::Aes67PtpLockHint
                    | StreamDiagnostic::DanteClockOrSubscriptionHint
                    | StreamDiagnostic::PcpAdvisory { .. } => {}
                }
            }
        }

        macro_rules! per_stream {
            ($count:expr, $deduction:expr, $bullet:expr) => {
                if $count > 0 {
                    p.push(ScorePenalty::PerStream {
                        total_deduction: $deduction,
                        bullet: $bullet,
                    });
                }
            };
        }
        // Bullet text is built from `StreamDiagnostic::category()` — the same
        // name `message()` traces back to — rather than an independently
        // hand-written string per category, which used to carry different
        // wording than the per-stream alert (see `category()`'s doc comment).
        per_stream!(loss_count,   loss_total,              format!("⚠  {} stream(s) with {}", loss_count, loss_category));
        per_stream!(jitter_count, jitter_total,             format!("⚠  {} stream(s) with {}", jitter_count, jitter_category));
        per_stream!(tsd_count,    tsd_total,                format!("⚠  {} stream(s) with {}", tsd_count, tsd_category));
        per_stream!(ssrc_count,   ssrc_total,                format!("⚠  {} stream(s) with {}", ssrc_count, ssrc_category));
        per_stream!(dead_count,   dead_count as f64 * 30.0, format!("⚠  {} dead stream(s) ({})", dead_count, dead_category));
        per_stream!(gap_count,    gap_count  as f64 * 10.0, format!("⚠  {} stream(s) with {}", gap_count, gap_category));
        per_stream!(dscp_count,   (dscp_count as f64 * 5.0).min(20.0), format!("⚠  {} stream(s) with {}", dscp_count, dscp_category));

        // ── AVB PCP mismatch (per stream_id, on AvtpStreamStats) ───────────────
        // AVB media is tracked on `avtp_streams`, not `streams` — this is the one
        // per-stream penalty category collect_penalties sources from a map other
        // than `streams`/`tcp_streams`. AES67/ST2110 PcpAdvisory is informational
        // only (deduction 0.0) and already flows through the `streams` loop above.
        // Not StreamDiagnostic-derived (AvtpStreamStats has no diagnostics() of its
        // own), so it keeps its own literal bullet text rather than category().
        let pcp_count = avtp_streams.values().filter(|s| s.pcp_violations > 0).count();
        per_stream!(pcp_count, pcp_count as f64 * 15.0, format!("⚠  {} AVB stream(s) with PCP mismatch", pcp_count));

        // ── TCP quality ───────────────────────────────────────────────────────
        let mut tcp_count = 0usize; let mut tcp_total = 0.0f64;
        for t in tcp_streams.values() {
            let d = match t.stream_quality {
                StreamQuality::Healthy    => 0.0,
                StreamQuality::Degrading  => 5.0,
                StreamQuality::Critical   => 15.0,
                StreamQuality::Terminated => 25.0,
            };
            if d > 0.0 { tcp_count += 1; tcp_total += d; }
        }
        per_stream!(tcp_count, tcp_total, format!("⚠  {} TCP stream(s) with degraded quality", tcp_count));

        let retrans = (self.tcp_retransmissions as f64 * 0.5).min(10.0);
        if retrans > 0.0 {
            p.push(ScorePenalty::Infrastructure {
                deduction: retrans,
                bullet: format!("⚠  TCP retransmissions ({})", self.tcp_retransmissions),
            });
        }

        // ── Congestion (ECN) ──────────────────────────────────────────────────
        let ecn = (self.ecn_congestion_marks as f64 * 2.0).min(20.0);
        if ecn > 0.0 {
            p.push(ScorePenalty::Infrastructure {
                deduction: ecn,
                bullet: format!("⚠  {} ECN congestion mark(s)", self.ecn_congestion_marks),
            });
        }

        // ── IGMP querier ──────────────────────────────────────────────────────
        if has_multicast {
            let absent = match self.last_igmp_query {
                None    => true,
                Some(t) => t.elapsed().as_secs() > self.querier_silent_after_secs(),
            };
            if absent {
                p.push(ScorePenalty::Infrastructure {
                    deduction: 10.0,
                    bullet: "⚠  IGMP querier absent — multicast may flood".to_string(),
                });
            }
        }
        if self.multiple_queriers_this_window {
            p.push(ScorePenalty::Infrastructure {
                deduction: 15.0,
                bullet: "⚠  Multiple IGMP queriers on segment".to_string(),
            });
        }

        // ── PTP clock health (deterministic order) ────────────────────────────
        let mut keys: Vec<&(u8, u8)> = ptp_domains.keys().collect();
        keys.sort();
        for key in keys {
            let ptp = &ptp_domains[key];
            if !ptp.clock_valid {
                if ptp.protocol_clock_lost {
                    p.push(ScorePenalty::Infrastructure {
                        deduction: 25.0,
                        bullet: format!("⚠  Clock Source lost (PTP domain {})", key.0),
                    });
                } else if ptp.packets > 0 {
                    p.push(ScorePenalty::Infrastructure {
                        deduction: 15.0,
                        bullet: format!("⚠  PTP traffic but no grandmaster (domain {})", key.0),
                    });
                }
            }
            if ptp.grandmaster_changes > 0 {
                p.push(ScorePenalty::Infrastructure {
                    deduction: 10.0 * (ptp.grandmaster_changes as f64).min(3.0),
                    bullet: format!("⚠  Grandmaster changed (PTP domain {})", key.0),
                });
            }
        }

        // ── MSRP / AVB bandwidth reservations ────────────────────────────────
        let msrp_failed = msrp_state.values()
            .filter(|d| matches!(d.decl_type, crate::protocols::MsrpDeclType::TalkerFailed))
            .count();
        if msrp_failed > 0 {
            p.push(ScorePenalty::Infrastructure {
                deduction: msrp_failed as f64 * 20.0,
                bullet: format!("⚠  {} AVB reservation failure(s)", msrp_failed),
            });
        }

        // ── EEE ───────────────────────────────────────────────────────────────
        let eee = (eee_ports.len() as f64 * 15.0).min(30.0);
        if eee > 0.0 {
            p.push(ScorePenalty::Infrastructure {
                deduction: eee,
                bullet: format!("⚠  EEE active on {} switch port(s)", eee_ports.len()),
            });
        }

        p
    }

    pub fn calculate_score(
        &mut self,
        streams: &std::collections::HashMap<String, StreamStats>,
        tcp_streams: &std::collections::HashMap<String, TcpStreamStats>,
        ptp_domains: &std::collections::HashMap<(u8, u8), PtpStats>,
        msrp_state: &std::collections::HashMap<[u8; 8], crate::protocols::MsrpDeclaration>,
        eee_ports: &std::collections::HashMap<(String, String), (u16, u16)>,
        avtp_streams: &std::collections::HashMap<[u8; 8], AvtpStreamStats>,
    ) {
        // Score = 100 − Σ penalties. The penalty table lives once in
        // `collect_penalties`; this is a thin consumer of it.
        let total: f64 = self
            .collect_penalties(streams, tcp_streams, ptp_domains, msrp_state, eee_ports, avtp_streams)
            .iter()
            .map(|p| p.deduction())
            .sum();
        self.network_score = (100.0 - total).max(0.0);
    }

    /// Build the Health Summary: one bullet per factor deducting from the Health
    /// Score this Window. Mirrors `calculate_score` exactly — every score penalty
    /// produces a bullet and every bullet corresponds to a penalty (the CONTEXT.md
    /// "Health Summary" biconditional). Pure: no IO, no rendering.
    ///
    /// The biconditional is now structural, not conventional: this is the same
    /// `collect_penalties` table that `calculate_score` sums, mapped to its bullets.
    /// Stream-level issues are collapsed by category across all affected streams
    /// (`⚠ N stream(s) with <issue>`); infrastructure issues each get their own
    /// bullet. Pcap kernel/interface drops are deliberately excluded — they are a
    /// tool limitation, not a network fault, and live in Network Status only.
    /// Factors that carry no score penalty (PAUSE/PFC frames, AES67/ST2110 PCP
    /// advisories) likewise produce no bullet.
    pub fn build_health_summary(
        &self,
        streams: &HashMap<String, StreamStats>,
        tcp_streams: &HashMap<String, TcpStreamStats>,
        ptp_domains: &HashMap<(u8, u8), PtpStats>,
        msrp_state: &HashMap<[u8; 8], crate::protocols::MsrpDeclaration>,
        eee_ports: &HashMap<(String, String), (u16, u16)>,
        avtp_streams: &HashMap<[u8; 8], AvtpStreamStats>,
    ) -> Vec<String> {
        self.collect_penalties(streams, tcp_streams, ptp_domains, msrp_state, eee_ports, avtp_streams)
            .into_iter()
            .map(ScorePenalty::into_bullet)
            .collect()
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

    /// `true` for an IP-network PTP domain (AES67/ST2110/Dante, PTPv1 or PTPv2
    /// over UDP) — i.e. NOT an L2 gPTP (AVB) domain. A domain with no
    /// `protocol_kind` set yet counts as IP-PTP, matching the historical
    /// `!= Some("AVB")` behavior. The single named predicate for a distinction
    /// previously inlined four times across `missing_ptp_clocks` and
    /// `check_clock_dropout_correlation`.
    pub fn is_ip_ptp_domain(&self) -> bool {
        self.protocol_kind.as_deref() != Some("AVB")
    }

    /// `true` for an L2 gPTP (AVB) domain.
    pub fn is_gptp_domain(&self) -> bool {
        self.protocol_kind.as_deref() == Some("AVB")
    }
}

/// `true` when the path-delay spread (max − min, both nanoseconds) indicates an
/// unstable link — EEE, half-duplex, or a dodgy cable. The single seam for this
/// threshold, extracted out of `report.rs::render_clock_sources` so tuning it
/// (an open TODO.md field-verification item) is a unit test, not a full-report
/// string match.
pub fn path_delay_spread_unstable(min_ns: i64, max_ns: i64) -> bool {
    (max_ns - min_ns) > 10_000
}

/// `true` when the absolute path delay indicates too many hops between this
/// node and the grandmaster.
pub fn path_delay_too_many_hops(max_ns: i64) -> bool {
    max_ns > 1_000_000
}

/// Rough hop-count estimate: ~5µs per gigabit switch hop. Never negative;
/// suppressed (0) below one hop's worth of delay.
pub fn path_delay_hop_estimate(min_ns: i64) -> u32 {
    (min_ns / 5_000).max(0) as u32
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

    // ── StreamDiagnostic ───────────────────────────────────────────────────────

    #[test]
    fn diagnostics_empty_for_clean_stream() {
        let mut s = aes67();
        s.update(0, 0,  1, 100);
        s.update(1, 48, 1, 100);
        assert!(s.diagnostics().is_empty());
    }

    #[test]
    fn diagnostics_packet_loss_scores_window_pct_not_lifetime() {
        let mut s = aes67();
        s.packets = 9_990;
        s.lost_packets = 10; // heavy lifetime loss from a past window
        s.packets_this_window = 100;
        s.lost_this_window = 0; // but nothing lost in the current window
        assert!(
            s.diagnostics().is_empty(),
            "a stream that recovered this window must not still be flagged"
        );
    }

    #[test]
    fn diagnostics_packet_loss_fires_on_window_delta() {
        let mut s = aes67();
        s.packets = 100;
        s.lost_packets = 2;
        s.packets_this_window = 98;
        s.lost_this_window = 2;
        let diags = s.diagnostics();
        let loss = diags.iter().find(|d| matches!(d, StreamDiagnostic::PacketLoss { .. }));
        assert!(loss.is_some(), "got {diags:?}");
        assert!(loss.unwrap().deduction() > 0.0);
        assert!(loss.unwrap().message().unwrap().contains("2 in last 5s"));
    }

    #[test]
    fn diagnostics_jitter_10_to_20ms_scores_silently() {
        // 2.0 deduction (Health Summary bullet) but no per-stream report line —
        // matches pre-deepening behaviour where this band had no inline alert.
        let mut s = aes67();
        s.jitter = 0.015; // 15 ms
        let diags = s.diagnostics();
        let jit = diags.iter().find(|d| matches!(d, StreamDiagnostic::HighJitter { .. })).unwrap();
        assert_eq!(jit.deduction(), 2.0);
        assert!(jit.message().is_none());
    }

    #[test]
    fn diagnostics_jitter_above_20ms_renders_and_scores() {
        let mut s = aes67();
        s.jitter = 0.025; // 25 ms
        let diags = s.diagnostics();
        let jit = diags.iter().find(|d| matches!(d, StreamDiagnostic::HighJitter { .. })).unwrap();
        assert_eq!(jit.deduction(), 5.0);
        assert!(jit.message().unwrap().contains("High jitter"));
    }

    #[test]
    fn diagnostics_aes67_jitter_hint_is_informational() {
        let mut s = aes67();
        s.jitter = 0.012; // 12 ms — above AES67's 10ms hint, below generic 20ms
        let diags = s.diagnostics();
        let hint = diags.iter().find(|d| matches!(d, StreamDiagnostic::Aes67PtpLockHint)).unwrap();
        assert_eq!(hint.deduction(), 0.0, "the hint itself carries no score weight");
        assert!(hint.message().unwrap().contains("check PTP lock"));
    }

    #[test]
    fn diagnostics_dead_stream_is_critical() {
        let mut s = aes67();
        s.last_packet_time = Some(Instant::now() - Duration::from_secs(crate::protocols::STREAM_TIMEOUT_SECS + 1));
        let diags = s.diagnostics();
        let dead = diags.iter().find(|d| matches!(d, StreamDiagnostic::Dead { .. })).unwrap();
        assert!(dead.is_critical());
        assert_eq!(dead.deduction(), 30.0);
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

    // ── build_health_summary ─────────────────────────────────────────────────
    fn empty_streams() -> HashMap<String, StreamStats> { HashMap::new() }
    fn empty_tcp() -> HashMap<String, TcpStreamStats> { HashMap::new() }
    fn empty_ptp() -> HashMap<(u8, u8), PtpStats> { HashMap::new() }
    fn empty_msrp() -> HashMap<[u8; 8], crate::protocols::MsrpDeclaration> { HashMap::new() }
    fn empty_eee() -> HashMap<(String, String), (u16, u16)> { HashMap::new() }
    fn empty_avtp() -> HashMap<[u8; 8], AvtpStreamStats> { HashMap::new() }

    /// A stream that has received `packets` packets and `lost` losses, so
    /// loss_pct() and liveness are controllable without driving update().
    fn live_stream(lost: u64) -> StreamStats {
        let mut s = aes67();
        s.packets = 100;
        s.lost_packets = lost;
        // Loss scoring is window-scoped (see StreamStats::diagnostics) — a
        // "currently lossy" fixture needs the loss to have happened in the
        // window under test, not just in some unspecified past window.
        s.packets_this_window = 100;
        s.lost_this_window = lost;
        s.last_packet_time = Some(Instant::now());
        s
    }

    #[test]
    fn summary_empty_when_all_healthy() {
        let health = NetworkHealth::new();
        let mut streams = empty_streams();
        streams.insert("s1".into(), live_stream(0));
        let out = health.build_health_summary(&streams, &empty_tcp(), &empty_ptp(), &empty_msrp(), &empty_eee(), &empty_avtp());
        assert!(out.is_empty(), "healthy state must yield no bullets, got {out:?}");
    }

    #[test]
    fn summary_single_loss_one_bullet() {
        let health = NetworkHealth::new();
        let mut streams = empty_streams();
        streams.insert("s1".into(), live_stream(5));
        let out = health.build_health_summary(&streams, &empty_tcp(), &empty_ptp(), &empty_msrp(), &empty_eee(), &empty_avtp());
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("1 stream(s) with packet loss"), "got {out:?}");
    }

    #[test]
    fn summary_collapses_same_issue_across_streams() {
        let health = NetworkHealth::new();
        let mut streams = empty_streams();
        streams.insert("s1".into(), live_stream(5));
        streams.insert("s2".into(), live_stream(3));
        streams.insert("s3".into(), live_stream(1));
        let out = health.build_health_summary(&streams, &empty_tcp(), &empty_ptp(), &empty_msrp(), &empty_eee(), &empty_avtp());
        assert_eq!(out.len(), 1, "three lossy streams collapse to one bullet, got {out:?}");
        assert!(out[0].contains("3 stream(s) with packet loss"));
    }

    #[test]
    fn summary_different_issues_one_bullet_each() {
        let health = NetworkHealth::new();
        let mut streams = empty_streams();

        let mut lossy = live_stream(5);
        lossy.dscp_violations = 2;                 // also a DSCP violation
        streams.insert("s1".into(), lossy);

        let mut jittery = live_stream(0);
        jittery.jitter = 0.015;                    // 15 ms > 10 ms threshold
        streams.insert("s2".into(), jittery);

        let out = health.build_health_summary(&streams, &empty_tcp(), &empty_ptp(), &empty_msrp(), &empty_eee(), &empty_avtp());
        // loss, jitter, DSCP — three distinct categories, one bullet each.
        assert_eq!(out.len(), 3, "got {out:?}");
        assert!(out.iter().any(|b| b.contains("packet loss")));
        assert!(out.iter().any(|b| b.contains("high jitter")));
        assert!(out.iter().any(|b| b.contains("incorrect DSCP")));
    }

    #[test]
    fn summary_each_infra_issue_individual_bullet() {
        let mut health = NetworkHealth::new();
        health.tcp_retransmissions = 4;
        health.ecn_congestion_marks = 3;
        health.multiple_queriers_this_window = true;

        let mut ptp = empty_ptp();
        let mut d0 = PtpStats::new(0, 1);
        d0.clock_valid = false;
        d0.protocol_clock_lost = true;             // clock lost
        ptp.insert((0, 1), d0);

        let mut eee = empty_eee();
        eee.insert(("chassis".into(), "port3".into()), (10, 20));

        let out = health.build_health_summary(&empty_streams(), &empty_tcp(), &ptp, &empty_msrp(), &eee, &empty_avtp());
        assert!(out.iter().any(|b| b.contains("TCP retransmissions")), "got {out:?}");
        assert!(out.iter().any(|b| b.contains("ECN congestion")));
        assert!(out.iter().any(|b| b.contains("Multiple IGMP queriers")));
        assert!(out.iter().any(|b| b.contains("Clock Source lost")));
        assert!(out.iter().any(|b| b.contains("EEE active")));
    }

    #[test]
    fn summary_igmp_querier_only_when_multicast_active() {
        // last_igmp_query is None (no querier). With no multicast stream, this is
        // not a penalty and must not produce a bullet.
        let health = NetworkHealth::new();
        let mut unicast = empty_streams();
        unicast.insert("u1".into(), live_stream(0)); // is_multicast = false by default
        let out = health.build_health_summary(&unicast, &empty_tcp(), &empty_ptp(), &empty_msrp(), &empty_eee(), &empty_avtp());
        assert!(out.is_empty(), "no multicast → no querier bullet, got {out:?}");

        // Same querier state, but now an active multicast stream → querier-absent bullet.
        let mut mc = empty_streams();
        let mut m = live_stream(0);
        m.is_multicast = true;
        mc.insert("m1".into(), m);
        let out = health.build_health_summary(&mc, &empty_tcp(), &empty_ptp(), &empty_msrp(), &empty_eee(), &empty_avtp());
        assert!(out.iter().any(|b| b.contains("IGMP querier absent")), "got {out:?}");
    }

    #[test]
    fn summary_pcap_drops_produce_no_bullet() {
        // pcap drops are not an input to build_health_summary at all — a fully
        // healthy network with drops elsewhere yields an empty summary. This
        // encodes "tool limitation, not network fault".
        let health = NetworkHealth::new();
        let mut streams = empty_streams();
        streams.insert("s1".into(), live_stream(0));
        let out = health.build_health_summary(&streams, &empty_tcp(), &empty_ptp(), &empty_msrp(), &empty_eee(), &empty_avtp());
        assert!(out.is_empty());
    }

    #[test]
    fn summary_dead_stream_bullet() {
        let health = NetworkHealth::new();
        let mut streams = empty_streams();
        let mut dead = aes67();
        dead.packets = 100;
        dead.last_packet_time = Some(Instant::now() - Duration::from_secs(crate::protocols::STREAM_TIMEOUT_SECS + 5));
        streams.insert("s1".into(), dead);
        let out = health.build_health_summary(&streams, &empty_tcp(), &empty_ptp(), &empty_msrp(), &empty_eee(), &empty_avtp());
        assert!(out.iter().any(|b| b.contains("dead stream")), "got {out:?}");
    }

    /// The CONTEXT.md "Health Summary" biconditional, now structural: the score
    /// and the summary are both derived from `collect_penalties`, so for any state
    /// the bullet count equals the penalty count and the score equals 100 minus
    /// the summed deductions. Exercises a mixed stream-level + infrastructure state.
    #[test]
    fn score_and_summary_share_one_penalty_table() {
        let mut health = NetworkHealth::new();
        health.tcp_retransmissions = 4;
        health.ecn_congestion_marks = 3;

        let mut streams = empty_streams();
        streams.insert("loss".into(), live_stream(5));      // packet loss
        let mut dscp = live_stream(0);
        dscp.dscp_violations = 2;                            // DSCP violation
        streams.insert("dscp".into(), dscp);

        let mut eee = empty_eee();
        eee.insert(("chassis".into(), "port3".into()), (10, 20));

        let penalties = health.collect_penalties(
            &streams, &empty_tcp(), &empty_ptp(), &empty_msrp(), &eee, &empty_avtp(),
        );
        let summary = health.build_health_summary(
            &streams, &empty_tcp(), &empty_ptp(), &empty_msrp(), &eee, &empty_avtp(),
        );
        let expected: f64 = penalties.iter().map(|p| p.deduction()).sum();
        health.calculate_score(&streams, &empty_tcp(), &empty_ptp(), &empty_msrp(), &eee, &empty_avtp());

        // One bullet per penalty (biconditional), and the score is exactly the
        // complement of the summed deductions.
        assert_eq!(summary.len(), penalties.len(), "bullet ⇔ penalty: {summary:?}");
        assert!(expected > 0.0, "test state must produce penalties");
        assert!((health.network_score - (100.0 - expected)).abs() < 1e-9,
            "score {} != 100 - {}", health.network_score, expected);
    }

    /// `category()` is the one place a Diagnostic's short human-facing name is
    /// written — `collect_penalties`'s aggregate Health Summary bullet builds
    /// from it instead of independently re-authoring the same name a fifth time
    /// (detection in `diagnostics()`, scoring in `deduction()`, per-stream text
    /// in `message()`, and the old separately-worded aggregate bullet were the
    /// other four).
    #[test]
    fn category_names_match_existing_aggregate_bullet_wording() {
        assert_eq!(StreamDiagnostic::PacketLoss { window_count: 1, window_pct: 1.0, lifetime_pct: 1.0 }.category(), "packet loss");
        assert_eq!(StreamDiagnostic::HighJitter { jitter_ms: 25.0 }.category(), "high jitter");
        assert_eq!(StreamDiagnostic::TsDiscontinuity { window_count: 1 }.category(), "timestamp discontinuities");
        assert_eq!(StreamDiagnostic::SsrcChange { count: 1 }.category(), "SSRC changes");
        assert_eq!(StreamDiagnostic::SignalGap { window_count: 1, max_iat_ms: 1.0 }.category(), "signal gaps");
        assert_eq!(StreamDiagnostic::DscpViolation { count: 1, expected: "EF (46)" }.category(), "incorrect DSCP");
        assert_eq!(StreamDiagnostic::Dead { silent_secs: 1.0 }.category(), "silent");
    }

    /// `collect_penalties`'s per-stream match must be exhaustive over
    /// `StreamDiagnostic` — no wildcard arm — so a future variant with a
    /// nonzero `deduction()` can't compile in while silently never reaching
    /// the Health Score. This pins the current informational-only variants
    /// (Reorder, PtMismatch, UnknownStreamType, NotAnnounced) as contributing
    /// zero deduction and zero bullets, matching `deduction() == 0.0` for each.
    #[test]
    fn informational_only_diagnostics_produce_no_penalty() {
        let health = NetworkHealth::new();
        let mut s = StreamStats::new("2110-??", 90_000.0); // UnknownStreamType
        s.packets = 100;
        s.packets_this_window = 100;
        s.last_packet_time = Some(Instant::now());
        s.rtp_seen = true;             // + NotAnnounced (no SDP, packets > 10)
        s.pt_mismatches = 3;           // + PtMismatch
        s.reorders_this_window = 5;    // + Reorder (5% > 1% threshold)

        let mut streams = empty_streams();
        streams.insert("s1".into(), s);

        let penalties = health.collect_penalties(
            &streams, &empty_tcp(), &empty_ptp(), &empty_msrp(), &empty_eee(), &empty_avtp(),
        );
        let summary = health.build_health_summary(
            &streams, &empty_tcp(), &empty_ptp(), &empty_msrp(), &empty_eee(), &empty_avtp(),
        );

        assert!(penalties.is_empty(), "informational-only diagnostics must add no penalty, got {} penalties", penalties.len());
        assert!(summary.is_empty(), "informational-only diagnostics must add no bullet, got {summary:?}");
    }

    #[test]
    fn summary_avb_pcp_mismatch_deducts_and_produces_bullet() {
        // PcpMismatch carries a real -15/stream deduction (see StreamDiagnostic::
        // deduction) but until now `collect_penalties` never read from
        // `avtp_streams` at all, so it never contributed to the Health Score or
        // Health Summary — this pins the fix.
        let health = NetworkHealth::new();
        let mut avtp = empty_avtp();
        let mut s = AvtpStreamStats::new([1, 2, 3, 4, 5, 6, 7, 8], 0x00);
        s.pcp_violations = 1;
        s.observed_pcp = Some(2);
        s.msrp_declared_pcp = Some(3);
        avtp.insert(s.stream_id, s);

        let penalties = health.collect_penalties(
            &empty_streams(), &empty_tcp(), &empty_ptp(), &empty_msrp(), &empty_eee(), &avtp,
        );
        let summary = health.build_health_summary(
            &empty_streams(), &empty_tcp(), &empty_ptp(), &empty_msrp(), &empty_eee(), &avtp,
        );
        let total: f64 = penalties.iter().map(|p| p.deduction()).sum();

        assert_eq!(total, 15.0, "PCP mismatch must deduct 15 points, got total {total}");
        assert!(summary.iter().any(|b| b.contains("PCP mismatch")), "got {summary:?}");
    }

    #[test]
    fn summary_no_bullet_for_avb_stream_without_pcp_violation() {
        let health = NetworkHealth::new();
        let mut avtp = empty_avtp();
        let s = AvtpStreamStats::new([1, 2, 3, 4, 5, 6, 7, 8], 0x00);
        avtp.insert(s.stream_id, s);

        let out = health.build_health_summary(
            &empty_streams(), &empty_tcp(), &empty_ptp(), &empty_msrp(), &empty_eee(), &avtp,
        );
        assert!(out.is_empty(), "got {out:?}");
    }

    // ── timing_metronomic (Transmitter Class) ────────────────────────────────
    #[test]
    fn timing_metronomic_true_for_steady_intervals() {
        let mut s = aes67();
        s.iat_samples = vec![1.0; 32]; // perfectly steady → cv 0
        assert_eq!(s.timing_metronomic(), Some(true));
    }

    #[test]
    fn timing_metronomic_false_for_noisy_intervals() {
        let mut s = aes67();
        // alternating 0.5 / 1.5 ms → mean 1.0, cv 0.5 — scheduler-noisy software
        s.iat_samples = (0..32).map(|i| if i % 2 == 0 { 0.5 } else { 1.5 }).collect();
        assert_eq!(s.timing_metronomic(), Some(false));
    }

    #[test]
    fn timing_metronomic_none_with_too_few_samples() {
        let mut s = aes67();
        s.iat_samples = vec![1.0; 4];
        assert_eq!(s.timing_metronomic(), None);
    }

    // ── apply_sdp (Session Announcement enrichment) ──────────────────────────

    fn media(clock_hz: f64, channels: u8, ptime_ms: f64, pt: u8) -> crate::protocols::SdpMedia {
        crate::protocols::SdpMedia {
            media_type: "audio".to_string(),
            port: 5004,
            payload_types: vec![pt],
            connection: String::new(),
            rtpmap: "L24/48000/2".to_string(),
            clock_hz, channels, ptime_ms,
            ts_refclk: String::new(),
            mediaclk: String::new(),
        }
    }

    #[test]
    fn apply_sdp_transfers_all_technical_fields() {
        let mut s = aes67();
        let confirmed = s.apply_sdp(&media(96_000.0, 2, 1.0, 97), "Studio Mix");
        assert!(confirmed);
        assert_eq!(s.clock_hz, 96_000.0);
        assert!(s.clock_hz_confirmed);
        assert_eq!(s.channels, 2);
        assert_eq!(s.ptime_ms, 1.0);
        assert_eq!(s.expected_pt, Some(97));
        assert_eq!(s.sdp_rtpmap.as_deref(), Some("L24/48000/2"));
        assert_eq!(s.sdp_name.as_deref(), Some("Studio Mix"));
    }

    #[test]
    fn apply_sdp_returns_false_when_clock_hz_zero() {
        let mut s = aes67();
        let confirmed = s.apply_sdp(&media(0.0, 2, 1.0, 97), "Studio Mix");
        assert!(!confirmed);
        assert!(!s.clock_hz_confirmed);
    }

    #[test]
    fn apply_sdp_name_written_once() {
        let mut s = aes67();
        s.apply_sdp(&media(48_000.0, 2, 1.0, 96), "First Name");
        s.apply_sdp(&media(96_000.0, 2, 1.0, 97), "Second Name");
        assert_eq!(s.sdp_name.as_deref(), Some("First Name"), "name must not be overwritten");
        assert_eq!(s.clock_hz, 96_000.0, "technical fields must still refresh");
    }

    // ── apply_pcp_advisory — single seam for the AES67/ST2110 PCP=6 check ────
    // Previously hand-copied identically in handle_aes67 and handle_st2110.

    #[test]
    fn apply_pcp_advisory_flags_non_six_pcp() {
        let mut s = aes67();
        s.apply_pcp_advisory(Some(3));
        assert_eq!(s.pcp_violations, 1);
        assert_eq!(s.observed_pcp, Some(3));
    }

    #[test]
    fn apply_pcp_advisory_silent_on_pcp_six() {
        let mut s = aes67();
        s.apply_pcp_advisory(Some(6));
        assert_eq!(s.pcp_violations, 0);
        assert_eq!(s.observed_pcp, None);
    }

    #[test]
    fn apply_pcp_advisory_silent_on_untagged_frame() {
        let mut s = aes67();
        s.apply_pcp_advisory(None);
        assert_eq!(s.pcp_violations, 0);
    }

    #[test]
    fn apply_sdp_zero_fields_do_not_clobber_existing_values() {
        let mut s = aes67();
        s.channels = 4;
        s.ptime_ms = 4.0;
        // A re-announcement with channels/ptime_ms left at 0 (not present in this
        // media block) must not stomp values set by an earlier announcement.
        s.apply_sdp(&media(48_000.0, 0, 0.0, 96), "Name");
        assert_eq!(s.channels, 4);
        assert_eq!(s.ptime_ms, 4.0);
    }

    // ── TcpStreamStats::update_quality / update_bitrate ──────────────────────

    fn ndi_tcp() -> TcpStreamStats {
        TcpStreamStats::new(Ipv4Addr::new(192, 168, 1, 60), Ipv4Addr::new(192, 168, 1, 5))
    }

    #[test]
    fn tcp_quality_healthy_at_zero_retransmissions() {
        let mut t = ndi_tcp();
        t.update_quality();
        assert_eq!(t.stream_quality, StreamQuality::Healthy);
    }

    #[test]
    fn tcp_quality_healthy_at_two_retransmissions() {
        let mut t = ndi_tcp();
        t.retransmissions = 2;
        t.update_quality();
        assert_eq!(t.stream_quality, StreamQuality::Healthy, "boundary: 2 is still Healthy");
    }

    #[test]
    fn tcp_quality_degrading_at_three_retransmissions() {
        let mut t = ndi_tcp();
        t.retransmissions = 3;
        t.update_quality();
        assert_eq!(t.stream_quality, StreamQuality::Degrading);
    }

    #[test]
    fn tcp_quality_degrading_at_ten_retransmissions() {
        let mut t = ndi_tcp();
        t.retransmissions = 10;
        t.update_quality();
        assert_eq!(t.stream_quality, StreamQuality::Degrading, "boundary: 10 is still Degrading");
    }

    #[test]
    fn tcp_quality_critical_at_eleven_retransmissions() {
        let mut t = ndi_tcp();
        t.retransmissions = 11;
        t.update_quality();
        assert_eq!(t.stream_quality, StreamQuality::Critical);
    }

    #[test]
    fn tcp_quality_terminated_on_rst() {
        let mut t = ndi_tcp();
        t.rst_packets = 1;
        t.update_quality();
        assert_eq!(t.stream_quality, StreamQuality::Terminated);
    }

    #[test]
    fn tcp_quality_terminated_overrides_high_retransmissions() {
        let mut t = ndi_tcp();
        t.retransmissions = 50;
        t.rst_packets = 1;
        t.update_quality();
        assert_eq!(t.stream_quality, StreamQuality::Terminated, "RST dominates regardless of retransmission count");
    }

    #[test]
    fn tcp_quality_healthy_on_single_fin() {
        let mut t = ndi_tcp();
        t.fin_packets = 1;
        t.update_quality();
        assert_eq!(t.stream_quality, StreamQuality::Healthy, "one FIN is a normal half-close, not termination");
    }

    #[test]
    fn tcp_quality_terminated_on_second_fin() {
        let mut t = ndi_tcp();
        t.fin_packets = 2;
        t.update_quality();
        assert_eq!(t.stream_quality, StreamQuality::Terminated);
    }

    #[test]
    fn tcp_bitrate_not_recalculated_within_one_second_window() {
        let mut t = ndi_tcp();
        t.bytes = 125_000; // 1 Mbit
        t.update_bitrate();
        assert_eq!(t.bitrate_bps, 0, "no recalculation until the 1s window elapses");
    }

    #[test]
    fn tcp_bitrate_recalculated_after_window_elapses() {
        let mut t = ndi_tcp();
        t.bytes = 125_000; // 1 Mbit of bytes accumulated over the window
        t.last_bitrate_check = Instant::now() - Duration::from_secs(2);
        t.update_bitrate();
        assert!(t.bitrate_bps > 0, "bitrate must be computed once the window has elapsed");
        assert_eq!(t.bytes_at_check, 125_000, "checkpoint must advance to the current byte count");
    }

    // ── PTP path-delay alert thresholds — pure, testable independent of rendering ─

    #[test]
    fn path_delay_spread_not_unstable_under_10us() {
        assert!(!path_delay_spread_unstable(1_000, 10_999));
    }

    #[test]
    fn path_delay_spread_unstable_over_10us() {
        assert!(path_delay_spread_unstable(1_000, 11_001));
    }

    #[test]
    fn path_delay_not_too_many_hops_under_1ms() {
        assert!(!path_delay_too_many_hops(1_000_000));
    }

    #[test]
    fn path_delay_too_many_hops_over_1ms() {
        assert!(path_delay_too_many_hops(1_000_001));
    }

    #[test]
    fn path_delay_hop_estimate_scales_by_5us_per_hop() {
        assert_eq!(path_delay_hop_estimate(0), 0);
        assert_eq!(path_delay_hop_estimate(4_999), 0, "suppressed below one hop's worth");
        assert_eq!(path_delay_hop_estimate(5_000), 1);
        assert_eq!(path_delay_hop_estimate(12_000), 2);
    }

    // ── PtpStats::is_ip_ptp_domain / is_gptp_domain ──────────────────────────
    // Named predicates replacing `protocol_kind.as_deref() != / == Some("AVB")`
    // inlined four times across missing_ptp_clocks/check_clock_dropout_correlation.

    #[test]
    fn is_ip_ptp_domain_true_for_aes67() {
        let mut s = PtpStats::new(0, crate::protocols::PTP_VERSION_V2);
        s.protocol_kind = Some("AES67".to_string());
        assert!(s.is_ip_ptp_domain());
        assert!(!s.is_gptp_domain());
    }

    #[test]
    fn is_gptp_domain_true_for_avb() {
        let mut s = PtpStats::new(0, crate::protocols::PTP_VERSION_V2);
        s.protocol_kind = Some("AVB".to_string());
        assert!(s.is_gptp_domain());
        assert!(!s.is_ip_ptp_domain());
    }

    #[test]
    fn is_ip_ptp_domain_true_when_protocol_kind_unset() {
        // A domain seen before its protocol_kind is assigned is IP-PTP by default
        // (matches the existing `!= Some("AVB")` behavior for None).
        let s = PtpStats::new(0, crate::protocols::PTP_VERSION_V2);
        assert!(s.is_ip_ptp_domain());
        assert!(!s.is_gptp_domain());
    }

    // ── NetworkHealth::record_ecn_mark_if_congested ──────────────────────────
    // Single seam for the ECN=3 check, previously hand-copied identically in
    // handle_aes67, handle_st2110, and handle_dante.

    #[test]
    fn record_ecn_mark_if_congested_counts_ce_marked_packet() {
        let mut health = NetworkHealth::new();
        health.record_ecn_mark_if_congested(3);
        assert_eq!(health.ecn_congestion_marks, 1);
    }

    #[test]
    fn record_ecn_mark_if_congested_ignores_non_ce_ecn() {
        let mut health = NetworkHealth::new();
        for ecn in [0u8, 1, 2] {
            health.record_ecn_mark_if_congested(ecn);
        }
        assert_eq!(health.ecn_congestion_marks, 0);
    }
}
