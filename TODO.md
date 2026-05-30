# AVStreamLens — TODO

---

## Missing Features

- **PTPv1 grandmaster Ethernet source MAC** — Dante puts a synthetic clock identity (not a real NIC MAC) in the `grandmasterClockUuid` field (bytes 50–55 of the Sync body), so the displayed grandmaster ID cannot be used for OUI lookup. Thread the actual Ethernet source MAC (bytes 6–11 of the raw frame) through to `PtpInfo` via a new `src_mac: Option<[u8;6]>` field; display it alongside the clock UUID as `(NIC: xx:xx:xx:xx:xx:xx)` so the real manufacturer OUI is visible. Requires passing the raw frame header into `detect_protocol` or extracting the src MAC before dispatch. (`src/protocols.rs` — `PtpInfo`; `src/parser.rs` — `detect_protocol`; `src/capture.rs` — `dispatch`; `src/report.rs`)

- **VLAN-ID filtering** — no per-VLAN filter is implemented; the tool processes all VLANs delivered by the capture interface. A `--vlan <id>` flag or interactive prompt could let the user narrow to a specific VLAN on trunk/SPAN ports. (`src/cli.rs`, BPF filter in `build_bpf_filter`)

- **Dante AV video stream support** — Dante audio is fully implemented; Dante AV (Audinate's video-over-IP product) is not. Needs investigation of transport (UDP vs TCP), port ranges, and codec signalling used by Dante AV devices to determine detection heuristic. A new `DanteKind::VideoStream` variant or a separate `AvProtocol::DanteAv` would follow the existing handler pattern. (`src/protocols.rs`, `src/parser.rs`, `src/capture.rs`)

- **Review health score penalty weights** — the current penalty table was set heuristically. Worth a pass to validate weights feel right for real AV deployments: e.g. is −30 for a dead stream vs −25 for a lost PTP clock the right relative severity? Are the caps (loss capped at −10, EEE capped at −30) appropriate? (`src/stats.rs` — `calculate_score`)

- **`--duration <seconds>` flag** — run for N seconds then exit with status 0 (healthy) or 1 (issues). Enables scripted health checks: `avstreamlens --interface en0 --protocol aes67 --duration 30 && echo OK`. (`src/main.rs` — report loop exit condition)

- **JSON output mode (`--output json`)** — emit newline-delimited JSON (one object per report cycle) for Grafana/Prometheus/`jq` integration. Add `serde::Serialize` to `StreamStats`, `PtpStats`, `NetworkHealth`; serialize at the point `print_report` is called. Log file format unchanged unless `--output json` is set. (`src/report.rs`, `src/stats.rs`)

- **SAP re-announcement rate monitoring** — RFC 2974 requires SAP senders to re-announce every ~30 s. Track `last_sap_time` per stream in `sdp_cache`; alert when >90 s with no re-announcement while the RTP stream is still live. Catches sources that silently drop off SAP. (`src/capture.rs` — `handle_sap`; `src/stats.rs` — `StreamStats` or `sdp_cache` entry)

- **Redundant stream pairing (ST 2110 / AES67)** — productions often run dual-redundant streams (same SSRC, same codec, two different multicast groups). Detect pairs by matching SSRC + clock_hz + media_type and report them as `primary / redundant` with a combined health indicator. (`src/capture.rs` — post-dispatch pairing pass; `src/report.rs`)

- **RTCP reception reports** — AES67 and ST 2110 senders transmit RTCP SR/RR packets on `rtp_port + 1`. RR contains the sender's own loss fraction and jitter estimate, often more accurate than passive loss counting at the capture point. Add a `parse_rtcp()` parser; store `rtcp_loss_fraction` and `rtcp_jitter` in `StreamStats`; show in the stream entry. (`src/parser.rs` or `src/parser/rtcp.rs`; `src/stats.rs`; `src/capture.rs`)

- **PTP BMCA analysis** — when multiple PTP masters are visible, compute which would win the Best Master Clock Algorithm election (`clock_class → clock_accuracy → offsetScaledLogVariance → priority1/priority2`). Show "active grandmaster + N standby(s), best standby: …" in the Clock Sources section. Useful for validating redundant clock infrastructure. (`src/capture.rs` — `handle_ptp`; `src/stats.rs` — `PtpStats`; `src/report.rs`)

- **Stream count anomaly detection** — alert when the number of observed streams increases by more than 2× the rolling average over the last 3 windows (e.g. runaway Dante device flooding multicast). Track a short history of stream counts in `CaptureState`. (`src/capture.rs` — `reset_window`)

- **SDP file pre-load (`--sdp <file>`)** — allow a local SDP or multi-session SDP bundle to be loaded at startup to enrich streams before any SAP announcement arrives. Sets `clock_hz_confirmed`, `expected_pt`, `sdp_name`, `ptime_ms` from packet 1. (`src/cli.rs`; `src/capture.rs` — startup enrichment pass using existing `handle_sap` logic)

- **NMOS IS-04 discovery** — detect `_nmos-node._tcp` mDNS services and optionally query the NMOS Node API (`http://<host>:3000/x-nmos/node/v1.3/senders`) to enrich ST 2110 streams with sender names and SDP without relying on SAP. Significant addition; new `AvProtocol::Nmos` variant + HTTP client dependency. (`src/protocols.rs`, `src/parser/mdns.rs`, `src/capture.rs`)

---

## Field Verification Needed

Items to check next time connected to a functional network of each type. Results will directly inform code changes — do not change the related logic until verified.

### Dante

- **gmClockIdentifier = device IP?** — The 4 bytes at PTPv1 Sync body offset 62–65 displayed as `a9:fe:68:56` match the grandmaster's IP `169.254.104.86`. If Dante consistently puts the grandmaster's IPv4 address in that field, render it as dotted-decimal instead of hex. Need to confirm on a second network / with a statically-addressed device.

- **PTPv1 stratum semantics** — We label stratum 0 as "Preferred grandmaster" assuming it indicates external clock reference. Need to observe a free-running Dante device (no word clock input) and check whether it also reports stratum 0, or stratum 1+. If free-running also = 0, the label is wrong and should be changed to something neutral.

- **BMCA with multiple Dante devices** — With several devices on the network, observe which one wins grandmaster election and whether its stratum is lower than the others. Confirms whether the stratum field actually drives Dante's BMCA or if some other field does.

- **Multicast Dante audio detection (no SPAN)** — On a simple switch port, verify that 239.255.x.x Dante multicast audio streams fire the `5000–6000 even port` heuristic and produce a stream entry. Current logic has never been confirmed on a live multicast Dante flow from a non-SPAN port.

- **PTPv1 grandmaster Ethernet source MAC** — See Missing Features above. Capture an ARP or mDNS packet from the PTPv1 grandmaster to cross-reference its real NIC MAC against the synthetic `grandmasterClockUuid`. Needed before implementing the NIC MAC display feature.

### AES67

- **Signal gap threshold** — The alert fires at ≥2 gap events > 50ms per 5s window to avoid pcap scheduling noise. Verify on a real network whether a single late packet is common on a healthy stream (would validate the ≥2 guard) and whether 50ms is the right floor (some implementations send at 1ms ptime, so a single lost packet would already exceed 50ms).

- **"Stream not announced" threshold** — Alert fires after 10 packets with no SDP enrichment. Verify how quickly a real AES67 sender transmits its first SAP announcement after stream start — if it typically arrives within the first few packets, 10 is fine; if SAP is delayed (e.g. 30s cycle), 10 will always fire a false positive.

- **ts-refclk cross-check on a real mismatch** — The SDP-claimed grandmaster EUI-64 is compared against the active PTPv2 domain. Has never been tested on a network where the SDP and wire grandmaster are actually different (e.g. after a grandmaster failover without SAP update). Verify the alert fires correctly and doesn't produce false positives.

- **DSCP in practice** — Verify that real AES67 senders consistently mark EF (46). Some implementations use CS7 or AF41 — if so, the per-stream DSCP alert would fire on healthy streams and the accepted-value set may need expanding.

### ST 2110

- **Port convention reliability** — Stream type is classified by the last digit of the UDP destination port (4=video, 6=audio, 8=anc) before falling back to RTP PT. Verify that real 2110-20/2110-30/2110-40 senders actually follow this convention, or whether RTP PT alone is more reliable.

- **SAP presence** — Many ST 2110 installations rely on NMOS IS-04 for stream discovery and do not send SAP at all. Verify whether "Stream not announced" fires constantly on real ST 2110 networks without NMOS, and whether the alert threshold or wording should be adjusted for this case.

- **DSCP for 2110-20 video** — Code accepts EF (46), CS5 (40), and AF41 (34) for video. Verify which values real encoders/switchers actually use — if only one value is common in practice, tighten the acceptance set and/or note the others as misconfigured.

- **90 kHz assumption for 2110-20** — `clock_hz_confirmed = true` is set immediately for video (no SDP needed). Verify on a real video stream that the RTP timestamp increments at 90 kHz — if a device uses a non-standard clock rate, TS discontinuity detection will produce false positives.

### NDI

- **mDNS before TCP** — Detection is IP-based: `ndi_sources` must be populated from mDNS before a TCP stream is counted. Verify on a real network whether mDNS discovery reliably arrives before (or shortly after) the first TCP connection, or whether streams are routinely missed at startup because the TCP flow is seen before the mDNS announcement.

- **Bitrate aggregation accuracy** — NDI bitrate is summed from `tcp_streams` matched by destination IP. Verify on a source sending multiple NDI streams that the per-source aggregation produces a sensible combined figure and doesn't double-count.

- **TCP port range** — Ports 5960–5980 are the documented NDI range but port-range matching was removed (caused double-counting). Verify that IP-only detection doesn't misclassify non-NDI TCP flows to/from a known NDI source IP (e.g. a web interface on the same device).

### AVB

- **MVRP on a real AVB network** — Alert fires if AVTP streams are active but no MVRP registration is seen. Verify whether a real AVB switch always sends MVRP, or if some configurations (endpoint-only, no managed switch) never produce MVRP — in which case the alert would be a persistent false positive.

- **MSRP timing** — Verify how quickly TalkerAdvertise appears after an AVB stream starts. If it arrives significantly later than the AVTP data, the "no reservation" state may be shown briefly on every stream start; a short grace period might be needed.

- **gPTP path delay spread baseline** — The alert threshold for path-delay spread is > 10µs. Verify the typical spread on a single well-configured AVB switch with no EEE — if clean links produce spreads of e.g. 2–3µs, 10µs is a reasonable threshold; if they produce 8–9µs, the threshold is too tight.

- **AVTP sequence counter byte** — Loss is tracked on byte 2 of the AVTP header as an 8-bit sequence counter. Verify on a real IEC 61883 stream that byte 2 is indeed the sequence number and increments per frame, not per packet (some subtypes use byte 2 differently).

### PTPv2 (AES67 / ST 2110)

- **Correction field on a transparent-clock network** — Alert fires if abs(correction) > 1µs. Verify on a network with a PTPv2 transparent clock (e.g. a Cisco or Arista switch in TC mode) what correction values are typical — if TC-corrected values routinely exceed 1µs on a healthy network, the threshold is too tight.

- **Path delay spread on a multi-hop network** — The > 10µs spread alert was tuned for single-switch AV networks. Verify the spread produced by a 2–3 hop path to understand whether the threshold needs to be topology-aware or at least documented as a single-hop figure.

- **PTPv2 class 7 (free-running) in practice** — `ptp_class_str(7)` is labelled "Primary reference — free-running". Verify whether a real device that has lost its GPS/GNSS lock actually advertises class 7, or whether it falls back to class 135 (holdover) first. Affects how the clock quality string reads during a reference failure.

---

## Platform Limitations (documented, tracked here for awareness)

- **NDI on loopback unsupported** — macOS loopback uses DLT_NULL (BSD null header, no Ethernet frame), and mDNS multicast doesn't flow over loopback. No fix planned; interface list already excludes `lo`/`lo0`. (`src/cli.rs`)

- **macOS VLAN tag stripping** — many macOS drivers strip the 802.1Q tag before pcap sees it, so per-VLAN stream attribution is unavailable on macOS even on trunk ports. Linux generally preserves the tag. No fix available at the application level.

- **Windows: no ANSI color in classic `cmd.exe`** — colour output requires Windows Terminal or VS Code. No fix planned; document in README under Platform Notes (already noted).

- **PAUSE / PFC frames consumed by NIC** — most NICs/drivers strip PAUSE and PFC frames at the MAC layer before pcap sees them. Absence of these alerts does NOT prove the link is congestion-free. Already documented in README; no fix available.

---

## Patterns to Follow When Extending

These aren't open bugs — they're invariants that must be preserved when adding new protocols or alerts:

- **"Selected AND observed" gate** for any new clock requirement: flag a missing clock only when (a) the relevant protocol is in `expanded_protocols` AND (b) at least one stream of that protocol has actually been observed. See `missing_ptp_clocks()` in `capture.rs`.

- **Alert dedup via `*_this_window` counters** for any new alert on a cumulative metric: keep the lifetime counter growing for history, but fire the alert only when the per-window delta is non-zero. See `lost_this_window`, `ts_discontinuities_this_window` in `stats.rs` and the corresponding reset in `reset_window()`.
