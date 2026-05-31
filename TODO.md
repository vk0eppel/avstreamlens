# AVStreamLens — TODO

---

## Missing Features

- **PTPv1 grandmaster Ethernet source MAC** — Dante puts a synthetic clock identity (not a real NIC MAC) in the `grandmasterClockUuid` field (bytes 50–55 of the Sync body), so the displayed grandmaster ID cannot be used for OUI lookup. Thread the actual Ethernet source MAC (bytes 6–11 of the raw frame) through to `PtpInfo` via a new `src_mac: Option<[u8;6]>` field; display it alongside the clock UUID as `(NIC: xx:xx:xx:xx:xx:xx)` so the real manufacturer OUI is visible. Requires passing the raw frame header into `detect_protocol` or extracting the src MAC before dispatch. (`src/protocols.rs` — `PtpInfo`; `src/parser.rs` — `detect_protocol`; `src/capture.rs` — `dispatch`; `src/report.rs`)

- **VLAN-ID filtering** — no per-VLAN filter is implemented; the tool processes all VLANs delivered by the capture interface. A `--vlan <id>` flag or interactive prompt could let the user narrow to a specific VLAN on trunk/SPAN ports. (`src/cli.rs`, BPF filter in `build_bpf_filter`)

- **Dante AV video stream support** — Dante audio is fully implemented; Dante AV (Audinate's video-over-IP product) is not. Needs investigation of transport (UDP vs TCP), port ranges, and codec signalling used by Dante AV devices to determine detection heuristic. A new `DanteKind::VideoStream` variant or a separate `AvProtocol::DanteAv` would follow the existing handler pattern. (`src/protocols.rs`, `src/parser.rs`, `src/capture.rs`)

- **Review health score penalty weights** — the current penalty table was set heuristically. Worth a pass to validate weights feel right for real AV deployments: e.g. is −30 for a dead stream vs −25 for a lost PTP clock the right relative severity? Are the caps (loss capped at −10, EEE capped at −30) appropriate? (`src/stats.rs` — `calculate_score`)

- **JSON output mode (`--output json`)** — emit newline-delimited JSON (one object per report cycle) for Grafana/Prometheus/`jq` integration. Add `serde::Serialize` to `StreamStats`, `PtpStats`, `NetworkHealth`; serialize at the point `print_report` is called. Log file format unchanged unless `--output json` is set. (`src/report.rs`, `src/stats.rs`)

- **SAP re-announcement rate monitoring** — RFC 2974 requires SAP senders to re-announce every ~30 s. Track `last_sap_time` per stream in `sdp_cache`; alert when >90 s with no re-announcement while the RTP stream is still live. Catches sources that silently drop off SAP. (`src/capture.rs` — `handle_sap`; `src/stats.rs` — `StreamStats` or `sdp_cache` entry)

- **Redundant stream pairing (ST 2110 / AES67)** — productions often run dual-redundant streams (same SSRC, same codec, two different multicast groups). Detect pairs by matching SSRC + clock_hz + media_type and report them as `primary / redundant` with a combined health indicator. (`src/capture.rs` — post-dispatch pairing pass; `src/report.rs`)

- **RTCP reception reports** — AES67 and ST 2110 senders transmit RTCP SR/RR packets on `rtp_port + 1`. RR contains the sender's own loss fraction and jitter estimate, often more accurate than passive loss counting at the capture point. Add a `parse_rtcp()` parser; store `rtcp_loss_fraction` and `rtcp_jitter` in `StreamStats`; show in the stream entry. (`src/parser.rs` or `src/parser/rtcp.rs`; `src/stats.rs`; `src/capture.rs`)

- **PTP BMCA analysis** — when multiple PTP masters are visible, compute which would win the Best Master Clock Algorithm election (`clock_class → clock_accuracy → offsetScaledLogVariance → priority1/priority2`). Show "active grandmaster + N standby(s), best standby: …" in the Clock Sources section. Useful for validating redundant clock infrastructure. (`src/capture.rs` — `handle_ptp`; `src/stats.rs` — `PtpStats`; `src/report.rs`)

- **SDP file pre-load (`--sdp <file>`)** — allow a local SDP or multi-session SDP bundle to be loaded at startup to enrich streams before any SAP announcement arrives. Sets `clock_hz_confirmed`, `expected_pt`, `sdp_name`, `ptime_ms` from packet 1. (`src/cli.rs`; `src/capture.rs` — startup enrichment pass using existing `handle_sap` logic)

- **NMOS IS-04 discovery** — detect `_nmos-node._tcp` mDNS services and optionally query the NMOS Node API (`http://<host>:3000/x-nmos/node/v1.3/senders`) to enrich ST 2110 streams with sender names and SDP without relying on SAP. Significant addition; new `AvProtocol::Nmos` variant + HTTP client dependency. (`src/protocols.rs`, `src/parser/mdns.rs`, `src/capture.rs`)

---

## Field Verification Needed

Items to check next time connected to a functional network of each type. Results will directly inform code changes — do not change the related logic until verified.

### Dante

- **gmClockIdentifier = device IP?** — ✅ CONFIRMED NO (2026-05-30). The PTPv1 `grandmasterClockUuid` field (`00:00:00:01:00:1d`) is a Dante firmware constant — identical across all Dante devices and networks tested. The real per-device identity is the EUI-64 `device_id` in the Dante application protocol (OUI `00:1D:C1` + `FF:FE` + MAC suffix, e.g. `001DC1FFFE8EB175` → MAC `00:1D:C1:8E:B1:75`), but this never appears in the PTPv1 wire format. The source IP is the only per-device discriminator visible in PTP — our display of `grandmaster <uuid>  (<ip>)` is correct and the IP is already the meaningful part.

- **PTPv1 stratum semantics** — Partially confirmed (2026-05-30). `preferred_master=true` + `external_word_clock=true` in Dante Controller → stratum 0 on the wire → `"Preferred grandmaster"` label is correct for an externally-clocked preferred leader. Still unknown: what stratum a device with `preferred_master=true` but `external_word_clock=false` (free-running, no external ref) reports. If it's also stratum 0, the label is still correct (Audinate uses stratum 0 as the preferred tier regardless of external ref). Check on a device with Preferred Leader ON but no word clock connected.

- **gmClockIdentifier junk after "Preferred grandmaster"** — ✅ FIXED (2026-05-30). Dante leaves non-identifier bytes in the PTPv1 `gmClockIdentifier` (bytes 62–65) that vary frame-to-frame; an intermittent lone printable byte (`@` = 0x40) was rendered as `Preferred grandmaster  @`. The old filter accepted any `is_ascii_graphic()` char. Tightened (`src/parser/ptp.rs`) to only show the ident when it's a plausible clock-source code — ≥2 ASCII alphanumeric chars (keeps GPS/ATOM/NTP/DFLT/HAND/INIT; suppresses `@` and other punctuation/short junk). Test: `ptpv1_lone_printable_junk_ident_suppressed`. **Note:** for Dante these bytes appear to carry no meaningful clock-source code at all — worth confirming whether *any* Dante device populates a real identifier here, or whether the ident should simply never be shown for PTPv1-from-Dante.

- **Dante grandmaster shown by device name** — ✅ DONE (2026-05-30). The PTPv1 gmClockUuid is a firmware constant (useless as an ID), so the report now identifies the grandmaster by its **discovered mDNS device name** when available: cross-references the GM's source IP against `dante_names`. New `PtpStats::grandmaster_src_ip` captures the IP from the grandmaster-bearing message only (Sync v1 / Announce v2), so a follower's Delay_Req can't mis-attribute the GM. Display: name `"Stage Box" (ip)` if known → else PTPv1 drops the UUID and shows just the IP → else PTPv2/gPTP keep the EUI-64. Tests: `ptp_grandmaster_src_ip_is_the_gm_not_a_follower`. **Possible follow-up:** OUI→vendor lookup for PTPv2/gPTP grandmasters (turn the EUI-64 into `… (Meinberg)`).

- **"Preferred Leader" flag wire mapping** — ✅ CONFIRMED (2026-05-30). Dante Controller `preferred_master=true` maps to PTPv1 stratum 0 in BMCA. Verified via XML export of a DirectOut PRODIGY (Brooklyn-3 module) that was the elected grandmaster. Stratum 0 = Preferred Leader enabled. No other wire field appears to be set — stratum alone determines the BMCA outcome.

- **DDM / Dante Director custom subdomains** — Dante Director uses user-defined PTPv1 subdomains (e.g. `H~O$L`) that are not `_DFLT/_ALT1/_ALT2/_ALT3`. Our `map_ptpv1_subdomain` silently maps unknown subdomains to domain 0 — on a DDM-managed network all domains would appear as domain 0 regardless of their actual subdomain. Need to observe DDM subdomain values in the wild and decide whether to show them as raw ASCII strings instead of mapping to a number. (`src/parser/ptp.rs` — `map_ptpv1_subdomain`; `src/report.rs` — domain display)

- **Multicast Dante audio detection (no SPAN)** — `is_dante_multicast()` now classifies `239.255.0.0/16` flows with an even 5000–6000 destination port as Dante (before the ST2110 catch-all). Verify on a live multicast Dante flow from a non-SPAN port that (a) such flows really land in `239.255/16` with an even Dante-range dst port, and (b) no local ST2110 deployment uses `239.255.x.x` with an even 5000–6000 dst port — that combination would now be mislabelled Dante. If ST2110-on-239.255 is found in the wild, tighten the heuristic (e.g. require the dst port to match Dante's exact flow ports, or add a `--st2110-multicast <range>` override). (`src/parser.rs` — `is_dante_multicast`, `detect_protocol`)

- **PTPv1 grandmaster Ethernet source MAC** — See Missing Features above. The PTPv1 UUID is a Dante firmware constant (not MAC-derived), so cross-referencing UUID → MAC is not useful. The correct approach is to correlate the grandmaster's source IP against ARP or mDNS packets from the same IP to retrieve the NIC MAC. Needed before implementing the NIC MAC display feature. The EUI-64 (`device_id`) in Dante's application protocol IS the MAC (`OUI + FFFE + suffix`) but never appears in PTP packets.

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

- **AVB stream count vs. empty Streams list** — ✅ FIXED (2026-05-30). A live AVB network showed `AVB: 1` in the overview with an empty Streams list. Root cause: the overview counted the per-subtype `streams["AVB …"]` map while the Streams list and gPTP clock gate read the per-stream-id `avtp_streams` map, and `handle_avb` created a `streams` entry even for sv=0 AVTP control/discovery frames (AVDECC ADP/ACMP, MAAP) that carry no stream id. Fix: `handle_avb` now early-returns for sv=0 frames (no phantom entry, no latent −30 dead-stream penalty), and the overview AVB count comes from `avtp_streams.len()` so count == rendered lines == clock gate. Bandwidth is unaffected (global `bytes_this_window`). Tests: `avb_control_frame_without_stream_id_creates_no_stream`, `avb_media_frame_with_stream_id_creates_stream`. (`src/capture.rs` `handle_avb`, `src/report.rs` overview count)

- **MSRP TalkerFailed FailureCode decoding** — ✅ CONFIRMED + FIXED (2026-05-30). Verified against a live AVB talker (`48:0b:b2:d0:04:ea:0000`, FailedBridgeId `80:00:d0:69:9e:11:86:3c`): the on-wire FailureCode (IEEE 802.1Qat Table 35-6) is **8 = "egress port is not AVB-capable"** — i.e. a port in the reservation path has no SRP/AVB enabled. The parser offset (`first_value[33]`, `src/parser/avb.rs:64`) is correct; the report only labelled codes 1/2/3 and rendered everything else as a useless `(failure)`. Fix: `protocols::msrp_failure_reason()` maps the full 1–19 table with a numeric fallback, used at both sites (`capture.rs` alert + `report.rs` inline), and the numeric code is always shown — e.g. `(code 8: egress port is not AVB-capable)`. Test: `msrp_failure_reason_maps_known_and_unknown_codes`. **Possible follow-up:** also surface the FailedBridgeId so the operator knows *which* bridge rejected the reservation.

- **gPTP "sync only" mislabel for a Pdelay-only endpoint** — ✅ CONFIRMED + FIXED (2026-05-30). On the same AVB endpoint, gPTP traffic (`ether proto 0x88f7`) was **only P_Delay_Req** (msgType 0x02, ~1/s, seq incrementing) from `d0:69:9e:ff:fe:11:86:3c` — **no Sync, no Announce, and no Pdelay_Resp**. The parser was correct (no Announce exists), but the report always rendered `(sync only, no announce)` because `last_clock_id` is set from any PTPv2 message (`stats.rs`) including PdelayReq. Fix: `PtpStats::seen_sync` (set only on msgType 0x00) now gates the wording — a Pdelay-only node renders `(peer-delay requests only — no Sync/grandmaster; link partner may not be gPTP-capable)`, while a real clock with no GM elected renders `(Sync seen, no Announce …)`. Test: `ptp_pdelay_req_only_does_not_set_seen_sync`. **Network diagnosis:** PdelayReq with no Pdelay_Resp + MSRP code 8 + no grandmaster together mean this AVB endpoint is plugged into a switch/port that is **not AVB/gPTP/SRP-capable**. (`src/stats.rs`, `src/report.rs`)

- **gPTP grandmaster not remotely observable** — ✅ EXPLAINED + DOCUMENTED (2026-05-30). Operator had a gPTP grandmaster configured (Luminex) but the tool never showed it. Not a bug: gPTP (802.1AS) is link-local — frames use the reserved MAC `01:80:C2:00:00:0E` that bridges must not forward, so each time-aware switch consumes the GM's Sync/Announce and regenerates its own hop-by-hop. The GM's Announce is therefore only visible on a time-aware (AVB-enabled) link, ideally the GM's own first link — never from an arbitrary port, even with SPAN. (Contrast: AES67/Dante PTP is IP multicast and floods the VLAN.) MSRP (`…:0E`) and MVRP (`…:21`) are link-local too; only AVTP stream data is forwardable. Fix: README "Monitoring gPTP / the AVB grandmaster" subsection + corrected the false "delivered to every port" claim, and a report hint `ℹ gPTP is link-local …` printed for the AVB peer-delay-only case (gated on `protocol_kind==AVB && !seen_sync && no grandmaster`). (`README.md`, `src/report.rs`)

- **AVDECC ADP on a live Milan/AVB network** — Verify that real Milan devices (d&b, MOTU, Luminex, etc.) send ADP frames with byte 0 = 0xFA to MAC `91:E0:F0:01:00:00` as expected, and that the parsed fields (entity_id, entity_model_id, talker/listener counts, gptp_grandmaster_id, domain) match what Milan Manager shows for the same device. Also verify: (a) message_type 1 (ENTITY_DEPARTING) is sent when a device is powered off cleanly; (b) available_index increments after connection changes; (c) valid_time values seen in the wild (expect 5–31, i.e. 10–62s). If gptp_grandmaster_id is all-zeros for some devices, confirm the "no grandmaster" display reads correctly. (`src/parser/avdecc.rs`, `src/capture.rs` `handle_avdecc_adp`)

- **MVRP on a real AVB network** — Alert fires if AVTP streams are active but no MVRP registration is seen. Verify whether a real AVB switch always sends MVRP, or if some configurations (endpoint-only, no managed switch) never produce MVRP — in which case the alert would be a persistent false positive.

- **MSRP timing** — Verify how quickly TalkerAdvertise appears after an AVB stream starts. If it arrives significantly later than the AVTP data, the "no reservation" state may be shown briefly on every stream start; a short grace period might be needed.

- **gPTP path delay spread baseline** — The alert threshold for path-delay spread is > 10µs. Verify the typical spread on a single well-configured AVB switch with no EEE — if clean links produce spreads of e.g. 2–3µs, 10µs is a reasonable threshold; if they produce 8–9µs, the threshold is too tight.

- **AVTP sequence counter byte** — Loss is tracked on byte 2 of the AVTP header as an 8-bit sequence counter. Verify on a real IEC 61883 stream that byte 2 is indeed the sequence number and increments per frame, not per packet (some subtypes use byte 2 differently).

### PTPv2 (AES67 / ST 2110)

- **Correction field on a transparent-clock network** — Alert fires if abs(correction) > 1µs. Verify on a network with a PTPv2 transparent clock (e.g. a Cisco or Arista switch in TC mode) what correction values are typical — if TC-corrected values routinely exceed 1µs on a healthy network, the threshold is too tight.

- **Path delay spread on a multi-hop network** — The > 10µs spread alert was tuned for single-switch AV networks. Verify the spread produced by a 2–3 hop path to understand whether the threshold needs to be topology-aware or at least documented as a single-hop figure.

- **PTPv2 class 7 (free-running) in practice** — `ptp_class_str(7)` is labelled "Primary reference — free-running". Verify whether a real device that has lost its GPS/GNSS lock actually advertises class 7, or whether it falls back to class 135 (holdover) first. Affects how the clock quality string reads during a reference failure.

### IGMP / Multicast Snooping

- **Querier detection with the Router Alert option (IHL=6)** — ✅ CONFIRMED (2026-05-30). Verified against a live Luminex IGMPv3 querier (`10.244.70.241` → `224.0.0.1`, ~125 s General-Query interval, `length 36`, `options (RA)`). Real IGMP queries carry the IP Router Alert option, so the IP header is 24 bytes (IHL=6) and the IGMP type byte sits at offset 24, not 20. `detect_protocol` reads it correctly (pnet's `Ipv4Packet::payload()` respects IHL); the report showed `IGMP: ✓ querier 88s ago (interval 125s)`. A regression test now pins this path — `igmpv3_query_with_router_alert_option_detected` in `src/parser.rs` (all other IGMP fixtures only build IHL=5). The initial "no querier seen" was a true statement about a single 5 s window, not a bug — the next query simply hadn't arrived yet.

- **"Querier silent" threshold margin** — ✅ ADDRESSED (2026-05-30). The old fixed 130 s threshold left only ~5 s of headroom on a default 125 s querier, so a single missed query produced a false `⚠ querier silent`. Replaced with an interval-aware threshold (`NetworkHealth::querier_silent_after_secs()` ≈ 2× observed interval, default 260 s) matching RFC 3376's "Other Querier Present Interval". (`src/stats.rs`, `src/report.rs`)

- **Snooping prunes multicast on a non-mirror port** — ✅ FIXED (2026-05-30). On the Luminex (IGMP-snooping) network, a standard non-mirror port received only always-flooded link-local multicast (mDNS) — Dante audio (`239.255.x.x`) and PTP (`224.0.1.x`) were pruned away because the passive monitor never sent IGMP joins. Fix: AVStreamLens now sends IGMP joins proactively and dynamically — at startup it joins PTP, SAP (`224.2.127.254`), and IGMPv3-reports (`224.0.0.22`) groups; then after each packet dispatch it drains `CaptureState::pending_join_groups` and opens a `UdpSocket::join_multicast_v4` for each new `239.x.x.x` address discovered from SAP/SDP media sections or from IGMPv3 Membership Report Group Records. The no-SPAN diagnostic in `report.rs` was broadened to distinguish multicast-snooping (now auto-resolved) from unicast subscriptions (still needs SPAN). **Remaining limitation**: Dante IGMPv2 on old switches — their reports go to the group address itself (`239.255.x.x`), which is itself snooped, creating a chicken/egg situation that the IGMPv3-report path cannot help. On modern switches (IGMPv3), the reports go to `224.0.0.22` (flooded) so we see them and can join. (`src/main.rs` — `join_multicast_groups`, `should_join_group`, drain loop; `src/capture.rs` — `CaptureState::pending_join_groups/joined_multicast`, `handle_igmp`, `handle_sap`; `src/parser.rs` — `parse_igmpv3_report`, `IgmpType::MembershipReportV3`; `src/report.rs` — diagnostic)

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
