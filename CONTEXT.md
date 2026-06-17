# AVStreamLens

A CLI tool for capturing and diagnosing professional AV network traffic — AES67, Dante, ST2110, NDI, and AVB — in real time.

## Language

**Stream**:
A media-carrying network flow between a source and destination, identified by protocol-specific keys, whose quality metrics (loss, jitter, bitrate) are tracked over time. Infrastructure traffic (PTP, IGMP, MSRP, ConMon) is not a Stream.
_Avoid_: flow (as a generic synonym — but "Flow" is retained in its Dante-specific sense, see Dante Audio Flow), session, connection

**Mirror Port**:
A switch port configured to receive a copy of traffic from one or more other ports or VLANs, making otherwise invisible unicast flows observable to AVStreamLens. Required to see Dante unicast audio, NDI streams, and any other non-multicast traffic on a managed switch. Without a mirror port, only multicast and broadcast traffic is visible.
_Avoid_: SPAN port (Cisco-specific), monitor port, tap

**AV Professional**:
The intended user of AVStreamLens — a live sound engineer, broadcast engineer, video or lighting technician, or systems integrator who works with AV protocols professionally but without specialist IT or networking knowledge. Alert and Diagnostic language should assume familiarity with AV concepts (subscriptions, grandmaster, latency) but explain network infrastructure consequences in plain terms rather than assuming networking expertise.
_Avoid_: AV engineer, AV technician, user (too generic)

**Session**:
A single run of AVStreamLens from start to exit, during which packets are observed and Streams, Alerts, and Diagnostics are produced. A Session operates in one of two modes: live (packets captured from a network interface) or replay (packets read from a pcap file). State accumulated during a Session does not persist to the next.
_Avoid_: capture (use only for the generic act of capturing packets, not for a Session), run

**Alert**:
A transient event notification printed once when a state change occurs — a Clock Source being detected, lost, or changed; a new device discovered; EEE found on a port. Not stored across Windows. Has a severity level: Info, Good, Warn, or Error.
_Avoid_: event, notification, message

**Diagnostic**:
A persistent condition derived from Stream or infrastructure state, re-evaluated and shown every Window in the report. Examples: stream loss percentage, missing Clock Source, IGMP querier absent. Unlike an Alert, a Diagnostic reflects ongoing state rather than a moment of change.
_Avoid_: alert (when referring to persistent conditions), warning, status

**Device Discovery**:
The process of learning that a network participant exists, independent of whether it is transmitting a Stream. Sources: mDNS for Dante and NDI devices, AVDECC ADP for AVB entities, ConMon for Dante liveness. A device can be discovered with zero active Streams — the diagnostic "devices announced but no active flows" fires in exactly that case.
_Avoid_: discovery (unqualified — ambiguous with Session Announcement)

**Session Announcement**:
The process of learning that a Stream exists and its parameters (codec, multicast group, Clock Source reference, packet time) before or alongside RTP traffic arriving. Carried by SAP/SDP for AES67 and ST2110. Enables stream enrichment: a Stream receiving its Session Announcement gains clock rate, payload type, and name. Retroactive — a Stream seen before its announcement is enriched when the announcement arrives.
_Avoid_: stream discovery, stream advertisement, SDP announcement

**Health Score**:
A 0–100 composite score representing the quality of the observable AV delivery chain within the current Window — from source device across the network as far as the tool can see. It reaches the destination end only when that end is itself observable (unicast Streams, or receivers whose return/ConMon traffic is seen); for a multicast Dante Audio Flow the tool confirms clean transmission onto the wire but cannot confirm any receiver is subscribed or consuming, so "healthy" there means "transmitted cleanly," not "delivered." Penalises both stream-level issues (loss, jitter, dead streams) and infrastructure issues (missing Clock Source, IGMP querier absence, EEE, QoS violations). A single number that summarises the state of the observable path without requiring the user to interpret individual metrics. Tool limitations (pcap kernel drops) do not affect the Health Score — they are captured in Network Status only.
_Avoid_: network score, quality score, health index

**Health Summary**:
A collapsed bullet list rendered directly after the Health Score line, present only when the Health Score is below 100%. Lists every factor contributing to score deductions — stream-level issues collapsed by type (e.g. "2 streams with packet loss") and infrastructure issues individually. Every bullet corresponds to a score penalty; every score penalty has a bullet. Replaces the previous single-line status summary.
_Avoid_: issue list, alert summary, status summary

**Network Status**:
The persistent infrastructure readout section at the bottom of each report, always shown regardless of Health Score. Displays bandwidth, QoS summary, IGMP querier status, EEE, PAUSE/PFC, ECN, and pcap capture statistics. Renamed from "Network Health detail" to avoid confusion with the Health Score. Infrastructure problems that appear here and contribute to the Health Score also appear in the Health Summary at the top; pcap drops appear here only.
_Avoid_: Network Health detail, infrastructure detail, health detail

**Clock Source**:
The device (or stream) that provides the audio clock reference for a protocol family. Manifests differently per protocol: the elected Preferred Master device in Dante (which may itself be locked to an external reference such as word clock or AES3); the PTP grandmaster in AES67 and ST2110; the gPTP grandmaster in AVB/Milan. A CRF stream is both a Stream and a Clock Source — it distributes clock reference over AVTP. The absence of a Clock Source is a network fault for any protocol that requires one.
_Avoid_: master clock, timing source, grandmaster (use grandmaster only when referring specifically to the PTP/gPTP role, not the concept in general)

**Window**:
A fixed observation period between successive reports, during which per-metric counters accumulate. Metrics that measure rate or frequency (loss, gaps, jitter) are scoped to the current Window; lifetime totals are tracked separately and never reset. Currently 5 seconds; intended to be configurable.
_Avoid_: cycle, interval, tick

**Stream Identity**:
The (source IP, destination IP, destination port) triple that uniquely identifies a Stream. Two packets belong to the same Stream if and only if all three fields match. Protocol label is display context, not part of the identity.
_Avoid_: stream key, stream ID

**Dante Audio Flow**:
The Dante-specific name (Audinate's own term) for a Stream carrying Dante audio. A Flow carries one or more Tx channels from a single transmitter to one or more receivers: unicast Flows are point-to-point (typically ~4 channels); multicast Flows are one-to-many, carry a Dante-assigned Flow ID, and consume network bandwidth even with zero receivers. One domain concept regardless of wire encoding — it may be RTP-framed (loss, jitter, SSRC measurable) or ATP-framed (only packet rate and bitrate observable); the encoding is an observability property, not a separate kind of thing. This is the only thing the tool actually observes for Dante audio routing — Channels and Subscriptions are inferred, never seen directly.
_Avoid_: Dante stream, ATP stream, Dante RTP stream

**Subscription**:
A Dante receive-channel-level configuration binding one Rx channel to one Tx channel on another Device. It lives inside the Device, not on the wire — AVStreamLens cannot observe a Subscription directly; it only ever sees the Dante Audio Flow that results. Many Subscriptions may be served by one multicast Flow, and a Subscription may exist with no observable Flow (muted, or no Mirror Port for that direction). Reference it only as a candidate root cause inferred from Flow behaviour, never as something measured.
_Avoid_: Dante route, channel subscription, Rx subscription

**Transmitter Class**:
Which kind of Dante implementation is sourcing a Dante Audio Flow — one of three: **Hardware** (an FPGA/embedded endpoint), **DVS** (Dante Virtual Soundcard — software Dante on a general-purpose computer), or **Via** (Dante Via — a distinct software product, not the same thing as DVS). "Software Dante" is not a single class; DVS and Via are siblings. Identified positively when its control-plane traffic is observable (each class uses a distinct, product-specific control/monitoring port family), and otherwise inferred from Flow-level signals — packet-timing regularity (hardware is metronomic, software is scheduler-sloppy), host TTL, source-MAC vendor class, and, as a last resort, absent QoS marking. Positive control-plane identification usually needs a Mirror Port; the inferred signals do not. Always a confidence verdict from independent signals, never a single-signal boolean.
_Avoid_: software vs hardware Dante (too binary — Via is neither), DVS detection (the concept is the class, not just DVS)
