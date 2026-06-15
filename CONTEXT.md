# AVStreamLens

A CLI tool for capturing and diagnosing professional AV network traffic — AES67, Dante, ST2110, NDI, and AVB — in real time.

## Language

**Stream**:
A media-carrying network flow between a source and destination, identified by protocol-specific keys, whose quality metrics (loss, jitter, bitrate) are tracked over time. Infrastructure traffic (PTP, IGMP, MSRP, ConMon) is not a Stream.
_Avoid_: flow, session, connection

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
A 0–100 composite score representing the quality of the end-to-end AV delivery chain within the current Window — from source device through the network to destination. Penalises both stream-level issues (loss, jitter, dead streams) and infrastructure issues (missing Clock Source, IGMP querier absence, EEE, QoS violations). A single number that summarises the state of the whole path without requiring the user to interpret individual metrics.
_Avoid_: network score, quality score, health index

**Clock Source**:
The device (or stream) that provides the audio clock reference for a protocol family. Manifests differently per protocol: the elected Preferred Master device in Dante (which may itself be locked to an external reference such as word clock or AES3); the PTP grandmaster in AES67 and ST2110; the gPTP grandmaster in AVB/Milan. A CRF stream is both a Stream and a Clock Source — it distributes clock reference over AVTP. The absence of a Clock Source is a network fault for any protocol that requires one.
_Avoid_: master clock, timing source, grandmaster (use grandmaster only when referring specifically to the PTP/gPTP role, not the concept in general)

**Window**:
A fixed observation period between successive reports, during which per-metric counters accumulate. Metrics that measure rate or frequency (loss, gaps, jitter) are scoped to the current Window; lifetime totals are tracked separately and never reset. Currently 5 seconds; intended to be configurable.
_Avoid_: cycle, interval, tick

**Stream Identity**:
The (source IP, destination IP, destination port) triple that uniquely identifies a Stream. Two packets belong to the same Stream if and only if all three fields match. Protocol label is display context, not part of the identity.
_Avoid_: stream key, stream ID
