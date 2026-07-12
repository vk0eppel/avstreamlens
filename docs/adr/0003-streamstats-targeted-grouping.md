# StreamStats stays mostly flat: group only the Dante Transmitter cluster

## Status

accepted

## Context

`StreamStats` is a ~45-field struct carrying, for one Stream: RTP quality
(loss/jitter/seq/ssrc), bitrate accounting, SDP/announcement enrichment,
clock-rate inference, QoS marks, and Dante Transmitter Class state. An
architecture review (issue #82) flagged it as a god struct and proposed splitting
all fields into ~5 sub-structs (RtpQuality / ClockInference / QosMarks /
TransmitterProfile / Announcement) for testability and locality.

## Decision

Extract **only** the Dante Transmitter Class cluster into a `TransmitterProfile`
sub-struct (`verdict`, `iat_samples`, `min_ttl`, `observed_dscp`, plus the
`record_*` / `timing_metronomic` / `classify` methods that read only those
fields). Leave the RTP-quality, bitrate, clock-inference, QoS, and announcement
fields flat on `StreamStats`.

A grouping only pays off when its fields are used **together and separately from
the rest** — that is what makes a cohesive sub-struct testable and localizes
change. Usage analysis across the three files that touch `StreamStats`:

- **Transmitter cluster** — `transmitter`/`iat_samples`/`min_ttl`/`observed_dscp`
  are Dante-only, used in a handful of sites (`handle_dante`, the report's
  transmitter tag, one diagnostic). They are exactly the inputs to the verdict.
  Cohesive **and** separable → a real sub-struct.
- **RTP-quality and bitrate fields** — `packets` (35 uses), `bitrate_bps` (24
  uses) and their siblings are read across `update()`, `diagnostics()`, the whole
  report render, and `reset_window`, in all three files. `update()` and
  `diagnostics()` read RTP + clock + QoS fields *together*. Grouping these would
  force `.rtp.`/`.bitrate.`/`.clock.` prefixes at 150+ sites and split single
  methods across sub-borrows — **noise with no locality gain**, because nothing
  uses them on their own.

## Considered options

- **Full 5-way split (the #82 proposal).** Rejected: for the fields used
  everywhere it adds prefix noise and cross-sub-struct borrows without
  concentrating any change; the deletion test says the grouping would *move*
  complexity (into `.rtp.` navigation), not remove it.
- **No split at all.** Rejected: it leaves the one genuinely cohesive,
  independently-testable cluster (Transmitter Class) tangled into the god struct,
  and keeps the classify/DSCP-gate logic reaching across loose fields.
- **Targeted extraction (chosen).** Captures the one real locality win —
  `TransmitterProfile::classify` owns the signal build + verdict and hands the
  bundle back so the DSCP gate can't drift — at ~15 sites, and leaves the
  hot-path fields where callers already expect them.

## Consequences

`StreamStats` is still a wide struct. A future architecture review will likely
re-flag it and re-propose the full split — this ADR is the answer: the split was
evaluated and confined to the Transmitter cluster on purpose, because the
remaining fields are used pervasively and together. Revisit only if a *different*
cohesive-and-separable cluster emerges (e.g. if bitrate accounting stops being
read by the report render, or clock-inference scratch stops being touched by
`update`).
