# Dante-vs-ST2110 classification: wire heuristic with a zone-scoped device tie-breaker

## Status

accepted

## Context

A Dante Audio Flow and an ST2110 stream can be indistinguishable on the wire.
Dante's default multicast block is `239.255.0.0/16` with even audio ports in
5000–6000; ST2110 is `239.x.x.x` with RTP. The two collide exactly inside
`239.255/16` on an even 5000–6000 destination port. `detect_protocol`
classifies purely from the wire (port ranges, the `239.255/16` block, and the
official ATP ports 4321 / 14336–15359), so in that overlap an ST2110 flow can be
mislabelled Dante.

We already maintain `dante_sources`, populated from mDNS Device Discovery and
ConMon — an independent, authoritative signal that a given source IP is a Dante
Device. The question was whether, and how much, to let device identity steer
audio classification.

## Decision

Keep the wire heuristic as the default and use device discovery as a
**tie-breaker only inside the ST2110-collision zone** (`239.255/16`, even dst
port 5000–6000). There, a `dante_sources` match upgrades confidence toward Dante
and a known-ST2110-device match downgrades it. Everywhere else — including the
unambiguous ATP ports, which nothing else uses — classification stays pure wire
heuristic. Device discovery never *gates* classification.

## Considered options

- **Pure wire heuristic (status quo).** Stateless, classifies on the first
  packet even before any device is discovered, but keeps the ST2110 false
  positive.
- **Hard gate on `dante_sources`.** Only commit to "Dante" when the source IP is
  a discovered Dante Device. Rejected: on an IGMP-snooped network the mirror port
  often sees the audio Flows while the standard port is starved of the device's
  mDNS — so a hard gate would mislabel real Dante as ST2110 and could stay blind
  indefinitely. That is the inverse of, and just as real as, the
  see-mDNS-but-no-streams case.
- **Zone-scoped tie-breaker (chosen).** Captures the discovery signal exactly
  where it disambiguates, without ever letting absent discovery blind the tool.

## Consequences

A future reader will see `dante_sources` consulted in one narrow port/IP zone and
nowhere else, and may assume it's an oversight — it is deliberate. The tool never
goes blind waiting on discovery, and the residual false positive is confined to
the one zone where an independent signal can correct it.
