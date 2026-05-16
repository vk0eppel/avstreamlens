# AVStreamLens

Passive CLI monitor for professional AV-over-IP networks. Designed for AV engineers and technicians who need to visualise stream activity and diagnose problems on live Dante, AES67, ST 2110, NDI, and AVB installations — without touching switches or interrupting traffic.

AVStreamLens reads the network passively using pcap, identifies streams and clock sources, and prints a plain-language report every 5 seconds.

---

## Supported Protocols

| Protocol | Transport | What is monitored |
|---|---|---|
| **AES67** | UDP multicast (239.69.*) | Loss, jitter, SSRC changes, timing discontinuities, payload type, burst detection, PTPv2 clock, ts-refclk validation, DSCP |
| **SMPTE ST 2110** | UDP multicast (239.x.x.x) | Video (2110-20), audio (2110-30), ancillary (2110-40) — same RTP metrics as AES67; video clock rate confirmed without SDP |
| **Dante** | UDP unicast or multicast / mDNS | Device names from mDNS, audio stream RTP metrics, burst detection, DSCP, PTPv1 clock |
| **NDI** | TCP (dynamic ports) | Source names from mDNS, bitrate, TCP quality, retransmissions, RST/FIN |
| **AVB / IEEE 802.1** | L2 Ethernet | gPTP grandmaster (802.1AS), MSRP bandwidth reservations (802.1Qat), MVRP VLAN registrations (802.1Q), AVTP stream IDs |

**Always monitored regardless of selection:** PTP (IEEE 1588 / gPTP), IGMP, and LLDP (for EEE detection).

---

## Prerequisites

**macOS**
```
brew install libpcap   # usually already present
```

**Linux**
```
sudo apt install libpcap-dev
```

**Rust toolchain**
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Capturing packets requires elevated privileges — run as `sudo` or grant the binary `cap_net_raw`.

---

## Build

```
cargo build --release
```

The binary is at `target/release/avstreamlens`.

---

## Usage

```
sudo ./target/release/avstreamlens
```

On startup:
1. Select the network interface to monitor
2. Select which protocols to watch (or press Enter for all)
3. Reports print every 5 seconds; a timestamped `.log` file is written in the current directory

---

## Protocol Selection

```
Choose the protocols to monitor:
  0) All
  1) Audio (AES67 + Dante + AVB)
  2) Video (ST2110 + NDI)
  3) AES67
  4) AVB
  5) Dante
  6) NDI
  7) ST2110
  [Separate by commas, e.g. '1,2,3' or enter for all]
```

- **Audio** and **Video** are convenience groups — selecting Audio captures AES67, Dante, and AVB streams in one step.
- PTP and IGMP are always captured regardless of selection.

---

## Report Layout

```
╔══════════════════════════════════════════════════╗
║  2026-05-15 14:32:00 | AVStreamLens  |  Health: 97%
╚══════════════════════════════════════════════════╝

📊 Bandwidth: 12.4 Mbps (last 5s)  |  AES67: 3  |  Dante: 1
✓  All streams healthy

  ▸ AES67  "Stage Mix"  [L24/48000/2]  —  239.69.0.1:5004
    loss: 0.0%  |  jitter: 0.18 ms  |  2.3 Mbps

  ▸ Dante  "Stage Box"  —  192.168.1.45:5010
    loss: 0.0%  |  jitter: 0.04 ms  |  0.8 Mbps

🔗 AVB:
  ✓ VLAN QoS active: 100
  ✓ Talker 00:1a:e5:ff:fe:12:34:56  2.3 Mbps  VLAN 100  prio 3
    ✓ Listener Ready

🕐 Clock Sources:
  ✓  PTPv2  —  grandmaster 00:1a:e5:ff:fe:78:9a:bc  (192.168.1.1)
      clock quality: Primary reference — locked  < 1 µs
  ✓  PTPv1  —  grandmaster 00:1a:e5:ff:fe:12:34:56
      clock quality: Primary reference  GPS
  ✓  AVB  —  grandmaster 00:1a:e5:ff:fe:ab:cd:ef

   QoS: ✓ DSCP EF (1247 pkts)  |  IGMP: ✓ querier 42s ago
   ⚠  EEE active on 1 switch port(s) — may cause audio/video glitches
      port "Gi0/1"  chassis 00:1a:2b:3c:4d:5e  Tx wake: 16µs  Rx wake: 16µs
```

**Status line** — `✓ All streams healthy` or `⚠ N issue(s)` with a brief description.

**Alerts** appear inline when problems are detected:
- `⚠  Audio glitch risk — timing discontinuity detected`
- `⚠  Packet loss detected`
- `⚠  Signal gap detected (N in last 5s, worst X.X ms) — stream interrupted`
- `⚠  RTP payload type mismatch — encoder/SDP misconfiguration`
- `⚠  Dante clock or subscription issue`
- `⚠  No clock source — streams requiring PTP may lose sync`
- `⚠  Large PTP correction field — transparent clock or path issue`
- `⚠  EEE active on switch port — disable EEE for AV reliability`
- `⚑  Stream not announced (no SAP) — audio glitch detection unavailable`
- `⚠  Stream type unknown — SDP required to classify as video/audio/ancillary`
- `💀 No signal for 12s`

---

## Health Score

The health percentage reflects the overall network quality. Factors that reduce the score include packet loss, high jitter, timestamp discontinuities, source interruptions (SSRC changes), dead streams, PTP clock loss or instability, QoS tagging violations, IGMP querier absence, AVB bandwidth reservation failures, and EEE active on switch ports.

---

## Platform Notes

- **macOS and Linux only** — requires libpcap
- Loopback (`lo`/`lo0`) is excluded — macOS loopback uses a non-Ethernet link layer incompatible with the packet parser
- Promiscuous mode is enabled automatically on the selected interface
- Virtual and tunnel interfaces (utun, awdl, docker, vpn…) are filtered from the interface list
