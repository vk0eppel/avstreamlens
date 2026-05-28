# AVStreamLens

Passive CLI monitor for professional AV-over-IP networks. Designed for AV engineers and technicians who need to visualise stream activity and diagnose problems on live Dante, AES67, ST 2110, NDI, and AVB installations — without touching switches or interrupting traffic.

AVStreamLens reads the network passively using pcap, identifies streams and clock sources, and prints a plain-language report every 5 seconds.

---

## Supported Protocols

| Protocol | Transport | What is monitored |
|---|---|---|
| **AES67** | UDP multicast (239.69.*) | Loss, jitter, SSRC changes, timing discontinuities, payload type, signal gap detection, PTPv2 clock, ts-refclk validation, DSCP |
| **SMPTE ST 2110** | UDP multicast (239.x.x.x) | Video (2110-20), audio (2110-30), ancillary (2110-40) — same RTP metrics as AES67; video clock rate confirmed without SDP |
| **Dante** | UDP unicast or multicast / mDNS | Device names from mDNS, audio stream RTP metrics, signal gap detection, DSCP, PTPv1 clock |
| **NDI** | TCP (dynamic ports) | Source names from mDNS, bitrate, TCP quality, retransmissions, RST/FIN |
| **AVB / IEEE 802.1** | L2 Ethernet | gPTP grandmaster (802.1AS), MSRP bandwidth reservations (802.1Qat), MVRP VLAN registrations (802.1Q), AVTP stream IDs |

**Always monitored regardless of selection:** LLDP (for EEE detection).
**Monitored when relevant:** PTP when AES67/ST2110/Dante/AVB selected — IGMP when AES67/ST2110/Dante selected — SAP when AES67/ST2110 selected.

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

**Windows**

Install [Npcap](https://npcap.com) (the modern WinPcap replacement). During installation, enable **"Install Npcap in WinPcap API-compatible mode"**.

**Rust toolchain**
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Capturing packets requires elevated privileges — run as `sudo` on macOS/Linux, or as **Administrator** on Windows.

---

## Build

```
cargo build --release
```

The binary is at `target/release/avstreamlens`.

---

## Usage

**Interactive** (prompts for interface and protocol on startup):
```
sudo ./target/release/avstreamlens
```

**Non-interactive** (skip prompts — useful for scripts and SSH sessions):
```
sudo ./target/release/avstreamlens --interface en0 --protocol aes67,dante
sudo ./target/release/avstreamlens -i eth0 -p all
sudo ./target/release/avstreamlens --help
```

On startup:
1. Select the network interface to monitor (or supply `--interface`)
2. Select which protocols to watch (or supply `--protocol`, or press Enter for all)
3. Reports print every 5 seconds; a timestamped `.log` file is written in the current directory

---

## CLI Flags

| Flag | Short | Description |
|---|---|---|
| `--interface <name>` | `-i` | pcap device name to capture on (e.g. `en0`, `eth0`) |
| `--protocol <list>` | `-p` | Comma-separated protocols: `all` `audio` `video` `aes67` `avb` `dante` `ndi` `st2110` |
| `--help` | `-h` | Show usage and exit |

Protocol names are case-insensitive. The interactive-mode numbers (0–7) are also accepted for scripting convenience. When a flag is omitted, AVStreamLens falls back to the interactive prompt for that item.

---

## Capture Setup — Monitoring One or Multiple VLANs

AVStreamLens has no per-VLAN configuration: it parses any VLAN delivered to the capture interface. 802.1Q, 802.1ad, and QinQ tags are stripped transparently before protocol detection, so AVB, PTP, and IP streams are recognised regardless of tagging.

What you actually see is determined by the **switch port** you plug into, not by the app:

| Port type | Visibility |
|---|---|
| **Access port** | One VLAN, untagged. You see only the streams on that VLAN. |
| **Trunk port** | Every VLAN the trunk carries, tagged. AVStreamLens peels the tags and parses normally. |
| **SPAN / mirror port** | Whatever the switch's mirror session copies. This is the usual way to monitor production AV networks without disturbing live traffic. |

**To monitor multiple VLANs at once**, ask the network team to configure a SPAN/mirror session that copies the trunk(s) carrying AV traffic, or plug the capture host into an existing trunk port.

**Caveats**

- **macOS** — Many macOS drivers strip the 802.1Q tag before pcap sees it. Stream detection still works (the inner payload is intact), but you lose visibility into *which* VLAN a stream rode on. Linux generally preserves the tag.
- **QinQ** — libpcap's BPF compiler handles a single 802.1Q tag transparently for `ether proto` matches, but stacked QinQ can hide L2 protocols (PTP, AVB) from the kernel filter on some drivers. If AVB or gPTP is missing on a known-good QinQ trunk, that's the first place to look.

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
- PTP, IGMP, and SAP are enabled automatically when the selected protocols require them — see the "Always monitored" note in Supported Protocols above.

---

## Report Layout

```
──────────────────────────────────────────────────────────────────
  AVStreamLens  ·  2026-05-17 14:32:00
──────────────────────────────────────────────────────────────────

📊 Bandwidth: 12.4 Mbps (last 5s)  |  AES67: 3  |  Dante: 1
✓  All streams healthy

📡 Streams:
  ▸ AES67  "Stage Mix"  [L24/48000/2]  —  239.69.0.1:5004
    loss: 0.0%  |  jitter: 0.18 ms  |  2.3 Mbps
  ▸ Dante  "Stage Box"  —  192.168.1.45:5010
    loss: 0.0%  |  jitter: 0.04 ms  |  0.8 Mbps
  ▸ NDI  "Studio Camera"  —  192.168.1.46
    healthy  |  120.3 Mbps  |  retrans: 0
  ▸ AVB  IEC 61883  —  00:1a:e5:ff:fe:12:34:56:0001
    loss: 0.0%  |  2.3 Mbps
    ✓  Reserved  VLAN 100  prio 3  ✓  Listener Ready

🕐 Clock Sources:
  ✓  PTPv2  —  grandmaster 00:1a:e5:ff:fe:78:9a:bc  (192.168.1.1)
    clock quality: Primary reference — locked  < 100 ns
  ✓  PTPv1  —  grandmaster 00:1a:e5:ff:fe:12:34:56
    clock quality: Primary reference  GPS
  ✓  AVB  —  grandmaster 00:1a:e5:ff:fe:ab:cd:ef

🔬 Network Health — 97%:
   QoS: ✓ all streams correctly marked  |  IGMP: ✓ querier 42s ago  (interval 125s)
   ⚠  EEE active on 1 switch port(s) — may cause audio/video glitches
      port "Gi0/1"  chassis 00:1a:2b:3c:4d:5e  Tx wake: 16µs  Rx wake: 16µs
   📦 48 120 pkts received  |  0 kernel drop(s)  |  0 interface drop(s)
```

**Status line** — `✓ All streams healthy` or `⚠ N issue(s)` with a brief description.

**Alerts** appear inline when problems are detected. Alerts on cumulative metrics (loss, timing discontinuities) include both a per-window count and the lifetime total, so an old loss does not re-alert forever:

*Per-stream:*
- `⚠  Audio glitch risk — timing discontinuity detected (N in last 5s)`
- `⚠  Packet loss detected (N in last 5s, X.XX% cumulative)`
- `⚠  Packet reorder X.X% (N in last 5s) — possible per-packet load-balancing`
- `⚠  QoS: N packet(s) not marked EF (46) — may be deprioritised by switches`
- `⚠  Signal gap detected (N in last 5s, worst X.X ms) — stream interrupted`
- `⚠  RTP payload type mismatch — encoder/SDP misconfiguration`
- `⚠  Dante clock or subscription issue`
- `⚠  Stream not announced (no SAP) — audio glitch detection unavailable`
- `⚠  Stream type unknown — SDP required to classify as video/audio/ancillary`
- `💀 No signal for 12s`

*Clock / PTP:*
- `⚠  No PTPv2 clock — AES67 streams may lose sync` (or `AES67 and ST2110`)
- `⚠  No PTPv1 or PTPv2 clock — Dante streams may lose sync`
- `⚠  No L2 gPTP clock — AVB streams may lose sync`
- `⚠  Large PTP correction field — transparent clock or path issue`
- `⚠  PTP path-delay variance > 10µs — unstable link (EEE, half-duplex, or cable)`
- `⚠  PTP path delay > 1ms — too many hops between this node and grandmaster`

*Network infrastructure:*
- `⚠  ECN: N congestion mark(s) — router congestion detected on the path`
- `⚠  PAUSE frames: N in last 5s — upstream link congestion causing tx-side freezes`
- `⚠  PFC frames: N in last 5s — priority flow control engaged on upstream link`
- `⚠  EEE active on switch port(s) — may cause audio/video glitches`
- `⚠  No VLAN registration — L2 QoS may not be configured`
- `❌ Capture drops detected — loss/jitter figures may be understated` (shown in red when pcap kernel or interface drops are non-zero)

PAUSE and PFC detection is best-effort: most NICs consume these frames at the MAC layer before pcap sees them. The absence of these alerts therefore does NOT prove no upstream congestion is happening.

The **pcap capture stats line** (`📦 N pkts received | N kernel drop(s) | N interface drop(s)`) always appears at the bottom of the Network Health section. Kernel drops mean the pcap ring buffer overflowed; interface drops mean packets were lost at the NIC before pcap. Either type of drop corrupts loss and jitter numbers — if you see this alert, reduce traffic load or increase the pcap buffer size.

---

## Health Score

The health percentage reflects the overall network quality. Factors that reduce the score include packet loss, high jitter, timestamp discontinuities, source interruptions (SSRC changes), dead streams, PTP clock loss or instability, QoS tagging violations, IGMP querier absence, AVB bandwidth reservation failures, and EEE active on switch ports.

---

## Platform Notes

- **macOS and Linux** — requires libpcap
- **Windows** — requires [Npcap](https://npcap.com); run as Administrator; colour output requires Windows Terminal or VS Code (not supported in classic `cmd.exe`)
- Loopback (`lo`/`lo0`) is excluded — macOS loopback uses a non-Ethernet link layer incompatible with the packet parser
- Promiscuous mode is enabled automatically on the selected interface
- Virtual and tunnel interfaces (utun, awdl, docker, vpn…) are filtered from the interface list on macOS/Linux; Windows interface names are passed through as-is

---

## Known Limitations

- **PAUSE / PFC detection is best-effort** — most NICs consume these frames at the MAC layer before pcap sees them. Absence of these alerts does not prove no upstream congestion.
- **EEE absence is not confirmed** — AVStreamLens detects EEE only when the switch sends LLDP with the EEE TLV. No LLDP does not mean EEE is disabled.
- **macOS VLAN tag stripping** — many macOS drivers strip 802.1Q tags before pcap, so per-VLAN stream attribution may be unavailable on macOS trunk/SPAN ports. Linux generally preserves tags.
- **NDI on loopback unsupported** — macOS loopback uses a non-Ethernet link layer; mDNS multicast does not flow over loopback.
- **No per-VLAN filtering** — the tool processes all VLANs delivered by the capture interface. Use a SPAN session scoped to the target VLAN(s) to limit visibility.

## Roadmap

See [TODO.md](TODO.md) for the full list of open issues and planned features. Highlights:

- `--vlan <id>` flag to filter captured traffic to a specific VLAN
- Dante AV video stream detection and metrics
- Health score penalty weight review
