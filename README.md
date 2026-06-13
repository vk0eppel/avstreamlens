# AVStreamLens

Passive CLI monitor for professional AV-over-IP networks. Designed for AV engineers and technicians who need to visualise stream activity and diagnose problems on live Dante, AES67, ST 2110, NDI, and AVB installations — without touching switches or interrupting traffic.

AVStreamLens reads the network passively using pcap, identifies streams and clock sources, and prints a plain-language report every 5 seconds.

---

## Supported Protocols

| Protocol | Transport | What is monitored |
|---|---|---|
| **AES67** | UDP multicast (239.69.*) | Loss, jitter, SSRC changes, timing discontinuities, payload type, signal gap detection, PTPv2 clock, ts-refclk validation, DSCP |
| **SMPTE ST 2110** | UDP multicast (239.x.x.x) | Video (2110-20), audio (2110-30), ancillary (2110-40) — same RTP metrics as AES67; video clock rate confirmed without SDP |
| **Dante** | UDP unicast or multicast / mDNS / ConMon | Device names from mDNS, live-device detection + channel count from ConMon multicast (no SPAN needed), audio stream metrics (RTP, or presence/bitrate for ATP-framed flows), signal gap detection, DSCP, PTPv1 clock |
| **NDI** | TCP (dynamic ports) | Source names from mDNS, bitrate, TCP quality, retransmissions, RST/FIN |
| **AVB / IEEE 802.1** | L2 Ethernet | gPTP grandmaster (802.1AS), MSRP bandwidth reservations (802.1Qat), MVRP VLAN registrations (802.1Q), AVTP stream IDs, AVDECC entity discovery (IEEE 1722.1) |

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
sudo ./target/release/avstreamlens -i en0 -p aes67 --duration 30 && echo OK
sudo ./target/release/avstreamlens --help
```

**Offline pcap replay** (no root required — analyse a file captured earlier):
```
./target/release/avstreamlens --read capture.pcapng
./target/release/avstreamlens -r site_visit.pcap --protocol dante
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
| `--read <file>` | `-r` | Replay a `.pcap` / `.pcapng` file offline — **no root required** |
| `--duration <secs>` | `-d` | Stop after N seconds; exit 0 if healthy (100%), exit 1 if any issues detected |
| `--quiet` | `-q` | Silent on healthy cycles; print the full report only when issues are detected |
| `--no-color` | | Disable ANSI colour output (also honoured via the `NO_COLOR` env var) |
| `--help` | `-h` | Show usage and exit |

Protocol names are case-insensitive. The interactive-mode numbers (0–7) are also accepted for scripting convenience. When a flag is omitted, AVStreamLens falls back to the interactive prompt for that item.

`--quiet` is useful for long-running monitoring sessions piped to a log file or `tail -f`: no output is produced on healthy cycles, so the terminal stays clean and each new report is immediately visible as an issue. The log file always receives the full report regardless of `--quiet`.

`--duration` enables one-shot scripted health checks. AVStreamLens captures for N seconds (at least one full 5-second report cycle), then exits with code 0 if the network health score is 100% or code 1 if any issue was detected. Pair with `--quiet` to suppress the intermediate report output: `avstreamlens -i en0 -p aes67 --duration 30 --quiet && echo OK`.

---

## Capture Methods

### Live capture (requires root / sudo)

AVStreamLens opens a live pcap handle on the selected interface in promiscuous mode. It joins multicast groups dynamically so IGMP-snooped switches deliver stream traffic to the capture port without a SPAN. Reports print every 5 seconds; use Ctrl-C to stop.

```
sudo ./target/release/avstreamlens -i en0 -p dante
```

**To avoid typing sudo every time on macOS** (non-persistent, resets on reboot):
```
sudo chmod o+r /dev/bpf*
./target/release/avstreamlens -i en0 -p dante
```

**On Linux** (permanent, survives reboots):
```
sudo setcap cap_net_raw+ep ./target/release/avstreamlens
./target/release/avstreamlens -i eth0 -p dante
```

### Offline pcap replay (no root needed)

Capture a `.pcap` or `.pcapng` file on-site with Wireshark or tcpdump, then replay it anywhere — no network interface, no root required. 5-second report windows are driven by the pcap packet timestamps, so you see the same view as a live capture would have produced. The tool exits at EOF and prints a final report.

```
# Capture on-site:
sudo tcpdump -i en0 -w site_visit.pcap

# Analyse later (no sudo):
./target/release/avstreamlens --read site_visit.pcap --protocol dante
./target/release/avstreamlens -r site_visit.pcapng
```

Protocol defaults to `all` when `--read` is given without `--protocol`. BPF filter is still applied. mDNS startup probe and IGMP joins are skipped (not meaningful for offline data). Device names from mDNS will only appear if mDNS traffic was captured in the file — there is no live probe to trigger responses.

---

## Capture Setup — Choosing the Right Switch Port

What AVStreamLens can see depends entirely on which switch port you connect to. The right choice depends on which protocols you are monitoring.

### What any port gives you (no SPAN needed)

AVStreamLens is a **passive capture tool** — it reads traffic delivered to its network interface. Multicast and L2 broadcast traffic is delivered to every port on the switch, so the following is visible from any access port, trunk port, or SPAN port:

| Protocol | Why visible without SPAN |
|---|---|
| **AES67** | UDP multicast (239.69.*) — AVStreamLens auto-joins these groups |
| **SMPTE ST 2110** | UDP multicast (239.x.x.x) — AVStreamLens auto-joins these groups |
| **Dante audio (multicast)** | 239.255.x.x — AVStreamLens auto-joins groups as streams are discovered |
| **AVB — AVTP stream data** | MAAP-allocated multicast MACs — forwarded like normal multicast |
| **AVB — AVDECC entities** | ADP uses MAC `91:E0:F0:01:00:00` (globally registered, bridges MUST forward) |
| **PTP, IGMP, SAP** | Multicast — AVStreamLens joins PTP and SAP groups at startup |
| **Dante / NDI discovery** | mDNS multicast (link-local, always flooded) — delivered to every port |
| **Dante device liveness (ConMon)** | Control & monitoring multicast (224.0.0.230–233, link-local, always flooded) — every live Dante device is visible at ~33 packets/s, with its channel count |
| **Dante PTPv1 clock** | Multicast — delivered to every port |

> **AVB gPTP / MSRP / MVRP are NOT delivered to every port.** They use link-local reserved MACs (`01:80:C2:00:00:0E`, `…:21`) in the IEEE range that bridges must **not** forward — they are hop-by-hop, so you only ever see the copy on your own link, not a remote grandmaster. See *Monitoring gPTP / the AVB grandmaster* below.

**IGMP snooping:** Managed switches with IGMP snooping only deliver multicast traffic to ports that have sent an IGMP Membership Report for that group. AVStreamLens handles this automatically — at startup it joins the PTP and SAP groups, and during capture it dynamically joins stream multicast addresses as they are discovered from SAP/SDP announcements and from IGMPv3 Membership Reports sent by other devices on the network. On a snooping switch the stream groups appear in the log file as `✓ Joined stream multicast 239.69.x.x` entries. No switch configuration is needed.

For AES67 and ST 2110 you can plug into any port on the switch and get full visibility. For AVB you will see **stream data** and your own link's MSRP/gPTP, but the **grandmaster and time domain are only visible on a time-aware (AVB-enabled) port** — see below.

### When you need a SPAN port

A switch forwards **unicast** frames only to the destination port. Promiscuous mode does not change this — it lets the NIC accept frames addressed to other MAC addresses, but only frames the switch has already forwarded to that port.

SPAN is required when you need to see **unicast flows between two other devices**:

- **Dante audio (unicast subscriptions)** — Dante subscriptions are unicast by default. If a flow runs between two devices that are not the capture machine, the switch delivers those packets only to those two ports. A SPAN session mirroring those ports (or the whole VLAN) is the only way to see them. Note: Dante multicast audio (239.255.x.x) does **not** require SPAN — AVStreamLens joins those groups automatically.
- **NDI streams** — NDI uses TCP (unicast). Same constraint as Dante unicast audio.

AVStreamLens detects this situation for you: because mDNS discovery is multicast and always visible, the report lists the discovered Dante/NDI devices under **📇 Discovered (mDNS)** and warns when devices are present but their flows are not visible — distinguishing multicast-snooping (resolved automatically by IGMP join) from unicast flows that still need a mirror port.

How to configure a SPAN session depends on the switch vendor:

| Switch family | How to configure port mirroring |
|---|---|
| Cisco IOS / IOS-XE | `monitor session 1 source interface Gi0/1 - 24` / `monitor session 1 destination interface Gi0/48` |
| Cisco Catalyst (GUI) | **Admin → Diagnostics → Port Mirroring** |
| Aruba / HP ProCurve | `mirror 1 port Trk1` + `interface X mirror 1` |
| Juniper EX | `set forwarding-options analyzer <name> input ... output interface <port>` |
| Luminex GigaCore | **Port Mirroring** tab in the web UI — select source ports and mirror destination |
| Netgear ProSafe | **Switching → Port Mirroring** in the web UI |
| Unmanaged switch | No SPAN capability — use a **network tap** or replace with a managed switch |

**Typical SPAN setup for a Dante or NDI network:**
1. Connect the capture machine to a spare port on the managed switch.
2. Configure a SPAN session that mirrors the uplink port (or the entire AV VLAN) to that port.
3. Run AVStreamLens — it will now see all unicast and multicast flows on the mirrored segment.

### Monitoring gPTP / the AVB grandmaster

AVB's clock protocol, **gPTP (IEEE 802.1AS)**, behaves differently from every other protocol here, and it surprises people: **you cannot see the grandmaster from an arbitrary port.**

gPTP frames use the link-local destination MAC `01:80:C2:00:00:0E`, which lives in the reserved `01:80:C2:00:00:00`–`0F` range that bridges are **required not to forward**. gPTP is *hop-by-hop*: each time-aware switch consumes the grandmaster's Sync/Announce on its upstream port and **regenerates its own** Sync/Announce on each downstream port. So the grandmaster's actual Announce never travels more than one link — you only ever see the gPTP of your **direct link partner**.

This is the opposite of AES67/Dante/ST 2110 PTP, which is ordinary **IP** multicast and floods the whole VLAN (so those grandmasters show up from any port).

**Consequences for monitoring:**

- If your capture port is **not** an AVB-enabled (time-aware) port, you will see at most the directly-attached device's `P_Delay_Req` traffic — **no Sync, no Announce, no grandmaster.** AVStreamLens reports this as `peer-delay requests only — link partner may not be gPTP-capable` and adds `ℹ gPTP is link-local — the grandmaster is only visible on a time-aware (AVB-enabled) port`.
- To actually observe the grandmaster's Announce, capture on (or SPAN-mirror) a **time-aware, AVB-enabled** link — ideally the link directly between the grandmaster device and its first switch. A mirror of a non-AVB port will **not** show it, because the frames were never forwarded there in the first place.
- The same link-local rule applies to **MSRP** (`01:80:C2:00:00:0E`) and **MVRP** (`…:21`): you see your own link's declarations, not a network-wide view. AVB **stream data (AVTP)** uses normal forwardable multicast and is not subject to this limitation.

### Trunk port vs access port

A trunk port carries multiple VLANs tagged with 802.1Q. It does **not** affect unicast forwarding — a trunk port gives the same unicast visibility as an access port. The difference is VLAN scope, not traffic coverage.

AVStreamLens has no per-VLAN configuration: it parses any VLAN delivered to the capture interface. 802.1Q, 802.1ad, and QinQ tags are stripped transparently before protocol detection, so AVB, PTP, and IP streams are recognised regardless of tagging.

| Port type | VLANs visible | Unicast between other devices |
|---|---|---|
| **Access port** | One VLAN, untagged | No |
| **Trunk port** | All VLANs the trunk carries, tagged | No |
| **SPAN / mirror port** | Depends on mirror session scope | Yes, for mirrored ports/VLANs |

To monitor streams across multiple VLANs, plug into a trunk port or configure a SPAN session scoped to the trunk.

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

📇 Discovered:
   Dante (5):  "Stage Box", "Yamaha-DM7", "TASCAM", "Amp-1", "Amp-2"  · 2 live
   NDI   (2):  "Studio Camera", "Playback PC"

🕐 Clock Sources:
  ✓  PTPv2  —  grandmaster 00:1a:e5:ff:fe:78:9a:bc  (192.168.1.1)
    clock quality: Primary reference — locked  < 100 ns
  ✓  PTPv1  —  grandmaster "Stage Box"  (169.254.10.20)
    clock quality: Preferred grandmaster
  ✓  AVB  —  grandmaster 00:1a:e5:ff:fe:ab:cd:ef

🔬 Network Health — 97%:
   QoS: ✓ all streams correctly marked  |  IGMP: ✓ querier 42s ago  (interval 125s)
   ⚠  EEE active on 1 switch port(s) — may cause audio/video glitches
      port "Gi0/1"  chassis 00:1a:2b:3c:4d:5e  Tx wake: 16µs  Rx wake: 16µs
   📦 48 120 pkts received  |  0 kernel drop(s)  |  0 interface drop(s)
```

**Status line** — `✓ All streams healthy` or `⚠ N issue(s)` with a brief description.

**Discovered** — Dante and NDI devices announce themselves over multicast mDNS, which reaches every switch port. This section lists those devices even when their actual audio/video flows are not visible. The `· N live` suffix on the Dante line shows real-time liveness from ConMon: Dante devices transmit control & monitoring multicast at ~33 packets/s on the link-local 224.0.0.230–233 groups, which snooping switches always flood — so AVStreamLens knows which devices are alive *right now*, not just which announced via mDNS at some point (`· all live` when every discovered device is also active in ConMon). On a plain (non-SPAN) port where Dante audio or NDI is unicast between other devices, you will see the devices here but no matching stream above — in that case AVStreamLens adds:

```
   ⚠  Devices announced but no active flows — unicast flows need a SPAN/mirror port
```

This distinguishes "wrong interface / nothing here" from "the devices are present but their flows are unicast and need a mirror port" — see [Capture Setup](#capture-setup--choosing-the-right-switch-port).

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
- `⚠  Stream count spike: N streams (avg last 3 windows: M) — possible runaway multicast flood`
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
