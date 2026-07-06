// AVStreamLens — src/cli.rs
// Interactive CLI prompts: interface selection and protocol selection.

use pcap::{ConnectionStatus, Device};
use std::io::{self, Write};

use crate::protocols::ProtocolChoice;

// ── CLI argument parsing ─────────────────────────────────────────────────────

/// Parsed command-line flags. All fields are `None` when the flag was not
/// supplied — callers fall back to interactive prompts in that case.
pub struct CliArgs {
    /// `--interface <name>` — pcap device name (e.g. `en0`, `eth0`)
    pub interface: Option<String>,
    /// `--protocol <list>` — comma-separated protocol names or numbers
    pub protocols: Option<Vec<ProtocolChoice>>,
    /// `--no-color` or `NO_COLOR` env var — disable ANSI colour output
    pub no_color: bool,
    /// `--quiet` — suppress all stdout output on healthy cycles; print only
    /// the status line and active alerts when issues are detected.
    /// The log file always receives the full report.
    pub quiet: bool,
    /// `--duration <seconds>` — stop after N seconds and exit 0 (healthy) or 1 (issues).
    pub duration: Option<u64>,
    /// `--read <path>` — replay a .pcap file offline instead of live capture.
    /// No root required. Timing driven by pcap timestamps; exits at EOF.
    pub read_file: Option<String>,
}

/// Parse command-line arguments.  Exits with a helpful message on bad input.
pub fn parse_cli_args() -> CliArgs {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        std::process::exit(0);
    }

    // Honour the NO_COLOR env var (https://no-color.org/): presence of the variable,
    // regardless of its value (even empty string), disables ANSI colour output.
    let mut no_color = std::env::var_os("NO_COLOR").is_some();
    let mut interface = None;
    let mut protocols = None;
    let mut quiet = false;
    let mut duration = None;
    let mut read_file = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--interface" | "-i" => {
                if i + 1 < args.len() {
                    interface = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("❌ --interface requires a value (e.g. --interface en0)");
                    std::process::exit(1);
                }
            }
            "--protocol" | "-p" => {
                if i + 1 < args.len() {
                    protocols = Some(parse_protocol_str(&args[i + 1]));
                    i += 2;
                } else {
                    eprintln!("❌ --protocol requires a value (e.g. --protocol aes67,dante)");
                    std::process::exit(1);
                }
            }
            "--no-color" | "--no-colour" => {
                no_color = true;
                i += 1;
            }
            "--quiet" | "-q" => {
                quiet = true;
                i += 1;
            }
            "--duration" | "-d" => {
                if i + 1 < args.len() {
                    match args[i + 1].parse::<u64>() {
                        Ok(n) if n > 0 => { duration = Some(n); i += 2; }
                        _ => {
                            eprintln!("❌ --duration requires a positive integer (e.g. --duration 30)");
                            std::process::exit(1);
                        }
                    }
                } else {
                    eprintln!("❌ --duration requires a value (e.g. --duration 30)");
                    std::process::exit(1);
                }
            }
            "--read" | "-r" => {
                if i + 1 < args.len() {
                    read_file = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("❌ --read requires a file path (e.g. --read capture.pcap)");
                    std::process::exit(1);
                }
            }
            other => {
                eprintln!("❌ Unknown argument: {}  (run with --help for usage)", other);
                std::process::exit(1);
            }
        }
    }

    CliArgs { interface, protocols, no_color, quiet, duration, read_file }
}

/// Decide whether ANSI colour output should be enabled. `no_color_requested` is
/// the already-merged result of `--no-color`/`--no-colour` or the `NO_COLOR` env
/// var (see `parse_cli_args` above — both collapse into `CliArgs::no_color`).
/// Colour defaults on only when nothing forces it off AND stdout is an
/// interactive terminal — piping or redirecting output disables it automatically.
pub fn resolve_color_enabled(no_color_requested: bool, stdout_is_tty: bool) -> bool {
    !no_color_requested && stdout_is_tty
}

#[cfg(test)]
mod color_tests {
    use super::resolve_color_enabled;

    #[test]
    fn enabled_on_tty_with_no_color_not_requested() {
        assert!(resolve_color_enabled(false, true));
    }

    #[test]
    fn disabled_on_non_tty_with_no_color_not_requested() {
        assert!(!resolve_color_enabled(false, false));
    }

    #[test]
    fn disabled_on_tty_when_no_color_requested() {
        assert!(!resolve_color_enabled(true, true));
    }

    #[test]
    fn disabled_on_non_tty_when_no_color_requested() {
        assert!(!resolve_color_enabled(true, false));
    }
}

#[cfg(test)]
mod protocol_flag_tests {
    use super::parse_protocol_str;
    use crate::protocols::ProtocolChoice;

    #[test]
    fn accepts_comma_separated_names() {
        assert_eq!(parse_protocol_str("aes67,dante"), vec![ProtocolChoice::AES67, ProtocolChoice::Dante]);
    }

    #[test]
    fn accepts_numeric_indices() {
        // Numeric fallback still works now that name-matching is shared with
        // ProtocolChoice::parse rather than reimplemented inline.
        let first = ProtocolChoice::all_choices()[0].clone();
        assert_eq!(parse_protocol_str("1"), vec![first]);
    }

    #[test]
    fn all_short_circuits_to_all() {
        assert_eq!(parse_protocol_str("aes67,all,dante"), vec![ProtocolChoice::All]);
    }

    #[test]
    fn unknown_token_ignored_falls_back_to_all_when_nothing_else_selected() {
        assert_eq!(parse_protocol_str("not-a-protocol"), vec![ProtocolChoice::All]);
    }

    #[test]
    fn unknown_token_ignored_alongside_valid_ones() {
        assert_eq!(parse_protocol_str("aes67,bogus"), vec![ProtocolChoice::AES67]);
    }
}

#[cfg(test)]
mod bpf_tests {
    use super::build_bpf_filter;
    use crate::protocols::ProtocolChoice;

    #[test]
    fn selective_filter_includes_vlan_tagged_arm() {
        // Plain udp/igmp/ether-proto primitives match only UNtagged frames. On a
        // Linux trunk/SPAN port (where tagged AVB traffic lives) a parallel
        // `vlan and (...)` arm is required or every tagged frame is dropped by the
        // kernel filter before the parser's unwrap_vlan ever runs.
        let f = build_bpf_filter(&[ProtocolChoice::AES67]);
        assert!(f.contains("vlan and ("), "selective filter must include a VLAN arm: {f}");
    }

    #[test]
    fn all_protocols_filter_includes_vlan_tagged_arm() {
        let f = build_bpf_filter(&[ProtocolChoice::All]);
        assert!(f.contains("vlan and ("), "all-protocols filter must include a VLAN arm: {f}");
    }

    // Excluded on Windows (not just #[ignore]d): this is the only test that
    // references a pcap runtime symbol (Capture::dead). Merely compiling the
    // reference into the test binary makes wpcap.dll a load-time import, and the
    // Npcap *runtime* DLL is absent in Windows CI (only the SDK link libs are
    // installed) — so the whole test binary would fail to load with
    // STATUS_DLL_NOT_FOUND. cfg-ing it out drops the import; Linux and macOS still
    // run the libpcap compile check.
    #[cfg(not(windows))]
    #[test]
    fn generated_filters_compile_in_libpcap() {
        // The real guarantee: libpcap must accept the generated expression (VLAN arm
        // included) on an Ethernet datalink. A dead capture compiles without a device.
        use pcap::{Capture, Linktype};
        let cases = [
            vec![ProtocolChoice::All],
            vec![ProtocolChoice::AES67, ProtocolChoice::Dante],
            vec![ProtocolChoice::AVB],
            vec![ProtocolChoice::NDI],
        ];
        for choices in cases {
            let f = build_bpf_filter(&choices);
            let cap = Capture::dead(Linktype::ETHERNET).expect("dead capture");
            assert!(cap.compile(&f, true).is_ok(), "filter must compile in libpcap: {f}");
        }
    }
}

/// Resolve a device by exact pcap name (e.g. `en0`).
/// Exits with a clear error if the name is not found.
///
/// Deliberately does not apply `select_interface`'s skip-list (loopback,
/// `utun`/`awdl`/`bridge`/etc., disconnected adapters) — that list exists only
/// to declutter the interactive menu of choices nobody would pick, not to
/// forbid a choice. A user who explicitly names an interface with `--interface`
/// has already made the decision the skip-list exists to help with; honoring
/// an unusual explicit request (e.g. a disconnected adapter for testing) is
/// more useful here than silently reproducing the interactive filter.
pub fn resolve_interface_by_name(name: &str) -> Device {
    let devices = Device::list().expect("Unable to list interfaces");
    devices.into_iter()
        .find(|d| d.name == name)
        .unwrap_or_else(|| {
            eprintln!("❌ Interface '{}' not found.", name);
            eprintln!("   Run without --interface to see available interfaces.");
            std::process::exit(1);
        })
}

/// Parse a `--protocol` value like `"aes67,dante"` into a `Vec<ProtocolChoice>`.
/// Accepts protocol names (case-insensitive) and interactive-mode numbers (1-7).
fn parse_protocol_str(s: &str) -> Vec<ProtocolChoice> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("all") || s == "0" {
        return vec![ProtocolChoice::All];
    }
    let mut selected = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        match ProtocolChoice::parse(part) {
            Some(ProtocolChoice::All) => return vec![ProtocolChoice::All],
            Some(c) if !selected.contains(&c) => selected.push(c),
            Some(_) => {}
            None => {
                eprintln!("⚠  Unknown protocol '{}' — ignored", part);
                eprintln!("   Valid names: all, audio, video, aes67, avb, dante, ndi, st2110");
            }
        }
    }
    if selected.is_empty() { vec![ProtocolChoice::All] } else { selected }
}

fn print_help() {
    println!("AVStreamLens — passive AV-over-IP network monitor\n");
    println!("USAGE");
    println!("  sudo avstreamlens [OPTIONS]\n");
    println!("OPTIONS");
    println!("  -i, --interface <name>    Network interface to capture on (e.g. en0, eth0)");
    println!("  -p, --protocol  <list>    Comma-separated protocols to monitor (default: all)");
    println!("  -r, --read      <file>    Replay a .pcap file offline — no root required");
    println!("  -d, --duration  <secs>    Stop after N seconds; exit 0 if healthy, 1 if issues");
    println!("  -q, --quiet               Suppress output on healthy cycles; show alerts only");
    println!("      --no-color            Disable ANSI colour output (also: NO_COLOR env var)");
    println!("  -h, --help                Show this help message\n");
    println!("PROTOCOL NAMES");
    println!("  all    audio   video");
    println!("  aes67  avb     dante   ndi   st2110\n");
    println!("EXAMPLES");
    println!("  sudo avstreamlens --interface en0 --protocol aes67,dante");
    println!("  sudo avstreamlens -i eth0 -p all");
    println!("  avstreamlens --read capture.pcap --protocol dante");
    println!("  avstreamlens -r site_visit.pcap\n");
    println!("  Without flags, AVStreamLens prompts interactively.");
}

// ── Interface selection (interactive) ───────────────────────────────────────

/// List and filter network interfaces, prompt the user to select one.
pub fn select_interface() -> Device {
    let devices = Device::list().expect("Unable to list interfaces");
    let filtered: Vec<Device> = devices
        .into_iter()
        .filter(|d| {
            let n = d.name.as_str();
            if n == "lo" || n == "lo0" { return false; }
            let skip = ["utun", "awdl", "llw", "bridge", "vpn", "docker", "veth", "virbr",
                        "ap1", "anpi", "gif", "stf"];
            if skip.iter().any(|k| n.contains(k)) { return false; }
            // On Windows: skip adapters that have no link and the Npcap loopback adapter
            if d.flags.connection_status == ConnectionStatus::Disconnected { return false; }
            if d.desc.as_deref() == Some("Npcap Loopback Adapter") { return false; }
            true
        })
        .collect();

    if filtered.is_empty() {
        eprintln!("❌ No active network interfaces found.");
        std::process::exit(1);
    }

    let port_names = macos_port_names();
    let windows_ips = windows_ip_lookup();

    println!("📡 Available interfaces:\n");
    for (i, d) in filtered.iter().enumerate() {
        let desc = port_names.get(&d.name)
            .map(|s| s.as_str())
            .or(d.desc.as_deref())
            .unwrap_or("");
        let mut ipv4 = d.addresses.iter()
            .filter_map(|a| match a.addr {
                std::net::IpAddr::V4(ip) if !ip.is_unspecified() => Some(ip.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(", ");
        // On Windows, Npcap's Device::list() doesn't always populate addresses — fall
        // back to ipconfig's view of the same adapter (matched by description).
        if ipv4.is_empty()
            && let Some(ip) = d.desc.as_deref().and_then(|desc| windows_ips.get(desc))
        {
            ipv4 = ip.clone();
        }
        // On Windows, Npcap names are \Device\NPF_{GUID} — show the description as
        // the primary label and suppress the GUID from the display entirely.
        if d.name.starts_with(r"\Device\NPF_") {
            let label = if desc.is_empty() { d.name.as_str() } else { desc };
            let ip_part = if ipv4.is_empty() {
                "  (no IPv4)".to_string()
            } else {
                format!("  ({})", ipv4)
            };
            println!("  {}: {}{}", i, label, ip_part);
        } else {
            let info = match (desc.is_empty(), ipv4.is_empty()) {
                (false, false) => format!("  —  {}  ({})", desc, ipv4),
                (false, true)  => format!("  —  {}  (no IPv4)", desc),
                (true,  false) => format!("  —  {}", ipv4),
                (true,  true)  => String::new(),
            };
            println!("  {}: {}{}", i, d.name, info);
        }
    }

    println!("\n👉 Choose an interface by its number [default: 0]:");
    let index: usize = loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        let trimmed = input.trim();
        if trimmed.is_empty() { break 0; }
        match trimmed.parse::<usize>() {
            Ok(n) if n < filtered.len() => break n,
            Ok(_) => println!("❌ Invalid selection. Must be between 0 and {}.", filtered.len() - 1),
            Err(_) => println!("❌ Invalid input. Please enter a number."),
        }
    };

    filtered.into_iter().nth(index).expect("Invalid selection")
}

/// Prompt the user to select which protocols to monitor.
pub fn prompt_protocol_selection() -> Vec<ProtocolChoice> {
    println!("Choose the protocols to monitor:");
    println!("  0) All");
    for (i, choice) in ProtocolChoice::all_choices().iter().enumerate() {
        println!("  {}) {}", i + 1, choice.name());
    }
    println!("  [Separate by commas, e.g. '1,2,3' or enter for all]");
    print!("> ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    if input.trim().is_empty() || input.trim() == "0" {
        return vec![ProtocolChoice::All];
    }

    let mut selected = Vec::new();
    for part in input.split(',') {
        match ProtocolChoice::parse(part.trim()) {
            Some(ProtocolChoice::All) => return vec![ProtocolChoice::All],
            Some(c) if !selected.contains(&c) => selected.push(c),
            _ => {}
        }
    }

    if selected.is_empty() { vec![ProtocolChoice::All] } else { selected }
}

/// Build a BPF filter string from selected protocols.
pub fn build_bpf_filter(selected: &[ProtocolChoice]) -> String {
    let mut expanded = Vec::new();
    for choice in selected {
        expanded.extend(choice.includes());
    }

    if expanded.is_empty() || expanded.iter().any(|c| matches!(c, ProtocolChoice::All)) {
        return all_protocols_filter();
    }

    let needs_udp = expanded.iter().any(|c| c.needs_udp());
    let needs_tcp = expanded.iter().any(|c| c.needs_tcp());
    let needs_avb = expanded.iter().any(|c| c.needs_avb());

    let mut filters = vec!["igmp".to_string()];
    if needs_udp { filters.push("udp".to_string()); }
    if needs_tcp { filters.push("tcp".to_string()); }
    if needs_avb { filters.push("(ether proto 0x22f0) or (ether proto 0x22ea) or (ether proto 0x88f5)".to_string()); }
    // LLDP, gPTP, and flow control are always included — they are infrastructure
    // signals (EEE detection, PTP, link-layer congestion) needed regardless of
    // the user's protocol selection.
    filters.push("(ether proto 0x88cc)".to_string());
    filters.push("(ether proto 0x88f7)".to_string());
    filters.push("(ether proto 0x8808)".to_string());

    // After All/Audio/Video expansion, every concrete ProtocolChoice triggers
    // one of needs_udp/tcp/avb — so this list always has at least 5 entries.
    with_vlan_arm(&filters.join(" or "))
}

/// Duplicate a BPF expression under a `vlan and (...)` arm so the filter matches
/// both untagged and 802.1Q-tagged frames. libpcap's plain primitives (`udp`,
/// `igmp`, `ether proto …`) only match untagged frames; the `vlan` keyword shifts
/// the decode offset so the same primitives match the tagged payload. Per tcpdump
/// semantics the `vlan` keyword mutates offsets for the remainder of the
/// expression, so it goes LAST as a self-contained arm with the untagged
/// expression first. Covers a single tag; QinQ (stacked tags) would need a second
/// nested `vlan` and is out of scope (documented as a capture-setup caveat).
fn with_vlan_arm(expr: &str) -> String {
    format!("({expr}) or (vlan and ({expr}))")
}

/// Suffix showing which infrastructure protocols are auto-enabled alongside the
/// user's selection.  Returns e.g. `"  (+ PTP, IGMP)"`, `"  (+ PTP)"`, or `""`.
///
/// Reads `ProtocolChoice::needs_ptp`/`needs_igmp` — the same rule `is_selected()`
/// gates real packet dispatch on, so this display can't drift from the gate.
pub fn selected_extras_display(expanded: &[ProtocolChoice]) -> String {
    let has_ptp  = expanded.iter().any(|c| c.needs_ptp());
    let has_igmp = expanded.iter().any(|c| c.needs_igmp());
    match (has_ptp, has_igmp) {
        (true,  true)  => "  (+ PTP, IGMP)".to_string(),
        (true,  false) => "  (+ PTP)".to_string(),
        (false, true)  => "  (+ IGMP)".to_string(),
        (false, false) => String::new(),
    }
}

/// Human-readable comma-separated list for the startup banner.
pub fn selected_protocol_display(selected: &[ProtocolChoice]) -> String {
    if selected.iter().any(|c| matches!(c, ProtocolChoice::All)) {
        return "all protocols".to_string();
    }
    selected.iter()
        .map(|c| c.name().split(" (").next().unwrap_or(c.name()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Format selected protocol names for use in the log filename.
pub fn selected_protocol_names(selected: &[ProtocolChoice]) -> String {
    if selected.iter().any(|c| matches!(c, ProtocolChoice::All)) {
        "all".to_string()
    } else {
        selected.iter()
            .map(|c| c.name().replace(" (", "_").replace(')', ""))
            .collect::<Vec<_>>()
            .join("_")
    }
}

/// Query Windows for IPv4 addresses keyed by adapter description, as a fallback for
/// interfaces where Npcap's `Device::list()` doesn't populate `addresses` (a known gap —
/// unlike Unix's getifaddrs-backed pcap, Npcap's address population can lag or omit
/// entries for some adapter types). Matches on adapter description since that's the
/// field common to both `ipconfig /all` output and Npcap's `desc`.
/// Returns an empty map on macOS/Linux or if `ipconfig` is unavailable.
fn windows_ip_lookup() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let Ok(out) = std::process::Command::new("ipconfig").arg("/all").output() else {
        return map;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut current_desc: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            current_desc = None;
            continue;
        }
        let Some((key, value)) = trimmed.split_once(':') else { continue };
        let key = key.trim_end_matches(['.', ' ']).trim();
        let value = value.trim();
        match key {
            "Description" => current_desc = Some(value.to_string()),
            "IPv4 Address" | "Autoconfiguration IPv4 Address" => {
                if let Some(desc) = &current_desc {
                    let ip = value.trim_end_matches("(Preferred)").trim();
                    map.entry(desc.clone())
                        .and_modify(|existing: &mut String| {
                            existing.push_str(", ");
                            existing.push_str(ip);
                        })
                        .or_insert_with(|| ip.to_string());
                }
            }
            _ => {}
        }
    }
    map
}

/// Query macOS for human-readable hardware port names (e.g. "Wi-Fi", "Thunderbolt Ethernet Slot 1").
/// Returns an empty map on Linux or if networksetup is unavailable.
fn macos_port_names() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let Ok(out) = std::process::Command::new("networksetup")
        .arg("-listallhardwareports")
        .output()
    else {
        return map;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut current_port = String::new();
    for line in text.lines() {
        if let Some(port) = line.strip_prefix("Hardware Port: ") {
            current_port = port.trim().to_string();
        } else if let Some(dev) = line.strip_prefix("Device: ") {
            let dev = dev.trim().to_string();
            if !dev.is_empty() && !current_port.is_empty() {
                map.insert(dev, std::mem::take(&mut current_port));
            }
        }
    }
    map
}

fn all_protocols_filter() -> String {
    with_vlan_arm("igmp or udp or tcp or (ether proto 0x22f0) or (ether proto 0x22ea) or (ether proto 0x88f5) or (ether proto 0x88f7) or (ether proto 0x88cc) or (ether proto 0x8808)")
}
