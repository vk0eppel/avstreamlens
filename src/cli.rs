// AVStreamLens — src/cli.rs
// Interactive CLI prompts: interface selection and protocol selection.

use pcap::Device;
use std::io::{self, Write};

use crate::protocols::ProtocolChoice;

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
            !skip.iter().any(|k| n.contains(k))
        })
        .collect();

    if filtered.is_empty() {
        eprintln!("❌ No active network interfaces found.");
        std::process::exit(1);
    }

    let port_names = macos_port_names();

    println!("📡 Available interfaces:\n");
    for (i, d) in filtered.iter().enumerate() {
        let desc = port_names.get(&d.name)
            .map(|s| s.as_str())
            .or(d.desc.as_deref())
            .unwrap_or("");
        let ipv4 = d.addresses.iter()
            .filter_map(|a| match a.addr {
                std::net::IpAddr::V4(ip) => Some(ip.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(", ");
        let info = match (desc.is_empty(), ipv4.is_empty()) {
            (false, false) => format!("  —  {}  ({})", desc, ipv4),
            (false, true)  => format!("  —  {}  (no IPv4)", desc),
            (true,  false) => format!("  —  {}", ipv4),
            (true,  true)  => String::new(),
        };
        println!("  {}: {}{}", i, d.name, info);
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
        if let Ok(idx) = part.trim().parse::<usize>() {
            if idx == 0 {
                return vec![ProtocolChoice::All];
            }
            if let Some(choice) = ProtocolChoice::all_choices().get(idx.saturating_sub(1)) {
                selected.push(choice.clone());
            }
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
    filters.join(" or ")
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
    "igmp or udp or tcp or (ether proto 0x22f0) or (ether proto 0x22ea) or (ether proto 0x88f5) or (ether proto 0x88f7) or (ether proto 0x88cc) or (ether proto 0x8808)".to_string()
}
