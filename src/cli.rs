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
            let skip = ["utun", "awdl", "llw", "bridge", "vpn", "docker", "veth", "virbr"];
            !skip.iter().any(|k| n.contains(k))
        })
        .collect();

    if filtered.is_empty() {
        eprintln!("❌ No active network interfaces found.");
        std::process::exit(1);
    }

    println!("📡 Available interfaces:\n");
    for (i, d) in filtered.iter().enumerate() {
        println!("  {}: {}", i, d.name);
    }

    println!("\n👉 Choose an interface by its number:");
    let index: usize = loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        match input.trim().parse::<usize>() {
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
    let needs_ptp = expanded.iter().any(|c| c.needs_ptp());

    let mut filters = vec!["igmp".to_string()];
    if needs_udp { filters.push("udp".to_string()); }
    if needs_tcp { filters.push("tcp".to_string()); }
    if needs_avb { filters.push("(ether proto 0x22f0)".to_string()); }
    if needs_ptp { filters.push("(ether proto 0x88f7)".to_string()); }

    if filters.len() == 1 {
        all_protocols_filter()
    } else {
        filters.join(" or ")
    }
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

/// Return true if the selected protocols require a valid PTP clock to be present.
pub fn protocol_requires_ptp(selected: &[ProtocolChoice]) -> bool {
    let expanded: Vec<_> = selected.iter().flat_map(|c| c.includes()).collect();
    if expanded.is_empty() || expanded.iter().any(|c| matches!(c, ProtocolChoice::All)) {
        return true;
    }
    expanded.iter().any(|c| c.requires_valid_ptp_clock())
}

fn all_protocols_filter() -> String {
    "igmp or udp or tcp or (ether proto 0x22f0) or (ether proto 0x88f7)".to_string()
}
