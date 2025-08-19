# pcap-to-json

A tool to convert pcap and pcapng files to JSON.

## Installation Requirements

0. **Rust and Cargo**: Check to have rust and cargo installed. If not, install from https://rustup.rs/

1. **Npcap Runtime**: Download from https://npcap.com in the Downloads section
![npcap_downloads_section](./docs/npcap_downloads_section.png)

2. **Npcap Runtime**: Check "Install Npcap in WinPcap API-compatible Mode" in the installer
![npcap_installation_settings](./docs/npcap_installation_settings.png)

3. **Npcap SDK**: Download from https://npcap.com in the Downloads section, extract to `C:\Program Files\Npcap\sdk\`

## Build
```bash
cargo build
```

## Usage

Navigate to the directory where the executable is (i.e. target/debug) and run the executable as:

1. Print the packets in the CLI
```bash
pcap-to-json input.pcap
```

2. Print the packets to a file called "output.json"
```
pcap-to-json input.pcap --out output.json
```
