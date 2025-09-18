# pcap-to-json

A tool to convert pcap and pcapng files to JSON format.

## Installation Requirements

0. **Rust and Cargo**: Check to have rust and cargo installed. If not, install from https://rustup.rs/

## To use the PCAP Converter too:

1. **Npcap Runtime**: Download from https://npcap.com in the Downloads section.

   <img src="./docs/npcap_downloads_section.png" alt="npcap_downloads_section" width="800"/>

2. **Npcap Runtime**: Check "Install Npcap in WinPcap API-compatible Mode" in the installer.

   <img src="./docs/npcap_installation_settings.png" alt="npcap_installation_settings" width="800"/>

3. **Npcap SDK**: Download from https://npcap.com in the Downloads section, extract to `C:\Program Files\Npcap\sdk\`

## Build

```bash
cargo build
```

## Usage (on repository)

### PCAP Converter:

Use this command to convert a pcap file to JSONL:

```
cargo run input.pcap output.jsonl
```

### DTC Report:

Extract DTC definitions from an Excel `.xlsx` file into JSONL:

```
cargo run -- --extract-dtcs-xlsx dtc_catalog.xlsx dtc_db.jsonl
```

Extract DTCs from a log file into JSONL:

```
cargo run -- --extract-dtcs sample.log dtcs.jsonl
```

## Usage (on .exe)

1. Navigate in the folder where *dtc-parser.exe* is contained.

2. Download from https://intranet.volvocars.net/sites/DTCLista the .xlsx file you want to use as DTC description database.

3. Save the DTC Lista file in the /files/input folder as *dtc-lista-xlsx* (call it as you wiish, just change the name afterwards)

Run:

```
./dtc-parser --extract-dtcs-xlsx dtc-lista.log dtcs-db.jsonl
```

5. Save the One Engine log file into the /files/input as *one-engine.log* (call it as you wiish, just change the name afterwards)

```
./dtc-parser --extract-dtcs one-engine.log dtcs.json
```

6. The DTC report will be available as *dtcs.json*

Note:
1. Keep *dtcs-db.jsonl* as the only fixed name as it is hardcoded in the code.
2. You don't need to create a new DTC database if you already have one.
