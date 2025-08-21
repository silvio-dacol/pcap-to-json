use std::{env, fs::File, io::Write};
use serde::Serialize;
use pcap::Capture;

#[derive(Serialize)]
struct PacketRecord {
    timestamp_sec: i64,
    timestamp_usec: i64,
    packet_len: u32,
    raw_hex: String,
}

fn hex_string(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let in_path = env::args().nth(1).expect("Usage: cargo run <infile.pcap> <outfile.jsonl>");
    let out_path = env::args().nth(2).expect("Usage: cargo run <infile.pcap> <outfile.jsonl>");

    // Open the PCAP file
    let mut cap = Capture::from_file(&in_path)?;
    let mut out = File::create(out_path)?;

    // Process each packet
    while let Ok(packet) = cap.next_packet() {
        let record = PacketRecord {
            timestamp_sec: packet.header.ts.tv_sec as i64,
            timestamp_usec: packet.header.ts.tv_usec as i64,
            packet_len: packet.header.len,
            raw_hex: hex_string(packet.data),
        };
        writeln!(out, "{}", serde_json::to_string(&record)?)?;
    }

    Ok(())
}
