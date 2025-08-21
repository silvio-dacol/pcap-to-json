use std::{env, fs::File, io::Write};
use serde::Serialize;
use pcap::Capture;
use chrono::{DateTime, Utc};

#[derive(Serialize)]
struct PacketRecord {
    index: usize,
    timestamp_sec: String,
    packet_len: u32,
    raw_hex: String,
}

// Function to parse the timestamp into a UTC string with format %H:%M:%S.%f
fn utc_time(sec: i64, usec: i64) -> String {
    let dt = DateTime::<Utc>::from_timestamp(sec, usec as u32).unwrap();
    dt.format("%Y-%m-%d %H:%M:%S.%f").to_string()
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

    // Initialize index that displays the packet number
    let mut index = 0;

    // Process each packet
    while let Ok(packet) = cap.next_packet() {
        // Increment the index every processed packet
        index = index + 1;

        let record = PacketRecord {
            index: index,
            timestamp_sec: utc_time(packet.header.ts.tv_sec as i64, packet.header.ts.tv_usec as i64),
            packet_len: packet.header.len,
            raw_hex: hex_string(packet.data),
        };

        // Write the JSON record to the output file
        writeln!(out, "{}", serde_json::to_string(&record)?)?;
    }

    Ok(())
}
