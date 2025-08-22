use std::{env, fs::File, io::Write};
use serde::Serialize;
use pcap::Capture;
use chrono::{DateTime, Utc};
use etherparse::SlicedPacket;

// Define the structure of the JSON record to be written
#[derive(Serialize)]
struct PacketRecord {
    index: usize,
    timestamp_sec: String,
    packet_len: u32,
    raw_hex: String,
    ethernet: Option<EthernetInfo>,
    ip: Option<IpInfo>,
    tcp: Option<TransportInfo>,
    // doip: Option<DoipInfo>, // TODO: Add DoIP parsing
}

#[derive(Serialize)]
struct EthernetInfo {
    src_mac: String,
    dst_mac: String,
    ethertype: u16,
}

#[derive(Serialize)]
struct IpInfo {
    version: u8,
    src_ip: String,
    dst_ip: String,
    protocol: u8,
    ttl: u8,
}

struct TransportInfo {
    protocol: String,
    src_port: u16,
    dst_port: u16,
    payload_length: usize,
}

struct DoipInfo {
    version: u8,
    payload_type: u8,
}

// Function to parse the timestamp into a UTC string with format %H:%M:%S.%f
fn utc_time(sec: i64, usec: i64) -> String {
    let dt = DateTime::<Utc>::from_timestamp(sec, (usec*1000) as u32).unwrap();
    dt.format("%H:%M:%S.%6f").to_string()
}

// Function to convert the packet data to a hex string
fn payload_string(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

// ------------------------------------------------------------------
// Parse Ethernet layer information
fn parse_ethernet(packet: &SlicedPacket) -> Option<EthernetInfo> {
    packet.link.as_ref().map(|link| {
        match link {
            etherparse::LinkSlice::Ethernet2(eth) => EthernetInfo {
                src_mac: format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    eth.source()[0], eth.source()[1], eth.source()[2],
                    eth.source()[3], eth.source()[4], eth.source()[5]),
                dst_mac: format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    eth.destination()[0], eth.destination()[1], eth.destination()[2],
                    eth.destination()[3], eth.destination()[4], eth.destination()[5]),
                ethertype: eth.ether_type(),
            }
        }
    })
}

// Parse IP layer information
fn parse_ip(packet: &SlicedPacket) -> Option<IpInfo> {
    packet.ip.as_ref().map(|ip| {
        match ip {
            etherparse::IpSlice::Ipv4(ipv4) => IpInfo {
                version: 4,
                src_ip: ipv4.source_addr().to_string(),
                dst_ip: ipv4.destination_addr().to_string(),
                protocol: ipv4.protocol(),
                ttl: ipv4.ttl(),
                total_length: ipv4.total_len(),
            },
            etherparse::IpSlice::Ipv6(ipv6) => IpInfo {
                version: 6,
                src_ip: ipv6.source_addr().to_string(),
                dst_ip: ipv6.destination_addr().to_string(),
                protocol: ipv6.next_header(),
                ttl: ipv6.hop_limit(),
                total_length: ipv6.payload_length(),
            },
        }
    })
}

// Parse Transport layer (TCP/UDP) information
fn parse_transport(packet: &SlicedPacket) -> Option<TransportInfo> {
    packet.transport.as_ref().map(|transport| {
        match transport {
            etherparse::TransportSlice::Tcp(tcp) => TransportInfo {
                protocol: "TCP".to_string(),
                src_port: tcp.source_port(),
                dst_port: tcp.destination_port(),
                payload_length: packet.payload.len(),
            },
            etherparse::TransportSlice::Udp(udp) => TransportInfo {
                protocol: "UDP".to_string(),
                src_port: udp.source_port(),
                dst_port: udp.destination_port(),
                payload_length: packet.payload.len(),
            },
            etherparse::TransportSlice::Icmpv4(_) => TransportInfo {
                protocol: "ICMPv4".to_string(),
                src_port: 0,
                dst_port: 0,
                payload_length: packet.payload.len(),
            },
            etherparse::TransportSlice::Icmpv6(_) => TransportInfo {
                protocol: "ICMPv6".to_string(),
                src_port: 0,
                dst_port: 0,
                payload_length: packet.payload.len(),
            },
        }
    })
}
// -----------------------------------------------------------------------

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
            raw_hex: payload_string(packet.data),
        };

        // Write the JSON record to the output file
        writeln!(out, "{}", serde_json::to_string(&record)?)?;
    }

    Ok(())
}
