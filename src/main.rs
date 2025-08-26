use std::{env, fs::File, io::Write};
use serde::Serialize;
use pcap::Capture;
use chrono::{DateTime, Utc};
use etherparse::SlicedPacket;

// Define the structure of the JSON record to be written
#[derive(Serialize)]
struct PacketRecord {
    index: usize,
    date: String,
    timestamp: String,
    packet_len: u32,
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

#[derive(Serialize)]
struct TransportInfo {
    protocol: String,
    src_port: u16,
    dst_port: u16,
    payload_length: usize,
}

#[derive(Serialize)]
struct DoipInfo {
    version: u8,
    payload_type: u8,
    raw_hex: String,
}

// Function to parse the timestamp into a UTC string with format %Y-%m-%d
fn utc_date(sec: i64, usec: i64) -> String {
    let dt = DateTime::<Utc>::from_timestamp(sec, (usec*1000) as u32).unwrap();
    dt.format("%Y-%m-%d").to_string()
}

// Function to parse the timestamp into a UTC string with format %H:%M:%S.%6f
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

// Parse Ethernet layer information
fn parse_ethernet(packet: &SlicedPacket) -> Option<EthernetInfo> {
    packet.link.as_ref().and_then(|link| {
        match link {
            etherparse::LinkSlice::Ethernet2(eth) => Some(EthernetInfo {
                src_mac: format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    eth.source()[0], eth.source()[1], eth.source()[2],
                    eth.source()[3], eth.source()[4], eth.source()[5]),
                dst_mac: format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    eth.destination()[0], eth.destination()[1], eth.destination()[2],
                    eth.destination()[3], eth.destination()[4], eth.destination()[5]),
                ethertype: eth.ether_type().into(),
            }),
            // For other link types, we don't extract ethernet info
            _ => None,
        }
    })
}

// Parse IP layer information
fn parse_ip(packet: &SlicedPacket) -> Option<IpInfo> {
    packet.net.as_ref().and_then(|net| {
        match net {
            etherparse::NetSlice::Ipv4(ipv4) => Some(IpInfo {
                version: 4,
                src_ip: ipv4.header().source_addr().to_string(),
                dst_ip: ipv4.header().destination_addr().to_string(),
                protocol: ipv4.header().protocol().into(),
                ttl: ipv4.header().ttl(),
            }),
            etherparse::NetSlice::Ipv6(ipv6) => Some(IpInfo {
                version: 6,
                src_ip: ipv6.header().source_addr().to_string(),
                dst_ip: ipv6.header().destination_addr().to_string(),
                protocol: ipv6.header().next_header().into(),
                ttl: ipv6.header().hop_limit(),
            }),
            // For ARP packets, we don't extract IP info
            etherparse::NetSlice::Arp(_) => None,
        }
    })
}

// Parse Transport layer (TCP/UDP) information
fn parse_transport(packet: &SlicedPacket) -> Option<TransportInfo> {
    packet.transport.as_ref().map(|transport| {
        // Get payload length from IP layer if available
        let payload_length = packet.ip_payload()
            .map(|ip_payload| ip_payload.payload.len())
            .unwrap_or(0);

        match transport {
            etherparse::TransportSlice::Tcp(tcp) => TransportInfo {
                protocol: "TCP".to_string(),
                src_port: tcp.source_port(),
                dst_port: tcp.destination_port(),
                payload_length,
            },
            etherparse::TransportSlice::Udp(udp) => TransportInfo {
                protocol: "UDP".to_string(),
                src_port: udp.source_port(),
                dst_port: udp.destination_port(),
                payload_length,
            },
            etherparse::TransportSlice::Icmpv4(_) => TransportInfo {
                protocol: "ICMPv4".to_string(),
                src_port: 0,
                dst_port: 0,
                payload_length,
            },
            etherparse::TransportSlice::Icmpv6(_) => TransportInfo {
                protocol: "ICMPv6".to_string(),
                src_port: 0,
                dst_port: 0,
                payload_length,
            },
        }
    })
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

        // Parse the packet using etherparse
        let sliced_packet = match SlicedPacket::from_ethernet(packet.data) {
            Ok(packet) => packet,
            Err(_) => continue, // Skip packets that can't be parsed
        };

        let record = PacketRecord {
            index: index,
            date: utc_date(packet.header.ts.tv_sec as i64, packet.header.ts.tv_usec as i64),
            timestamp: utc_time(packet.header.ts.tv_sec as i64, packet.header.ts.tv_usec as i64),
            packet_len: packet.header.len,
            // raw_hex: payload_string(packet.data),
            ethernet: parse_ethernet(&sliced_packet),
            ip: parse_ip(&sliced_packet),
            tcp: parse_transport(&sliced_packet),
            // doip: parse_doip(&sliced_packet), // TODO: Add DoIP parsing
        };

        // Write the JSON record to the output file
        writeln!(out, "{}", serde_json::to_string(&record)?)?;
    }

    Ok(())
}
