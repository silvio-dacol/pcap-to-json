use std::{env, fs::File, io::Write};
use serde::Serialize;
use pcap::Capture;
use chrono::{DateTime, Utc};
use etherparse::SlicedPacket;
use hex;

// Define the structure of the JSON record to be written
#[derive(Serialize)]
struct PacketRecord {
    index: usize,
    date: String,
    timestamp: String,
    ethernet: Option<EthernetInfo>,
    ip: Option<IpInfo>,
    tcp: Option<TransportInfo>,
    doip: Option<DoipInfo>,
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
}

#[derive(Serialize)]
struct DoipInfo {
    version: u8,
    inverse_version: u8,
    payload_type: u16,
    payload_length: u32,
    payload_type_description: String,
    raw_hex: String,
    payload_hex: String,
    header_valid: bool,
    version_valid: bool,
    payload_length_matches: bool,
    payload_analysis: Option<String>,
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
        match transport {
            etherparse::TransportSlice::Tcp(tcp) => TransportInfo {
                protocol: "TCP".to_string(),
                src_port: tcp.source_port(),
                dst_port: tcp.destination_port(),
            },
            etherparse::TransportSlice::Udp(udp) => TransportInfo {
                protocol: "UDP".to_string(),
                src_port: udp.source_port(),
                dst_port: udp.destination_port(),
            },
            etherparse::TransportSlice::Icmpv4(_) => TransportInfo {
                protocol: "ICMPv4".to_string(),
                src_port: 0,
                dst_port: 0,
            },
            etherparse::TransportSlice::Icmpv6(_) => TransportInfo {
                protocol: "ICMPv6".to_string(),
                src_port: 0,
                dst_port: 0,
            },
        }
    })
}

// Analyze DoIP payload content based on message type
fn analyze_doip_payload(payload_type: u16, payload: &[u8]) -> Option<String> {
    match payload_type {
        0x8001 => {
            // Diagnostic message - analyze UDS content
            if payload.len() >= 2 {
                let source_address = u16::from_be_bytes([payload[0], payload[1]]);
                let target_address = if payload.len() >= 4 {
                    u16::from_be_bytes([payload[2], payload[3]])
                } else {
                    0
                };
                let uds_data = if payload.len() > 4 { &payload[4..] } else { &[] };
                Some(format!("UDS Diagnostic message: Source=0x{:04X}, Target=0x{:04X}, UDS data: {} bytes",
                    source_address, target_address, uds_data.len()))
            } else {
                Some("Diagnostic message: Invalid payload length".to_string())
            }
        },
        0x0004 => {
            // Vehicle announcement/identification response
            if payload.len() >= 17 {
                let vin = String::from_utf8_lossy(&payload[0..17]);
                Some(format!("Vehicle identification: VIN={}", vin))
            } else {
                Some("Vehicle identification: Incomplete VIN".to_string())
            }
        },
        0x0005 => {
            // Routing activation request
            if payload.len() >= 7 {
                let source_address = u16::from_be_bytes([payload[0], payload[1]]);
                let activation_type = payload[2];
                Some(format!("Routing activation request: Source=0x{:04X}, Type=0x{:02X}",
                    source_address, activation_type))
            } else {
                Some("Routing activation request: Invalid payload".to_string())
            }
        },
        0x0006 => {
            // Routing activation response
            if payload.len() >= 9 {
                let tester_address = u16::from_be_bytes([payload[0], payload[1]]);
                let entity_address = u16::from_be_bytes([payload[2], payload[3]]);
                let response_code = payload[4];
                Some(format!("Routing activation response: Tester=0x{:04X}, Entity=0x{:04X}, Code=0x{:02X}",
                    tester_address, entity_address, response_code))
            } else {
                Some("Routing activation response: Invalid payload".to_string())
            }
        },
        _ => None,
    }
}

// Get description for DoIP payload type based on ISO-13400 standard
fn get_doip_payload_type_description(payload_type: u16) -> String {

    match payload_type {
        // Generic DoIP header negative acknowledge
        0x0000 => "Generic DoIP header negative acknowledge".to_string(),
        // Vehicle identification
        0x0001 => "Vehicle identification request message".to_string(),
        0x0002 => "Vehicle identification request message with EID".to_string(),
        0x0003 => "Vehicle identification request message with VIN".to_string(),
        0x0004 => "Vehicle announcement message/vehicle identification response message".to_string(),
        // Routing activation
        0x0005 => "Routing activation request".to_string(),
        0x0006 => "Routing activation response".to_string(),
        // Alive check
        0x0007 => "Alive check request".to_string(),
        0x0008 => "Alive check response".to_string(),
        // DoIP entity status
        0x4001 => "DoIP entity status request".to_string(),
        0x4002 => "DoIP entity status response".to_string(),
        // Diagnostic power mode
        0x4003 => "Diagnostic power mode information request".to_string(),
        0x4004 => "Diagnostic power mode information response".to_string(),
        // Diagnostic messages
        0x8001 => "Diagnostic message".to_string(),
        0x8002 => "Diagnostic message positive acknowledgement".to_string(),
        0x8003 => "Diagnostic message negative acknowledgement".to_string(),
        _ => format!("Unknown payload type (0x{:04X})", payload_type),
    }
}

// Parse DoIP layer information
fn parse_doip(packet: &SlicedPacket) -> Option<DoipInfo> {
    packet.transport.as_ref().and_then(|transport| {
        match transport {
            etherparse::TransportSlice::Udp(udp) => {
                let payload = udp.payload();
                // DoIP header is at least 8 bytes: version(1) + inverse_version(1) + payload_type(2) + payload_length(4)
                if payload.len() >= 8 {
                    let version = payload[0];
                    let inverse_version = payload[1];
                    let payload_type = u16::from_be_bytes([payload[2], payload[3]]);
                    let payload_length = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);

                    // Extract the actual payload (after the 8-byte header)
                    let doip_payload = if payload.len() > 8 {
                        &payload[8..]
                    } else {
                        &[]
                    };

                    // Validate DoIP header
                    let version_valid = version == 0x02 && inverse_version == 0xFD;
                    let header_valid = version_valid;
                    let actual_payload_length = doip_payload.len() as u32;
                    let payload_length_matches = payload_length == actual_payload_length;

                    Some(DoipInfo {
                        version,
                        inverse_version,
                        payload_type,
                        payload_length,
                        payload_type_description: get_doip_payload_type_description(payload_type),
                        raw_hex: hex::encode(payload),
                        payload_hex: hex::encode(doip_payload),
                        header_valid,
                        version_valid,
                        payload_length_matches,
                        payload_analysis: analyze_doip_payload(payload_type, doip_payload),
                    })
                } else {
                    None
                }
            },
            etherparse::TransportSlice::Tcp(tcp) => {
                // DoIP can also run over TCP
                let payload = tcp.payload();
                if payload.len() >= 8 {
                    let version = payload[0];
                    let inverse_version = payload[1];
                    let payload_type = u16::from_be_bytes([payload[2], payload[3]]);
                    let payload_length = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);

                    let doip_payload = if payload.len() > 8 {
                        &payload[8..]
                    } else {
                        &[]
                    };

                    // Validate DoIP header
                    let version_valid = version == 0x02 && inverse_version == 0xFD;
                    let header_valid = version_valid;
                    let actual_payload_length = doip_payload.len() as u32;
                    let payload_length_matches = payload_length == actual_payload_length;

                    Some(DoipInfo {
                        version,
                        inverse_version,
                        payload_type,
                        payload_length,
                        payload_type_description: get_doip_payload_type_description(payload_type),
                        raw_hex: hex::encode(payload),
                        payload_hex: hex::encode(doip_payload),
                        header_valid,
                        version_valid,
                        payload_length_matches,
                        payload_analysis: analyze_doip_payload(payload_type, doip_payload),
                    })
                } else {
                    None
                }
            },
            _ => None,
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
            ethernet: parse_ethernet(&sliced_packet),
            ip: parse_ip(&sliced_packet),
            tcp: parse_transport(&sliced_packet),
            doip: parse_doip(&sliced_packet),
        };

        // Write the JSON record to the output file
        writeln!(out, "{}", serde_json::to_string(&record)?)?;
    }

    Ok(())
}
