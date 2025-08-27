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
    payload_hex: String,
    source_address: Option<String>,
    destination_address: Option<String>,
    uds_info: Option<UdsInfo>,
}

#[derive(Serialize)]
struct UdsInfo {
    service_id: u8,
    service_description: String,
    is_response: bool,
    sub_function: Option<u8>,
    sub_function_description: Option<String>,
    data_identifier: Option<u16>,
    routine_identifier: Option<u16>,
    negative_response_code: Option<u8>,
    nrc_description: Option<String>,
    data_hex: String,
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

// Get UDS service description
fn get_uds_service_description(service_id: u8, is_response: bool) -> String {
    if is_response {
        match service_id {
            0x50 => "DiagnosticSessionControl Positive Response".to_string(),
            0x51 => "ECUReset Positive Response".to_string(),
            0x62 => "ReadDataByIdentifier Positive Response".to_string(),
            0x6E => "WriteDataByIdentifier Positive Response".to_string(),
            0x71 => "RoutineControl Positive Response".to_string(),
            0x74 => "RequestDownload Positive Response".to_string(),
            0x76 => "TransferData Positive Response".to_string(),
            0x77 => "RequestTransferExit Positive Response".to_string(),
            0x7F => "Negative Response Code (NRC)".to_string(),
            _ => format!("Unknown UDS Response (0x{:02X})", service_id),
        }
    } else {
        match service_id {
            0x10 => "DiagnosticSessionControl".to_string(),
            0x11 => "ECUReset".to_string(),
            0x22 => "ReadDataByIdentifier".to_string(),
            0x2E => "WriteDataByIdentifier".to_string(),
            0x31 => "RoutineControl".to_string(),
            0x34 => "RequestDownload".to_string(),
            0x36 => "TransferData".to_string(),
            0x37 => "RequestTransferExit".to_string(),
            0x3E => "TesterPresent".to_string(),
            0x85 => "ControlDTCSetting".to_string(),
            0x19 => "ReadDTCInformation".to_string(),
            0x14 => "ClearDiagnosticInformation".to_string(),
            0x27 => "SecurityAccess".to_string(),
            0x28 => "CommunicationControl".to_string(),
            0x29 => "Authentication".to_string(),
            0x2A => "ReadDataByPeriodicIdentifier".to_string(),
            0x2C => "DynamicallyDefineDataIdentifier".to_string(),
            0x2F => "InputOutputControlByIdentifier".to_string(),
            0x83 => "AccessTimingParameter".to_string(),
            0x84 => "SecuredDataTransmission".to_string(),
            0x86 => "ResponseOnEvent".to_string(),
            0x87 => "LinkControl".to_string(),
            _ => format!("Unknown UDS Service (0x{:02X})", service_id),
        }
    }
}

// Get NRC (Negative Response Code) description
fn get_nrc_description(nrc: u8) -> String {
    match nrc {
        0x10 => "generalReject".to_string(),
        0x11 => "serviceNotSupported".to_string(),
        0x12 => "subFunctionNotSupported".to_string(),
        0x13 => "incorrectMessageLengthOrInvalidFormat".to_string(),
        0x21 => "busyRepeatRequest".to_string(),
        0x22 => "conditionsNotCorrect".to_string(),
        0x24 => "requestSequenceError".to_string(),
        0x25 => "noResponseFromSubnetComponent".to_string(),
        0x26 => "failurePreventsExecutionOfRequestedAction".to_string(),
        0x31 => "requestOutOfRange".to_string(),
        0x33 => "securityAccessDenied".to_string(),
        0x35 => "invalidKey".to_string(),
        0x36 => "exceedNumberOfAttempts".to_string(),
        0x37 => "requiredTimeDelayNotExpired".to_string(),
        0x70 => "uploadDownloadNotAccepted".to_string(),
        0x71 => "transferDataSuspended".to_string(),
        0x72 => "generalProgrammingFailure".to_string(),
        0x73 => "wrongBlockSequenceCounter".to_string(),
        0x78 => "requestCorrectlyReceived-ResponsePending".to_string(),
        0x7E => "subFunctionNotSupportedInActiveSession".to_string(),
        0x7F => "serviceNotSupportedInActiveSession".to_string(),
        _ => format!("Unknown NRC (0x{:02X})", nrc),
    }
}

// Get routine control sub-function description
fn get_routine_control_subfunction_description(sub_func: u8) -> String {
    match sub_func {
        0x01 => "startRoutine".to_string(),
        0x02 => "stopRoutine".to_string(),
        0x03 => "requestRoutineResults".to_string(),
        _ => format!("Unknown sub-function (0x{:02X})", sub_func),
    }
}

// Parse UDS message from DoIP diagnostic payload
fn parse_uds_message(payload: &[u8]) -> Option<UdsInfo> {
    if payload.len() < 5 {
        return None; // Need at least source addr (2) + target addr (2) + service (1)
    }

    // Skip source and target addresses (first 4 bytes)
    let uds_data = &payload[4..];
    if uds_data.is_empty() {
        return None;
    }

    let service_id = uds_data[0];
    let is_response = service_id >= 0x40 || service_id == 0x7F;
    let mut negative_response_code = None;
    let mut nrc_description = None;
    let mut sub_function = None;
    let mut sub_function_description = None;
    let mut data_identifier = None;
    let mut routine_identifier = None;

    // Handle negative response
    if service_id == 0x7F && uds_data.len() >= 3 {
        let _failed_service = uds_data[1]; // Service that failed
        let nrc = uds_data[2];
        negative_response_code = Some(nrc);
        nrc_description = Some(get_nrc_description(nrc));
    }
    // Handle specific services
    else {
        match service_id {
            // ReadDataByIdentifier request/response
            0x22 | 0x62 => {
                if uds_data.len() >= 3 {
                    data_identifier = Some(u16::from_be_bytes([uds_data[1], uds_data[2]]));
                }
            },

            // I/O Control by Identifier request/response
            0x2F | 0x6F => {
                if uds_data.len() >= 3 {
                    data_identifier = Some(u16::from_be_bytes([uds_data[1], uds_data[2]]));
                }
            },

            // WriteDataByIdentifier request/response
            0x2E | 0x6E => {
                if uds_data.len() >= 3 {
                    data_identifier = Some(u16::from_be_bytes([uds_data[1], uds_data[2]]));
                }
            },

            // RoutineControl request/response
            0x31 | 0x71 => {
                if uds_data.len() >= 2 {
                    sub_function = Some(uds_data[1]);
                    sub_function_description = Some(get_routine_control_subfunction_description(uds_data[1]));
                }
                if uds_data.len() >= 4 {
                    routine_identifier = Some(u16::from_be_bytes([uds_data[2], uds_data[3]]));
                }
            },

            _ => {}
        }
    }

    Some(UdsInfo {
        service_id,
        service_description: get_uds_service_description(service_id, is_response),
        is_response,
        sub_function,
        sub_function_description,
        data_identifier,
        routine_identifier,
        negative_response_code,
        nrc_description,
        data_hex: hex::encode(uds_data),
    })
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

                    // Extract source and target addresses for diagnostic messages
                    let (source_address, destination_address) = if payload_type == 0x8001 && doip_payload.len() >= 4 {
                        let src_addr = u16::from_be_bytes([doip_payload[0], doip_payload[1]]);
                        let dst_addr = u16::from_be_bytes([doip_payload[2], doip_payload[3]]);
                        (
                            Some(format!("0x{:04x}", src_addr)),
                            Some(format!("0x{:04x}", dst_addr)),
                        )
                    } else {
                        (None, None)
                    };

                    // Parse UDS information for diagnostic messages
                    let uds_info = if payload_type == 0x8001 {
                        parse_uds_message(doip_payload)
                    } else {
                        None
                    };

                    Some(DoipInfo {
                        version,
                        inverse_version,
                        payload_type,
                        payload_length,
                        payload_type_description: get_doip_payload_type_description(payload_type),
                        payload_hex: hex::encode(doip_payload),
                        source_address,
                        destination_address,
                        uds_info,
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

                    // Extract source and target addresses for diagnostic messages
                    let (source_address, destination_address) = if payload_type == 0x8001 && doip_payload.len() >= 4 {
                        let src_addr = u16::from_be_bytes([doip_payload[0], doip_payload[1]]);
                        let dst_addr = u16::from_be_bytes([doip_payload[2], doip_payload[3]]);
                        (
                            Some(format!("0x{:04x}", src_addr)),
                            Some(format!("0x{:04x}", dst_addr)),
                        )
                    } else {
                        (None, None)
                    };

                    // Parse UDS information for diagnostic messages
                    let uds_info = if payload_type == 0x8001 {
                        parse_uds_message(doip_payload)
                    } else {
                        None
                    };

                    Some(DoipInfo {
                        version,
                        inverse_version,
                        payload_type,
                        payload_length,
                        payload_type_description: get_doip_payload_type_description(payload_type),
                        payload_hex: hex::encode(doip_payload),
                        source_address,
                        destination_address,
                        uds_info,
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
