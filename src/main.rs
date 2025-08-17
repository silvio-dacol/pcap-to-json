/*
pcap-to-json — PCAP → NDJSON converter (see README.md)

High-level flow of this file (src/main.rs):
1) Parse CLI arguments with clap (Args).
   - input: path to PCAP/PCAPNG, or "-" to capture live traffic
   - iface: network interface to use for live capture
   - filter: optional BPF filter (e.g., "tcp port 443") applied by libpcap
   - out: output file path; if omitted, write to stdout
   - limit: stop after N packets (0 = unlimited)

2) Open the capture source via the pcap crate:
   - Offline: Capture::from_file(...) if input != "-"
   - Live:    Capture::from_device(...).promisc(true).immediate_mode(true).open() if input == "-"
   - If a --filter is provided, it is compiled and applied at the capture level.

3) Stream packets in run_capture(...) and emit one JSON object per line (NDJSON):
   - Convert libpcap timestamps to RFC3339/UTC string (field: ts)
   - Decode layers with pnet:
       Ethernet → (maybe) IPv4/IPv6 → (maybe) TCP/UDP
   - For each successfully decoded layer, populate the corresponding Optional JSON section.
   - Serialize with serde_json and write a single line per packet.

4) Output schema roughly will be:
   {
     "ts": "2025-08-17T12:34:56.123456Z",
     "len": 74,
     "eth": { "src": "aa:bb:cc:dd:ee:ff", "dst": "11:22:33:44:55:66", "ethertype": "ipv4" },
     "ip":  { "src": "192.168.0.10", "dst": "8.8.8.8", "proto": "udp", "ttl": 64 },
     "tcp": { "src_port": 443, "dst_port": 58624, "syn": false, "ack": true },
     "udp": { ... }
   }
   - len is the captured byte length for this packet buffer.
   - ethertype/proto/next_header are printed as strings for quick filtering.
   - ip (IPv4) and ip6 (IPv6) are mutually exclusive for a given packet.
   - tcp/udp sections appear only if the packet contains those transport layers.

Notes and tips:
- This tool does not emit payload bytes; it focuses on headers/metadata. You can extend
  PacketJson to include more fields from pnet_packet if needed.
- BPF filters (e.g., "host 8.8.8.8", "tcp port 443") reduce what libpcap delivers, improving speed.
- For live capture, on some OSes you may need elevated privileges for promisc mode.
- Timestamps are generated from libpcap's timeval and converted to RFC3339 with chrono.
- IPv4 uses ttl; IPv6 uses hop_limit. The field names match their respective headers.
- NDJSON means one compact JSON object per line; easy to pipe into jq, log stores, etc.

Example usage:
  # Convert a file to NDJSON on stdout
  pcap-to-json trace.pcapng | jq .

  # Live capture from default iface, filter only UDP, save to file
  pcap-to-json - --filter "udp" --out out.ndjson

*/


use anyhow::{Context, Result};
use clap::Parser;
use pcap::{Activated, Capture};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet;
use serde::Serialize;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(name = "pcap-to-json", version, about = "PCAP → NDJSON converter (pcap + pnet + serde_json)")]
struct Args {
    /// PCAP/PCAPNG file path (use '-' to capture live from default device)
    #[arg()]
    input: String,

    /// Network interface for live capture (ignored if reading from file)
    #[arg(long)]
    iface: Option<String>,

    /// BPF filter (e.g., 'tcp port 443')
    #[arg(long)]
    filter: Option<String>,

    /// Output file (defaults to stdout)
    #[arg(long)]
    out: Option<PathBuf>,

    /// Limit number of packets (0 = no limit)
    #[arg(long, default_value_t = 0)]
    limit: u64,
}

#[derive(Serialize)]
struct EthJson {
    src: String,
    dst: String,
    ethertype: String,
}

#[derive(Serialize)]
struct Ip4Json {
    src: String,
    dst: String,
    proto: String,
    ttl: u8,
}

#[derive(Serialize)]
struct Ip6Json {
    src: String,
    dst: String,
    next_header: String,
    hop_limit: u8,
}

#[derive(Serialize)]
struct TcpJson {
    src_port: u16,
    dst_port: u16,
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
    psh: bool,
    urg: bool,
    ecn: bool,
    cwr: bool,
}

#[derive(Serialize)]
struct UdpJson {
    src_port: u16,
    dst_port: u16,
    length: u16,
}

#[derive(Serialize)]
struct PacketJson {
    ts: String,
    len: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    eth: Option<EthJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<Ip4Json>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip6: Option<Ip6Json>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp: Option<TcpJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp: Option<UdpJson>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Writer (stdout or file)
    let writer: Box<dyn Write> = match args.out {
        Some(p) => Box::new(BufWriter::new(File::create(p)?)),
        None => Box::new(io::BufWriter::new(io::stdout())),
    };
    let mut writer = writer;

    // Capture: file or live
    if args.input == "-" {
        // Live capture
        let mut cap = if let Some(iface) = &args.iface {
            Capture::from_device(iface.as_str())
                .context("Interface not found")?
                .promisc(true)
                .immediate_mode(true)
                .open()
                .context("Failed to open live capture")?
        } else {
            let dev = pcap::Device::lookup()
                .context("Failed to lookup default device")?
                .ok_or_else(|| anyhow::anyhow!("No default device"))?;
            Capture::from_device(dev.name.as_str())?
                .promisc(true)
                .immediate_mode(true)
                .open()
                .context("Failed to open live capture")?
        };
        if let Some(f) = &args.filter {
            cap.filter(f, true)?;
        }
        run_capture(&mut cap, args.limit, &mut writer)?;
    } else {
        // Offline capture from file
        let mut cap = Capture::from_file(&args.input)
            .with_context(|| format!("Failed to open input file '{}'", args.input))?;
        if let Some(f) = &args.filter {
            cap.filter(f, true)?;
        }
        run_capture(&mut cap, args.limit, &mut writer)?;
    }

    Ok(())
}

fn run_capture<T: Activated>(
    cap: &mut Capture<T>,
    limit: u64,
    writer: &mut dyn Write,
) -> Result<()> {
    let mut count: u64 = 0;

    while let Ok(packet) = cap.next_packet() {
        // Respect limit
        if limit != 0 && count >= limit {
            break;
        }

        // Timestamp → RFC3339
        let ts = packet.header.ts;
        let secs = ts.tv_sec as u64;
        let usec = ts.tv_usec as u32;
        let nanos = (usec as u64) * 1000;
        let datetime = UNIX_EPOCH + Duration::new(secs, nanos as u32);
        let ts_str = chrono::DateTime::<chrono::Utc>::from(datetime).to_rfc3339();

        // Decode Ethernet
        let mut eth_json: Option<EthJson> = None;
        let mut ip4_json: Option<Ip4Json> = None;
        let mut ip6_json: Option<Ip6Json> = None;
        let mut tcp_json: Option<TcpJson> = None;
        let mut udp_json: Option<UdpJson> = None;

        if let Some(eth_pkt) = EthernetPacket::new(packet.data) {
            let ethertype = match eth_pkt.get_ethertype() {
                EtherTypes::Ipv4 => "ipv4",
                EtherTypes::Ipv6 => "ipv6",
                EtherTypes::Arp => "arp",
                _ => "other",
            }
            .to_string();

            eth_json = Some(EthJson {
                src: format!("{}", eth_pkt.get_source()),
                dst: format!("{}", eth_pkt.get_destination()),
                ethertype,
            });

            match eth_pkt.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ip) = Ipv4Packet::new(eth_pkt.payload()) {
                        let proto = match ip.get_next_level_protocol() {
                            pnet_packet::ip::IpNextHeaderProtocols::Tcp => "tcp",
                            pnet_packet::ip::IpNextHeaderProtocols::Udp => "udp",
                            pnet_packet::ip::IpNextHeaderProtocols::Icmp => "icmp",
                            _ => "other",
                        }
                        .to_string();

                        ip4_json = Some(Ip4Json {
                            src: ip.get_source().to_string(),
                            dst: ip.get_destination().to_string(),
                            proto: proto.clone(),
                            ttl: ip.get_ttl(),
                        });

                        match ip.get_next_level_protocol() {
                            pnet_packet::ip::IpNextHeaderProtocols::Tcp => {
                                if let Some(tcp) = TcpPacket::new(ip.payload()) {
                                    tcp_json = Some(TcpJson {
                                        src_port: tcp.get_source(),
                                        dst_port: tcp.get_destination(),
                                        syn: tcp.get_flags() & pnet_packet::tcp::TcpFlags::SYN != 0,
                                        ack: tcp.get_flags() & pnet_packet::tcp::TcpFlags::ACK != 0,
                                        fin: tcp.get_flags() & pnet_packet::tcp::TcpFlags::FIN != 0,
                                        rst: tcp.get_flags() & pnet_packet::tcp::TcpFlags::RST != 0,
                                        psh: tcp.get_flags() & pnet_packet::tcp::TcpFlags::PSH != 0,
                                        urg: tcp.get_flags() & pnet_packet::tcp::TcpFlags::URG != 0,
                                        ecn: tcp.get_flags() & pnet_packet::tcp::TcpFlags::ECE != 0,
                                        cwr: tcp.get_flags() & pnet_packet::tcp::TcpFlags::CWR != 0,
                                    });
                                }
                            }
                            pnet_packet::ip::IpNextHeaderProtocols::Udp => {
                                if let Some(udp) = UdpPacket::new(ip.payload()) {
                                    udp_json = Some(UdpJson {
                                        src_port: udp.get_source(),
                                        dst_port: udp.get_destination(),
                                        length: udp.get_length(),
                                    });
                                }
                            }
                            _ => {}
                        }
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(ip6) = Ipv6Packet::new(eth_pkt.payload()) {
                        let next = ip6.get_next_header();
                        ip6_json = Some(Ip6Json {
                            src: ip6.get_source().to_string(),
                            dst: ip6.get_destination().to_string(),
                            next_header: format!("{:?}", next),
                            hop_limit: ip6.get_hop_limit(),
                        });

                        match next {
                            pnet_packet::ip::IpNextHeaderProtocols::Tcp => {
                                if let Some(tcp) = TcpPacket::new(ip6.payload()) {
                                    tcp_json = Some(TcpJson {
                                        src_port: tcp.get_source(),
                                        dst_port: tcp.get_destination(),
                                        syn: tcp.get_flags() & pnet_packet::tcp::TcpFlags::SYN != 0,
                                        ack: tcp.get_flags() & pnet_packet::tcp::TcpFlags::ACK != 0,
                                        fin: tcp.get_flags() & pnet_packet::tcp::TcpFlags::FIN != 0,
                                        rst: tcp.get_flags() & pnet_packet::tcp::TcpFlags::RST != 0,
                                        psh: tcp.get_flags() & pnet_packet::tcp::TcpFlags::PSH != 0,
                                        urg: tcp.get_flags() & pnet_packet::tcp::TcpFlags::URG != 0,
                                        ecn: tcp.get_flags() & pnet_packet::tcp::TcpFlags::ECE != 0,
                                        cwr: tcp.get_flags() & pnet_packet::tcp::TcpFlags::CWR != 0,
                                    });
                                }
                            }
                            pnet_packet::ip::IpNextHeaderProtocols::Udp => {
                                if let Some(udp) = UdpPacket::new(ip6.payload()) {
                                    udp_json = Some(UdpJson {
                                        src_port: udp.get_source(),
                                        dst_port: udp.get_destination(),
                                        length: udp.get_length(),
                                    });
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => { /* non-IP */ }
            }
        }

        let obj = PacketJson {
            ts: ts_str,
            len: packet.data.len(),
            eth: eth_json,
            ip: ip4_json,
            ip6: ip6_json,
            tcp: tcp_json,
            udp: udp_json,
        };

        serde_json::to_writer(&mut *writer, &obj)?;
        writer.write_all(b"\n")?;
        count += 1;
    }

    writer.flush()?;
    Ok(())
}
