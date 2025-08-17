# pcap-to-json

A tool to convert pcap files to JSON.

### Example output in json

{
"ts": "2025-08-17T12:34:56.123456Z",
"len": 74,
"eth": { "src": "aa:bb:cc:dd:ee:ff", "dst": "11:22:33:44:55:66", "ethertype": "ipv4" },
"ip": { "src": "192.168.0.10", "dst": "8.8.8.8", "proto": "udp", "ttl": 64 },
"tcp": { "src_port": 443, "dst_port": 58624, "syn": false, "ack": true }
"udp": {...}
}
