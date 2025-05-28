# Packet Sniffer

A powerful network packet sniffer built with Python and Scapy. This tool allows you to capture and analyze network traffic with detailed protocol information.

## Features

- Real-time packet capture and analysis
- Support for multiple protocols (TCP, UDP, ICMP, ARP, DNS)
- IPv4 and IPv6 support
- Detailed DNS query and response analysis
- Filtering capabilities by protocol, port, domain, and source IP
- Colorized output for better readability
- Logging functionality

## Requirements

- Python 3.6+
- Scapy
- colorama
- netifaces

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/packet_sniffer.git
cd packet_sniffer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python sniffer.py --interface "Wi-Fi"
```

List available interfaces:
```bash
python sniffer.py
```

Capture specific number of packets:
```bash
python sniffer.py --interface "Wi-Fi" --count 10
```

Filter by protocol and port:
```bash
python sniffer.py --interface "Wi-Fi" --filter "tcp port 80"
```

Track packets from specific source IP:
```bash
python sniffer.py --interface "Wi-Fi" --source "192.168.1.100"
```

Filter DNS traffic by domain:
```bash
python sniffer.py --interface "Wi-Fi" --filter "port 53" --domain "example.com"
```

## Command Line Options

- `--interface`, `-i`: Network interface to capture packets from
- `--filter`, `-f`: BPF filter string (e.g., "tcp port 80")
- `--count`, `-c`: Number of packets to capture
- `--source`, `-s`: Track packets from specific source IP
- `--domain`, `-d`: Filter DNS packets for specific domain

## Project Structure

```
packet_sniffer/
├── sniffer.py          # Main script
├── requirements.txt    # Dependencies
├── logs/              # Capture logs
│   └── sniffer.log
└── README.md
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and legitimate network analysis purposes only. Always ensure you have proper authorization before capturing network traffic. 