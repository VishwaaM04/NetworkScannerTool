# Network Scanner Tool

A powerful command-line tool to scan open ports and detect active devices in a local network. This tool integrates Nmap for advanced network scanning capabilities and uses Socket programming for port scanning.

## Features

- **Active Host Detection**: Identify all active hosts in a given network using ICMP ping
- **Port Scanning**: Scan multiple ports on target hosts with multi-threaded approach
- **Nmap Integration**: Advanced network scanning using Nmap
- **Service Identification**: Identify common services running on open ports
- **Multi-threaded Scanning**: Fast and efficient scanning with configurable thread count
- **Detailed Reports**: Generate comprehensive scan reports with all findings

## Technologies Used

- **Python 3**: Core programming language
- **Socket Programming**: Low-level port scanning
- **Nmap**: Advanced network reconnaissance
- **Threading**: Multi-threaded scanning for performance
- **Subprocess**: Integration with system tools

## Installation

### Requirements
- Python 3.6+
- Nmap installed on system (optional, for advanced scanning)

### Setup

```bash
# Clone the repository
git clone https://github.com/VishwaaM04/NetworkScannerTool.git
cd NetworkScannerTool

# Install dependencies (if any)
pip install -r requirements.txt
```

## Usage

### Basic Network Scan

```bash
python3 network_scanner.py 192.168.1.0/24
```

### Scan Specific Ports

```bash
python3 network_scanner.py 192.168.1.100 --ports 20-1000
```

### Advanced Nmap Scan

```bash
python3 network_scanner.py 192.168.1.0/24 --nmap
```

## Project Structure

```
NetworkScannerTool/
├── network_scanner.py      # Main scanning tool
├── requirements.txt        # Python dependencies
├── README.md              # Project documentation
├── index.html             # Web demo interface
└── docs/                  # Additional documentation
```

## How It Works

### Host Discovery
- Sends ICMP echo requests to all hosts in the network
- Identifies active hosts with successful responses
- Uses multi-threading for faster discovery

### Port Scanning
- Attempts TCP connections to specified ports
- Identifies open ports where connections succeed
- Maps ports to known services
- Generates detailed reports

### Nmap Integration
- Executes Nmap commands with custom arguments
- Provides advanced network reconnaissance
- Supports various Nmap scanning techniques

## Example Output

```
============================================================
Network Scan Report - 2025-11-13 11:30:45
============================================================

Active Hosts Found: 5
  - 192.168.1.1
  - 192.168.1.100
  - 192.168.1.101
  - 192.168.1.102
  - 192.168.1.105

Open Ports by Host:

  192.168.1.100:
    Port    22 - SSH
    Port    80 - HTTP
    Port   443 - HTTPS
    Port  3306 - MySQL

============================================================
```

## Security Considerations

- **Ethical Use**: Only scan networks you own or have permission to scan
- **Network Impact**: Large scans may impact network performance
- **Firewall Rules**: Some networks may block or rate-limit ICMP/TCP
- **Legal**: Ensure compliance with local laws and regulations

## Troubleshooting

### No hosts found
- Check network connection
- Verify CIDR notation is correct
- Check firewall rules

### Permission denied
- Run with appropriate privileges
- On Linux/Mac: may need sudo for raw socket access

### Nmap not found
- Install Nmap: `brew install nmap` (Mac) or `apt install nmap` (Linux)
- Or use socket-based scanning without --nmap flag

## Author

Vishwaa - VishwaaM04

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Unauthorized access to computer networks is illegal. Always ensure you have proper authorization before scanning any network.
