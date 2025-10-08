# Usage Guide

This guide provides detailed instructions on how to use Ginger Scan for various network scanning and analysis tasks.

## Table of Contents

- [Installation](#installation)
- [Command Line Interface](#command-line-interface)
- [Web Dashboard](#web-dashboard)
- [Configuration](#configuration)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

## Installation

### Local Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mrxcherif/gingerscan.git
   cd gingerscan
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### Docker Installation

1. **Build and run with Docker Compose:**
   ```bash
   docker-compose up --build
   ```

2. **Or build and run manually:**
   ```bash
   docker build -t gingerscan .
   docker run -it --rm --network host gingerscan
   ```

## Command Line Interface

### Basic Usage

The CLI provides several commands for different tasks:

```bash
# Basic port scan
python -m tools.cli scan --target 192.168.1.1 --ports 1-1000

# Comprehensive scan with banner grabbing
python -m tools.cli scan --target 192.168.1.0/24 --ports 22,80,443 --banner --discover

# Full scan with all features enabled (alias for --comprehensive)
python -m tools.cli scan --target 192.168.1.1 --ports 1-1000 --all

# Generate HTML report
python -m tools.cli scan --target 192.168.1.1 --ports 1-1000 --output results.json --format json
python -m tools.cli report --input results.json --output report.html --report-format html

# Parse existing scan results
python -m tools.cli parse --input results.json --format json --output parsed.csv --output-format csv

# Check vulnerabilities
python -m tools.cli vuln --input results.json --output vulnerabilities.json

# Start web dashboard
python -m tools.cli web --host 0.0.0.0 --port 8000
```

### Scan Command Options

| Option | Description | Default |
|--------|-------------|---------|
| `--target`, `-t` | Target host or network (required) | - |
| `--ports`, `-p` | Port range or list | `1-1000` |
| `--scan-type`, `-s` | Type of scan (`tcp_connect`, `tcp_syn`, `udp`) | `tcp_connect` |
| `--timeout` | Connection timeout in seconds | `3.0` |
| `--rate-limit` | Ports per second | `100` |
| `--threads` | Number of concurrent threads | `50` |
| `--banner` | Enable banner grabbing | `False` |
| `--discover` | Enable host discovery | `False` |
| `--all`, `-a` | Enable all features (same as `--comprehensive`) | `False` |
| `--vuln-check` | Enable vulnerability checks | `False` |
| `--output`, `-o` | Output file | - |
| `--format` | Output format (`json`, `csv`, `txt`, `xml`) | `txt` |
| `--verbose`, `-v` | Verbose output | `False` |

### Port Specification

Ports can be specified in several ways:

```bash
# Single ports
--ports 22,80,443

# Port ranges
--ports 1-1000

# Mixed
--ports 1-1000,22,80,443,8080-8090

# Common port lists
--ports 22,23,25,53,80,110,143,443,993,995,3389
```

### Scan Types

1. **TCP Connect Scan** (`tcp_connect`):
   - Establishes full TCP connection
   - Most reliable but easily detected
   - Default scan type

2. **TCP SYN Scan** (`tcp_syn`):
   - Sends SYN packets without completing handshake
   - Faster and stealthier
   - Requires Scapy and root privileges

3. **UDP Scan** (`udp`):
   - Scans UDP ports
   - Less reliable due to UDP nature
   - Useful for DNS, SNMP, etc.

### Comprehensive Service Detection

When the `--banner` option is enabled, the tool performs a comprehensive 6-step service detection process:

1. **Banner Grab**: Simple connection and banner reading
2. **Application Probes**: Service-specific probes (HTTP GET, SMTP EHLO, FTP USER, MySQL handshake, Redis PING, etc.)
3. **TLS Detection**: SSL/TLS certificate analysis and cipher identification
4. **Nmap Analysis**: Industry-standard `nmap -sV` version detection
5. **Protocol Fingerprinting**: Response pattern analysis and binary protocol detection
6. **NSE Scripts**: Nmap Scripting Engine for vulnerability detection

**Requirements for Full Functionality**:
```bash
# Install Nmap for best results
sudo apt-get install nmap  # Ubuntu/Debian
sudo yum install nmap      # CentOS/RHEL
brew install nmap         # macOS
```

**Service Detection Results**:
- **High Confidence (0.8-1.0)**: SSH, HTTP, HTTPS, FTP, SMTP, MySQL, etc.
- **Medium Confidence (0.5-0.7)**: Custom applications with clear patterns
- **Unknown Services (0.1-0.4)**: Ports requiring manual investigation (711, 982, 1337, etc.)

## Web Dashboard

### Starting the Dashboard

```bash
python -m tools.cli web --host 0.0.0.0 --port 8000
```

Access the dashboard at `http://localhost:8000`

### Dashboard Features

- **Sequential Multi-Host Scanning**: Scan multiple hosts one at a time with intelligent queue management
- **Priority-Based Display**: Running scans at top, pending in middle, completed at bottom (sorted by end time)
- **Professional Messaging**: Context-aware scan start messages (single vs. multiple hosts)
- **Real-time Progress**: Live updates with detailed phase information:
  - ARP scan progress
  - OS detection status
  - IP information gathering
  - Port scanning with percentage
  - Service detection progress
- **Enhanced Service Detection**: 6-step comprehensive service identification
- **Comprehensive Reports**: Export in HTML, PDF, TXT, CSV, JSON, YAML formats with host information
- **Graceful Cancellation**: Stop scans immediately with automatic progression to next pending scan
- **Unique Scan IDs**: 6-digit unique identifiers for each scan
- **Interactive Scan Configuration**: Web form for setting scan parameters
- **Results Visualization**: Tables and charts of scan results
- **Scan History**: View and manage previous scans

### API Endpoints

The web dashboard also provides a REST API:

- `POST /api/scan` - Start a new scan (supports multiple targets with sequential processing)
- `GET /api/scan/{scan_id}/status` - Get scan status with detailed progress
- `GET /api/scan/{scan_id}/results` - Get scan results
- `GET /api/scan/{scan_id}/report` - Generate comprehensive report (HTML, PDF, TXT, CSV, JSON, YAML)
- `GET /api/scan/{scan_id}/export` - Export results in various formats
- `GET /api/scans` - List all scans with priority sorting
- `POST /api/scan/{scan_id}/stop` - Stop current scan and start next pending scan

## Configuration

### Configuration File

Create a `config.yaml` file for persistent settings:

```yaml
# Default scan configuration
default_scan:
  timeout: 3.0
  rate_limit: 100
  threads: 50
  banner_grab: true
  host_discovery: true

# Output settings
output:
  default_format: json
  save_reports: true
  report_directory: ./reports

# Vulnerability checks
vulnerability:
  check_anonymous_ftp: true
  check_ssl_certificates: true
  check_http_headers: true
  shodan_api_key: "your_api_key_here"

# Web dashboard
dashboard:
  host: "0.0.0.0"
  port: 8000
  debug: false
```

### Environment Variables

Set these environment variables for configuration:

```bash
export NETWORK_TOOLS_TIMEOUT=5.0
export NETWORK_TOOLS_RATE_LIMIT=200
export NETWORK_TOOLS_THREADS=100
export SHODAN_API_KEY="your_api_key_here"
```

## Examples

### Basic Network Scan

```bash
# Scan a single host
python -m tools.cli scan --target 192.168.1.1 --ports 1-1000

# Scan a network range
python -m tools.cli scan --target 192.168.1.0/24 --ports 22,80,443

# Scan with host discovery
python -m tools.cli scan --target 192.168.1.0/24 --ports 1-1000 --discover
```

### Advanced Scanning

```bash
# Comprehensive scan with all features
python -m tools.cli scan \
  --target 192.168.1.0/24 \
  --ports 1-1000 \
  --scan-type tcp_syn \
  --all \
  --output comprehensive_scan.json \
  --format json

# Fast scan with high concurrency
python -m tools.cli scan \
  --target 192.168.1.1 \
  --ports 1-65535 \
  --threads 200 \
  --rate-limit 500 \
  --timeout 1.0
```

### Report Generation

```bash
# Generate HTML report
python -m tools.cli report \
  --input scan_results.json \
  --output report.html \
  --report-format html \
  --title "Network Security Assessment"

# Generate PDF report
python -m tools.cli report \
  --input scan_results.json \
  --output report.pdf \
  --report-format pdf
```

### Data Processing

```bash
# Parse Nmap XML output
python -m tools.cli parse \
  --input nmap_output.xml \
  --format xml \
  --output parsed_results.json \
  --output-format json

# Convert between formats
python -m tools.cli parse \
  --input results.csv \
  --format csv \
  --output results.xml \
  --output-format xml
```

### Vulnerability Assessment

```bash
# Check vulnerabilities in scan results
python -m tools.cli vuln \
  --input scan_results.json \
  --output vulnerabilities.json \
  --check-ftp \
  --check-ssl

# With Shodan integration
python -m tools.cli vuln \
  --input scan_results.json \
  --shodan-key "your_api_key" \
  --output vulnerabilities.json
```

## Troubleshooting

### Common Issues

1. **Permission Denied for SYN Scan**:
   ```bash
   # Run with sudo for SYN scans
   sudo python -m tools.cli scan --target 192.168.1.1 --scan-type tcp_syn
   ```

2. **Scapy Import Error**:
   ```bash
   # Install Scapy
   pip install scapy
   ```

3. **Docker Network Issues**:
   ```bash
   # Use host networking
   docker run --network host gingerscan
   ```

4. **Rate Limiting**:
   ```bash
   # Reduce rate limit for stability
   python -m tools.cli scan --target 192.168.1.1 --rate-limit 50
   ```

### Performance Tuning

1. **Increase Threads for Faster Scans**:
   ```bash
   python -m tools.cli scan --target 192.168.1.0/24 --threads 200
   ```

2. **Adjust Timeout for Slow Networks**:
   ```bash
   python -m tools.cli scan --target 192.168.1.1 --timeout 10.0
   ```

3. **Optimize Rate Limiting**:
   ```bash
   # For local networks
   python -m tools.cli scan --target 192.168.1.1 --rate-limit 1000
   
   # For internet scans
   python -m tools.cli scan --target 8.8.8.8 --rate-limit 50
   ```

### Debug Mode

Enable verbose output for debugging:

```bash
python -m tools.cli scan --target 192.168.1.1 --verbose
```

### Log Files

Check log files for detailed error information:

```bash
# View recent logs
tail -f /var/log/gingerscan.log

# Check specific scan logs
grep "scan_12345" /var/log/gingerscan.log
```

## Best Practices

1. **Always get permission** before scanning networks
2. **Use appropriate scan types** for your needs
3. **Start with small ranges** to test configuration
4. **Monitor network impact** during scans
5. **Save results** for analysis and comparison
6. **Regular updates** of vulnerability databases
7. **Secure storage** of scan results and reports
