# Ginger Scan Complete Setup Guide

This comprehensive guide helps you install and configure Ginger Scan with all features including the web dashboard with real-time updates.

## 🚀 Quick Start

### Option 1: Automated Installation (Recommended)
```bash
chmod +x install.sh
./install.sh
```

### Option 2: Manual Installation
```bash
# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# 2. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 3. Verify installation
python3 -m tools.cli --help
```

## 🔧 Dependency Requirements

### Core Dependencies
- **Python 3.11+** (required)
- **click>=8.1.0** - CLI framework
- **rich>=13.0.0** - Rich terminal output
- **pydantic>=2.0.0** - Data validation
- **scapy>=2.5.0** - Network packet manipulation
- **requests>=2.31.0** - HTTP requests

### Web Dashboard Dependencies
- **fastapi>=0.100.0** - Web framework
- **uvicorn[standard]>=0.20.0** - ASGI server with WebSocket support
- **websockets>=10.0** - WebSocket support for real-time updates
- **python-multipart>=0.0.5** - Form data parsing
- **jinja2>=3.1.0** - Template engine

### Optional Dependencies
- **matplotlib>=3.7.0** - Charts and graphs
- **plotly>=5.15.0** - Interactive visualizations
- **reportlab>=4.0.0** - PDF generation
- **pandas>=2.0.0** - Data processing
- **shodan>=1.30.0** - Shodan API integration

## 🚨 Common Issues & Solutions

### Issue 1: Externally Managed Environment
**Error**: `error: externally-managed-environment`

**Solution**: Use a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Issue 2: WebSocket Support Missing
**Error**: `No supported WebSocket library detected`

**Solution**: Install WebSocket support
```bash
pip install "uvicorn[standard]" websockets
# or
pip install -r requirements.txt  # This includes WebSocket support
```

### Issue 3: Scapy Permission Issues
**Error**: `Operation not permitted` during ARP scans

**Solutions**:
```bash
# Option 1: Run with sudo (not recommended for web dashboard)
sudo python3 -m tools.cli scan -t 192.168.1.0/24

# Option 2: Set capabilities (recommended)
sudo setcap cap_net_raw=eip $(which python3)

# Option 3: Use without ARP scanning (will use ICMP ping instead)
# No action needed - tool automatically falls back
```

### Issue 4: Cryptography Installation Fails
**Error**: `Failed building wheel for cryptography`

**Solutions**:
```bash
# Install system dependencies first
# Ubuntu/Debian:
sudo apt-get update
sudo apt-get install build-essential libssl-dev libffi-dev python3-dev

# CentOS/RHEL:
sudo yum install gcc openssl-devel libffi-devel python3-devel

# Then install cryptography
pip install --upgrade pip
pip install cryptography
```

### Issue 5: Port Already in Use
**Error**: `address already in use` for web dashboard

**Solutions**:
```bash
# Option 1: Kill existing process
pkill -f "tools.cli web"

# Option 2: Use different port
python3 -m tools.cli web --port 8001

# Option 3: Find and kill process using port 8000
lsof -i :8000
kill -9 <PID>
```

## 📋 Installation Verification

### 1. Test CLI Tools
```bash
# Activate virtual environment
source venv/bin/activate

# Test basic scan
python3 -m tools.cli scan --target 127.0.0.1 --ports 80

# Test with verbose output
python3 -m tools.cli scan --target 127.0.0.1 --ports 22,80,443 --verbose

# Test banner grabbing
python3 -m tools.cli scan --target 127.0.0.1 --ports 80 --banner
```

### 2. Test Web Dashboard
```bash
# Start web dashboard
python3 -m tools.cli web

# Expected output:
# Starting web dashboard on 0.0.0.0:8000
# Access the dashboard at: http://0.0.0.0:8000
# INFO:     Uvicorn running on http://0.0.0.0:8000

# Access in browser: http://localhost:8000
```

### 3. Test WebSocket Functionality
```bash
# Test WebSocket support
python3 -c "import websockets; print('WebSocket support: OK')"

# Test uvicorn[standard]
python3 -c "import uvicorn; print('Uvicorn standard: OK')"
```

## 🐳 Docker Installation (Alternative)

### Build Docker Image
```bash
docker build -t gingerscan .
```

### Run with Docker
```bash
# CLI usage
docker run --rm -it --network host gingerscan scan -t 127.0.0.1 -p 80

# Web dashboard
docker run --rm -p 8000:8000 gingerscan web
```

### Run with Docker Compose
```bash
docker-compose up -d
```

## 🌐 Web Dashboard Features

### Real-Time Updates
- **WebSocket support** required for live progress updates
- **Status flow**: PENDING → RUNNING → COMPLETED
- **Progress tracking**: Real-time percentage updates
- **Current target display**: Shows which host is being scanned

### API Endpoints
- `POST /api/scan` - Start new scan
- `GET /api/scan/{id}/status` - Get scan status
- `GET /api/scan/{id}/results` - Get scan results
- `GET /api/scan/{id}/report` - Generate report
- `GET /api/scans` - List all scans
- `WebSocket /ws` - Real-time updates

## 🔒 Security Considerations

### Network Permissions
- **ARP scanning** requires raw socket access
- **SYN scanning** requires root privileges or capabilities
- **Web dashboard** should not be run as root

### Recommended Setup
```bash
# Set capabilities for network access
sudo setcap cap_net_raw=eip $(which python3)

# Run web dashboard as regular user
python3 -m tools.cli web
```

## 📊 Feature Overview

### Scanning Capabilities
- ✅ **Port Scanning**: TCP Connect, SYN, UDP
- ✅ **Host Discovery**: ICMP ping, ARP scan, DNS resolution
- ✅ **Banner Grabbing**: Service identification and version detection
- ✅ **Vulnerability Checks**: Security header analysis, default credentials
- ✅ **Real-time Progress**: Live updates via WebSocket

### Output Formats
- ✅ **Terminal**: Rich formatted output with colors
- ✅ **JSON**: Machine-readable format
- ✅ **CSV**: Spreadsheet-compatible
- ✅ **XML**: Nmap-compatible format
- ✅ **HTML Reports**: Web-viewable reports with vulnerability details
- ✅ **PDF Reports**: Professional documentation

### Web Dashboard
- ✅ **Modern UI**: Responsive design with animations
- ✅ **Real-time Updates**: WebSocket-powered live progress
- ✅ **Host-based Naming**: Scans named by target host
- ✅ **Vulnerability Viewer**: Detailed security findings
- ✅ **Report Generation**: HTML and JSON reports
- ✅ **Progress Tracking**: Visual progress bars and status indicators

## 🔄 Upgrade Instructions

### Update Ginger Scan
```bash
cd /path/to/gingerscan
git pull origin main

# Reactivate virtual environment
source venv/bin/activate

# Update dependencies
pip install --upgrade pip
pip install -r requirements.txt --upgrade

# Verify WebSocket support
python3 -c "import websockets; print('WebSocket support: OK')"
```

## 📞 Support

If you encounter issues not covered in this guide:

1. **Check logs**: Look for error messages in terminal output
2. **Verify dependencies**: Ensure all required packages are installed
3. **Test step by step**: Follow verification steps above
4. **Check permissions**: Ensure proper network access permissions

### Debug Commands
```bash
# Check Python version
python3 --version

# Check installed packages
pip list | grep -E "(fastapi|uvicorn|websockets|scapy)"

# Test network permissions
python3 -c "import scapy.all; print('Scapy permissions: OK')"

# Test WebSocket server
python3 -c "import uvicorn; print('Uvicorn available:', hasattr(uvicorn, 'run'))"
```

This guide should help you get Ginger Scan running with all features enabled, including the real-time web dashboard! 🚀