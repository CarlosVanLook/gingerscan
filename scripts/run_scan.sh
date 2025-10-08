#!/bin/bash

# Ginger Scan - Scan Runner Script
# This script provides convenient ways to run common scan types

set -e

# Default values
TARGET=""
PORTS="1-1000"
SCAN_TYPE="tcp_connect"
TIMEOUT="3.0"
RATE_LIMIT="100"
THREADS="50"
OUTPUT=""
FORMAT="txt"
VERBOSE=false
BANNER=false
DISCOVER=false
OS_DETECTION=false
IP_INFO=false
VULN_CHECK=false
COMPREHENSIVE=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -t, --target TARGET        Target host or network (required)"
    echo "  -p, --ports PORTS          Port range or list (default: 1-1000)"
    echo "  -s, --scan-type TYPE       Scan type: tcp_connect, tcp_syn, udp (default: tcp_connect)"
    echo "  --timeout TIMEOUT          Connection timeout in seconds (default: 3.0)"
    echo "  --rate-limit RATE          Ports per second (default: 100)"
    echo "  --threads THREADS          Number of concurrent threads (default: 50)"
    echo "  -o, --output FILE          Output file"
    echo "  -f, --format FORMAT        Output format: json, csv, txt, xml (default: txt)"
    echo "  -v, --verbose              Verbose output"
    echo "  -b, --banner               Enable banner grabbing"
    echo "  -d, --discover             Enable host discovery"
    echo "  --os-detection             Enable OS detection"
    echo "  --ip-info                  Enable IP information gathering (hostname, geolocation, ASN)"
    echo "  --vuln-check               Enable vulnerability checks"
    echo "  --comprehensive            Enable all features (banner, discover, os-detection, ip-info, vuln-check)"
    echo "  -h, --help                 Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -t 192.168.1.1 -p 22,80,443 -b"
    echo "  $0 -t 192.168.1.0/24 -p 1-1000 -d -o results.json -f json"
    echo "  $0 -t example.com -s tcp_syn -v --vuln-check"
    echo "  $0 -t 192.168.1.1 -p 1-1000 --comprehensive --output results.json -f json"
    echo "  $0 -t 192.168.1.0/24 --comprehensive --scan-type tcp_syn"
}

# Function to display banner
banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                         Ginger Scan                          ║"
    echo "║                   Advanced Network Scanning                  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to check if target is provided
check_target() {
    if [ -z "$TARGET" ]; then
        echo -e "${RED}Error: Target is required${NC}"
        echo "Use -t or --target to specify the target host or network"
        echo "Run '$0 --help' for more information"
        exit 1
    fi
}

# Function to validate scan type
validate_scan_type() {
    case $SCAN_TYPE in
        tcp_connect|tcp_syn|udp)
            ;;
        *)
            echo -e "${RED}Error: Invalid scan type '$SCAN_TYPE'${NC}"
            echo "Valid scan types: tcp_connect, tcp_syn, udp"
            exit 1
            ;;
    esac
}

# Function to validate output format
validate_format() {
    case $FORMAT in
        json|csv|txt|xml)
            ;;
        *)
            echo -e "${RED}Error: Invalid output format '$FORMAT'${NC}"
            echo "Valid formats: json, csv, txt, xml"
            exit 1
            ;;
    esac
}

# Function to check dependencies
check_dependencies() {
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}Error: Python 3 is required but not installed${NC}"
        exit 1
    fi
    
    if [ "$SCAN_TYPE" = "tcp_syn" ] && ! python3 -c "import scapy" 2>/dev/null; then
        echo -e "${YELLOW}Warning: Scapy is not installed. SYN scanning will not be available.${NC}"
        echo "Install with: pip install scapy"
    fi
}

# Function to run the scan
run_scan() {
    echo -e "${GREEN}Starting scan...${NC}"
    echo "Target: $TARGET"
    echo "Ports: $PORTS"
    echo "Scan Type: $SCAN_TYPE"
    echo "Timeout: $TIMEOUT"
    echo "Rate Limit: $RATE_LIMIT"
    echo "Threads: $THREADS"
    if [ "$COMPREHENSIVE" = true ]; then
        echo "Comprehensive Scan: ENABLED (all features)"
        echo "  - Banner Grabbing: ENABLED"
        echo "  - Host Discovery: ENABLED"
        echo "  - OS Detection: ENABLED"
        echo "  - IP Information: ENABLED"
        echo "  - Vulnerability Checks: ENABLED"
    else
        echo "Banner Grabbing: $BANNER"
        echo "Host Discovery: $DISCOVER"
        echo "OS Detection: $OS_DETECTION"
        echo "IP Information: $IP_INFO"
        echo "Vulnerability Checks: $VULN_CHECK"
    fi
    echo ""
    
    # Build command - ensure we're in the project root
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
    
    # Check if virtual environment exists
    if [ -f "$PROJECT_ROOT/venv/bin/python" ]; then
        PYTHON_CMD="$PROJECT_ROOT/venv/bin/python"
    else
        PYTHON_CMD="python3"
    fi
    
    CMD="cd '$PROJECT_ROOT' && $PYTHON_CMD -m tools.cli scan"
    CMD="$CMD --target $TARGET"
    CMD="$CMD --ports $PORTS"
    CMD="$CMD --scan-type $SCAN_TYPE"
    CMD="$CMD --timeout $TIMEOUT"
    CMD="$CMD --rate-limit $RATE_LIMIT"
    CMD="$CMD --threads $THREADS"
    
    if [ "$VERBOSE" = true ]; then
        CMD="$CMD --verbose"
    fi
    
    if [ "$COMPREHENSIVE" = true ]; then
        CMD="$CMD --comprehensive"
    else
        if [ "$BANNER" = true ]; then
            CMD="$CMD --banner"
        fi
        
        if [ "$DISCOVER" = true ]; then
            CMD="$CMD --discover"
        fi
        
        if [ "$OS_DETECTION" = true ]; then
            CMD="$CMD --os-detection"
        fi
        
        if [ "$IP_INFO" = true ]; then
            CMD="$CMD --ip-info"
        fi
        
        if [ "$VULN_CHECK" = true ]; then
            CMD="$CMD --vuln-check"
        fi
    fi
    
    if [ -n "$OUTPUT" ]; then
        CMD="$CMD --output $OUTPUT"
    fi
    
    CMD="$CMD --format $FORMAT"
    
    # Run the command
    echo -e "${BLUE}Executing: $CMD${NC}"
    echo ""
    
    eval $CMD
    
    if [ $? -eq 0 ]; then
        echo ""
        echo -e "${GREEN}Scan completed successfully!${NC}"
        if [ -n "$OUTPUT" ]; then
            echo -e "${GREEN}Results saved to: $OUTPUT${NC}"
        fi
    else
        echo ""
        echo -e "${RED}Scan failed!${NC}"
        exit 1
    fi
}

# Function to run quick scan
quick_scan() {
    echo -e "${YELLOW}Running quick scan (common ports)...${NC}"
    PORTS="22,23,25,53,80,110,143,443,993,995,3389,5432,5900,6379,8080,9200"
    run_scan
}

# Function to run comprehensive scan
comprehensive_scan() {
    echo -e "${YELLOW}Running comprehensive scan...${NC}"
    PORTS="1-65535"
    COMPREHENSIVE=true
    run_scan
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--target)
            TARGET="$2"
            shift 2
            ;;
        -p|--ports)
            PORTS="$2"
            shift 2
            ;;
        -s|--scan-type)
            SCAN_TYPE="$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --rate-limit)
            RATE_LIMIT="$2"
            shift 2
            ;;
        --threads)
            THREADS="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT="$2"
            shift 2
            ;;
        -f|--format)
            FORMAT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -b|--banner)
            BANNER=true
            shift
            ;;
        -d|--discover)
            DISCOVER=true
            shift
            ;;
        --os-detection)
            OS_DETECTION=true
            shift
            ;;
        --ip-info)
            IP_INFO=true
            shift
            ;;
        --vuln-check)
            VULN_CHECK=true
            shift
            ;;
        --comprehensive)
            COMPREHENSIVE=true
            shift
            ;;
        --quick)
            quick_scan
            exit 0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option '$1'${NC}"
            usage
            exit 1
            ;;
    esac
done

# Main execution
banner
check_target
validate_scan_type
validate_format
check_dependencies
run_scan
