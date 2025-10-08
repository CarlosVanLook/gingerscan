#!/bin/bash

# Ginger Scan - Installation Script
# This script installs Ginger Scan and its dependencies

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display banner
banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                  Ginger Scan Installer                       ║"
    echo "║                Installing Ginger Scan v1.0.0                 ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Python version
check_python() {
    if ! command_exists python3; then
        echo -e "${RED}Error: Python 3 is required but not installed${NC}"
        echo "Please install Python 3.11 or later"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    REQUIRED_VERSION="3.11"
    
    if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
        echo -e "${YELLOW}Warning: Python $PYTHON_VERSION detected. Python 3.11+ is recommended${NC}"
    else
        echo -e "${GREEN}✓ Python $PYTHON_VERSION detected${NC}"
    fi
}

# Function to check and install Nmap
check_nmap() {
    echo -e "${BLUE}Checking for Nmap installation...${NC}"
    
    if command_exists nmap; then
        NMAP_VERSION=$(nmap --version | head -n1 | grep -o '[0-9]\+\.[0-9]\+')
        echo -e "${GREEN}✓ Nmap $NMAP_VERSION detected${NC}"
        echo -e "${GREEN}✓ Comprehensive service detection will be available${NC}"
    else
        echo -e "${YELLOW}Nmap not found. Installing for comprehensive service detection...${NC}"
        
        # Detect OS and install Nmap
        if command_exists apt-get; then
            # Ubuntu/Debian
            sudo apt-get update
            sudo apt-get install -y nmap
        elif command_exists yum; then
            # CentOS/RHEL
            sudo yum install -y nmap
        elif command_exists dnf; then
            # Fedora
            sudo dnf install -y nmap
        elif command_exists brew; then
            # macOS
            brew install nmap
        elif command_exists pacman; then
            # Arch Linux
            sudo pacman -S nmap
        else
            echo -e "${RED}Could not detect package manager. Please install Nmap manually:${NC}"
            echo "  Ubuntu/Debian: sudo apt-get install nmap"
            echo "  CentOS/RHEL: sudo yum install nmap"
            echo "  macOS: brew install nmap"
            echo "  Arch Linux: sudo pacman -S nmap"
            echo ""
            echo -e "${YELLOW}Continuing without Nmap. Service detection will be limited.${NC}"
            return 1
        fi
        
        if command_exists nmap; then
            echo -e "${GREEN}✓ Nmap installed successfully${NC}"
            echo -e "${GREEN}✓ Comprehensive service detection enabled${NC}"
        else
            echo -e "${RED}Failed to install Nmap. Service detection will be limited.${NC}"
            return 1
        fi
    fi
}

# Function to create virtual environment
create_venv() {
    if [ ! -d "venv" ]; then
        echo -e "${BLUE}Creating virtual environment...${NC}"
        python3 -m venv venv
        echo -e "${GREEN}✓ Virtual environment created${NC}"
    else
        echo -e "${YELLOW}Virtual environment already exists${NC}"
    fi
}

# Function to activate virtual environment
activate_venv() {
    echo -e "${BLUE}Activating virtual environment...${NC}"
    source venv/bin/activate
    echo -e "${GREEN}✓ Virtual environment activated${NC}"
}

# Function to install dependencies
install_dependencies() {
    echo -e "${BLUE}Installing dependencies...${NC}"
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Try to install minimal requirements first
    if [ "$MINIMAL" = true ]; then
        echo -e "${YELLOW}Installing minimal dependencies...${NC}"
        pip install -r requirements-minimal.txt
    else
    # Try full requirements, fall back to minimal if it fails
    if pip install -r requirements.txt; then
        echo -e "${GREEN}✓ All dependencies installed${NC}"
        
        # Verify WebSocket support for web dashboard
        echo -e "${BLUE}Verifying WebSocket support...${NC}"
        if python -c "import websockets; import uvicorn; print('WebSocket support: OK')" 2>/dev/null; then
            echo -e "${GREEN}✓ WebSocket support verified${NC}"
        else
            echo -e "${YELLOW}Installing additional WebSocket support...${NC}"
            pip install "uvicorn[standard]" websockets
        fi
        
    else
        echo -e "${YELLOW}Some dependencies failed, installing minimal set...${NC}"
        pip install -r requirements-minimal.txt
        fi
    fi
    
    echo -e "${GREEN}✓ Dependencies installed${NC}"
}

# Function to install optional dependencies
install_optional() {
    echo -e "${BLUE}Installing optional dependencies...${NC}"
    
    # Install development dependencies
    pip install pytest pytest-asyncio pytest-cov black flake8 mypy pre-commit
    
    # Install web dependencies
    pip install fastapi uvicorn jinja2
    
    # Install report dependencies
    pip install reportlab plotly matplotlib
    
    # Install security dependencies
    pip install shodan cryptography
    
    echo -e "${GREEN}✓ Optional dependencies installed${NC}"
}

# Function to make scripts executable
make_executable() {
    echo -e "${BLUE}Making scripts executable...${NC}"
    chmod +x scripts/*.sh
    echo -e "${GREEN}✓ Scripts made executable${NC}"
}

# Function to run tests
run_tests() {
    echo -e "${BLUE}Running tests...${NC}"
    # If no tests directory or no test files, skip gracefully
    if [ ! -d "tests" ] || ! find tests -type f \( -name "test_*.py" -o -name "*_test.py" -o -name "tests.py" -o -name "test*.py" \) | grep -q .; then
        echo -e "${YELLOW}No tests found. Skipping test run.${NC}"
        return 0
    fi

    # Run pytest and handle the "no tests collected" exit code (5) as success
    if python3 -m pytest tests/ -v; then
        echo -e "${GREEN}✓ All tests passed${NC}"
    else
        rc=$?
        if [ "$rc" -eq 5 ]; then
            echo -e "${YELLOW}No tests collected. Skipping.${NC}"
            return 0
        fi
        echo -e "${YELLOW}Some tests failed, but installation continues${NC}"
    fi
}

# Function to create configuration
create_config() {
    echo -e "${BLUE}Setting up configuration...${NC}"
    
    # Create logs directory
    mkdir -p logs
    
    # Create reports directory
    mkdir -p reports
    
    # Copy default config if it doesn't exist
    if [ ! -f "config/local.yaml" ]; then
        cp config/default.yaml config/local.yaml
        echo -e "${GREEN}✓ Configuration file created${NC}"
    else
        echo -e "${YELLOW}Configuration file already exists${NC}"
    fi
}

# Function to display usage instructions
show_usage() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    Installation Complete                     ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo "Ginger Scan has been successfully installed."
    echo ""
    echo "Key capabilities:"
    echo "   - Comprehensive multi-step service detection"
    echo "   - Sequential multi-host scanning"
    echo "   - Priority-based scan management"
    echo "   - Web dashboard"
    echo "   - Reporting (HTML, PDF, TXT, CSV, JSON, YAML)"
    echo "   - Host information (geolocation, ISP, ASN)"
    echo "   - Graceful scan cancellation"
    echo "   - Unknown port investigation (711, 982, 1337, etc.)"
    echo ""
    echo "To get started:"
    echo "1. Activate the virtual environment:"
    echo "   source venv/bin/activate"
    echo ""
    echo "2. Run an all-in-one scan (enables discovery, banner, OS detection, IP info, vuln checks):"
    echo "   python3 -m tools.scanner --target 192.168.1.1 --ports 1-1000 --all"
    echo ""
    echo "3. Run a customized comprehensive scan:"
    echo "   python3 -m tools.scanner --target 192.168.1.1 --ports 1-1000 --banner --os-detection --ip-info"
    echo ""
    echo "4. Start the web dashboard:"
    echo "   python3 -m tools.web_dashboard"
    echo "   Access at: http://localhost:8000"
    echo ""
    echo "5. Scan multiple hosts sequentially:"
    echo "   python3 -m tools.scanner --target 192.168.1.1,192.168.1.2,192.168.1.3 --ports 22,80,443 --banner"
    echo ""
    echo "6. Generate reports:"
    echo "   python3 -m tools.scanner --target 192.168.1.1 --ports 1-1000 --output report.txt --format txt"
    echo ""
    echo "For more information, see README.md and docs/usage.md."
}

# Main installation function
main() {
    banner
    
    # Check Python
    check_python
    
    # Check and install Nmap
    check_nmap
    
    # Create virtual environment
    create_venv
    
    # Activate virtual environment
    activate_venv
    
    # Install dependencies
    install_dependencies
    
    # Ask about optional dependencies
    echo ""
    read -p "Install optional dependencies (web dashboard, reports, etc.)? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_optional
    fi
    
    # Make scripts executable
    make_executable
    
    # Create configuration
    create_config
    
    # Ask about running tests
    if [ "$NO_TESTS" = true ]; then
        echo -e "${YELLOW}Skipping tests as requested (--no-tests).${NC}"
    else
        echo ""
        read -p "Run tests to verify installation? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            run_tests
        fi
    fi
    
    # Show usage instructions
    show_usage
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --minimal)
            MINIMAL=true
            shift
            ;;
        --no-tests)
            NO_TESTS=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --minimal     Install only basic dependencies"
            echo "  --no-tests    Skip running tests"
            echo "  --no-nmap     Skip Nmap installation (service detection will be limited)"
            echo "  --all         Enable all scanner features by default (CLI examples)"
            echo "  --help        Show this help message"
            echo ""
            echo "Capabilities:"
            echo "  - Multi-step service detection"
            echo "  - Sequential multi-host scanning"
            echo "  - Priority-based scan management"
            echo "  - Web dashboard"
            echo "  - Reporting (HTML, PDF, TXT, CSV, JSON, YAML)"
            echo "  - Host information (geolocation, ISP, ASN)"
            echo "  - Graceful scan cancellation"
            echo "  - Unknown port investigation"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main installation
main
