#!/bin/bash

# Ginger Scan - Output Parser Script
# This script provides convenient ways to parse and convert scan results

set -e

# Default values
INPUT=""
INPUT_FORMAT="json"
OUTPUT=""
OUTPUT_FORMAT="json"
VERBOSE=false

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
    echo "  -i, --input FILE           Input file (required)"
    echo "  --input-format FORMAT      Input format: json, csv, txt, xml (default: json)"
    echo "  -o, --output FILE          Output file"
    echo "  --output-format FORMAT     Output format: json, csv, txt, xml (default: json)"
    echo "  -v, --verbose              Verbose output"
    echo "  -h, --help                 Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -i results.json -o results.csv --output-format csv"
    echo "  $0 -i nmap_output.xml --input-format xml -o parsed.json"
    echo "  $0 -i scan_results.txt --input-format txt -o formatted.json"
}

# Function to display banner
banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                  Ginger Scan Parser                         ║"
    echo "║                 Scan Result Processing                       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to check if input file is provided
check_input() {
    if [ -z "$INPUT" ]; then
        echo -e "${RED}Error: Input file is required${NC}"
        echo "Use -i or --input to specify the input file"
        echo "Run '$0 --help' for more information"
        exit 1
    fi
    
    if [ ! -f "$INPUT" ]; then
        echo -e "${RED}Error: Input file '$INPUT' does not exist${NC}"
        exit 1
    fi
}

# Function to validate input format
validate_input_format() {
    case $INPUT_FORMAT in
        json|csv|txt|xml)
            ;;
        *)
            echo -e "${RED}Error: Invalid input format '$INPUT_FORMAT'${NC}"
            echo "Valid input formats: json, csv, txt, xml"
            exit 1
            ;;
    esac
}

# Function to validate output format
validate_output_format() {
    case $OUTPUT_FORMAT in
        json|csv|txt|xml)
            ;;
        *)
            echo -e "${RED}Error: Invalid output format '$OUTPUT_FORMAT'${NC}"
            echo "Valid output formats: json, csv, txt, xml"
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
}

# Function to run the parser
run_parser() {
    echo -e "${GREEN}Starting parsing...${NC}"
    echo "Input File: $INPUT"
    echo "Input Format: $INPUT_FORMAT"
    echo "Output File: $OUTPUT"
    echo "Output Format: $OUTPUT_FORMAT"
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
    
    CMD="cd '$PROJECT_ROOT' && $PYTHON_CMD -m tools.cli parse"
    CMD="$CMD --input $INPUT"
    CMD="$CMD --format $INPUT_FORMAT"
    
    if [ -n "$OUTPUT" ]; then
        CMD="$CMD --output $OUTPUT"
    fi
    
    CMD="$CMD --output-format $OUTPUT_FORMAT"
    
    # Run the command
    echo -e "${BLUE}Executing: $CMD${NC}"
    echo ""
    
    eval $CMD
    
    if [ $? -eq 0 ]; then
        echo ""
        echo -e "${GREEN}Parsing completed successfully!${NC}"
        if [ -n "$OUTPUT" ]; then
            echo -e "${GREEN}Results saved to: $OUTPUT${NC}"
        fi
    else
        echo ""
        echo -e "${RED}Parsing failed!${NC}"
        exit 1
    fi
}

# Function to show file info
show_file_info() {
    if [ -f "$INPUT" ]; then
        echo -e "${BLUE}File Information:${NC}"
        echo "File: $INPUT"
        echo "Size: $(du -h "$INPUT" | cut -f1)"
        echo "Lines: $(wc -l < "$INPUT")"
        echo "Type: $(file "$INPUT" | cut -d: -f2)"
        echo ""
    fi
}

# Function to validate file format
validate_file_format() {
    case $INPUT_FORMAT in
        json)
            if ! python3 -c "import json; json.load(open('$INPUT'))" 2>/dev/null; then
                echo -e "${YELLOW}Warning: File may not be valid JSON${NC}"
            fi
            ;;
        csv)
            if ! python3 -c "import csv; list(csv.reader(open('$INPUT')))" 2>/dev/null; then
                echo -e "${YELLOW}Warning: File may not be valid CSV${NC}"
            fi
            ;;
        xml)
            if ! python3 -c "import xml.etree.ElementTree; xml.etree.ElementTree.parse('$INPUT')" 2>/dev/null; then
                echo -e "${YELLOW}Warning: File may not be valid XML${NC}"
            fi
            ;;
    esac
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--input)
            INPUT="$2"
            shift 2
            ;;
        --input-format)
            INPUT_FORMAT="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT="$2"
            shift 2
            ;;
        --output-format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --info)
            show_file_info
            exit 0
            ;;
        --validate)
            validate_file_format
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
check_input
validate_input_format
validate_output_format
check_dependencies

if [ "$VERBOSE" = true ]; then
    show_file_info
    validate_file_format
fi

run_parser
