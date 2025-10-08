"""
Output Parser Module

Provides parsing and data normalization capabilities:
- Parse scan results from various formats
- Normalize data structures
- Compare scan results
- Export to multiple formats
"""

import json
import csv
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class ParsedScanResult:
    """Normalized scan result structure."""
    host: str
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    banner: Optional[str] = None
    version: Optional[str] = None
    response_time: Optional[float] = None
    scan_type: Optional[str] = None
    timestamp: Optional[datetime] = None


@dataclass
class ScanMetadata:
    """Metadata about a scan."""
    scan_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration: Optional[float] = None
    target: Optional[str] = None
    scan_type: Optional[str] = None
    total_hosts: int = 0
    total_ports: int = 0
    open_ports: int = 0


class OutputParser:
    """Parse and normalize scan results from various formats."""
    
    def __init__(self):
        self.results: List[ParsedScanResult] = []
        self.metadata: Optional[ScanMetadata] = None
    
    def parse_json(self, json_data: Union[str, Dict]) -> List[ParsedScanResult]:
        """Parse JSON scan results."""
        if isinstance(json_data, str):
            data = json.loads(json_data)
        else:
            data = json_data
        
        results = []
        
        # Handle different JSON formats
        if isinstance(data, list):
            # Direct list of results
            for item in data:
                result = self._parse_json_item(item)
                if result:
                    results.append(result)
        elif isinstance(data, dict):
            # Structured format with metadata
            if "metadata" in data:
                self.metadata = self._parse_metadata(data["metadata"])
            
            if "results" in data:
                for item in data["results"]:
                    result = self._parse_json_item(item)
                    if result:
                        results.append(result)
            elif "hosts" in data:
                # Nmap-style format
                for host_data in data["hosts"]:
                    host = host_data.get("ip", "")
                    for port_data in host_data.get("ports", []):
                        result = self._parse_json_item(port_data, host)
                        if result:
                            results.append(result)
        
        self.results = results
        return results
    
    def _parse_json_item(self, item: Dict, host: Optional[str] = None) -> Optional[ParsedScanResult]:
        """Parse a single JSON item."""
        try:
            return ParsedScanResult(
                host=host or item.get("host", ""),
                port=int(item.get("port", 0)),
                protocol=item.get("protocol", "tcp"),
                state=item.get("state", "unknown"),
                service=item.get("service"),
                banner=item.get("banner"),
                version=item.get("version"),
                response_time=item.get("response_time"),
                scan_type=item.get("scan_type"),
                timestamp=self._parse_timestamp(item.get("timestamp"))
            )
        except (ValueError, KeyError) as e:
            logger.warning(f"Error parsing JSON item: {e}")
            return None
    
    def _parse_metadata(self, metadata: Dict) -> ScanMetadata:
        """Parse scan metadata."""
        return ScanMetadata(
            scan_id=metadata.get("scan_id", ""),
            start_time=self._parse_timestamp(metadata.get("start_time")),
            end_time=self._parse_timestamp(metadata.get("end_time")),
            duration=metadata.get("duration"),
            target=metadata.get("target"),
            scan_type=metadata.get("scan_type"),
            total_hosts=metadata.get("total_hosts", 0),
            total_ports=metadata.get("total_ports", 0),
            open_ports=metadata.get("open_ports", 0)
        )
    
    def _parse_timestamp(self, timestamp: Any) -> Optional[datetime]:
        """Parse timestamp from various formats."""
        if not timestamp:
            return None
        
        if isinstance(timestamp, datetime):
            return timestamp
        
        if isinstance(timestamp, str):
            # Try common timestamp formats
            formats = [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S"
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(timestamp, fmt)
                except ValueError:
                    continue
        
        return None
    
    def parse_csv(self, csv_data: str) -> List[ParsedScanResult]:
        """Parse CSV scan results."""
        results = []
        
        try:
            reader = csv.DictReader(csv_data.splitlines())
            for row in reader:
                result = ParsedScanResult(
                    host=row.get("host", ""),
                    port=int(row.get("port", 0)),
                    protocol=row.get("protocol", "tcp"),
                    state=row.get("state", "unknown"),
                    service=row.get("service") or None,
                    banner=row.get("banner") or None,
                    version=row.get("version") or None,
                    response_time=float(row.get("response_time", 0)) if row.get("response_time") else None,
                    scan_type=row.get("scan_type") or None,
                    timestamp=self._parse_timestamp(row.get("timestamp"))
                )
                results.append(result)
        except Exception as e:
            logger.error(f"Error parsing CSV: {e}")
        
        self.results = results
        return results
    
    def parse_nmap_xml(self, xml_data: str) -> List[ParsedScanResult]:
        """Parse Nmap XML output."""
        results = []
        
        try:
            root = ET.fromstring(xml_data)
            
            # Parse scan metadata
            scan_info = root.find("scaninfo")
            if scan_info is not None:
                self.metadata = ScanMetadata(
                    scan_id=root.get("scanner", ""),
                    start_time=self._parse_timestamp(root.get("startstr")),
                    scan_type=scan_info.get("type", ""),
                    total_hosts=len(root.findall("host"))
                )
            
            # Parse hosts
            for host in root.findall("host"):
                host_ip = host.find("address").get("addr") if host.find("address") is not None else ""
                
                # Get hostname
                hostname = None
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    hostname_elem = hostnames.find("hostname")
                    if hostname_elem is not None:
                        hostname = hostname_elem.get("name")
                
                # Parse ports
                ports = host.find("ports")
                if ports is not None:
                    for port in ports.findall("port"):
                        port_id = int(port.get("portid", 0))
                        protocol = port.get("protocol", "tcp")
                        
                        # Get port state
                        state = "closed"
                        state_elem = port.find("state")
                        if state_elem is not None:
                            state = state_elem.get("state", "closed")
                        
                        # Get service info
                        service = None
                        version = None
                        service_elem = port.find("service")
                        if service_elem is not None:
                            service = service_elem.get("name")
                            version = service_elem.get("version")
                        
                        # Get banner
                        banner = None
                        script_elem = port.find("script")
                        if script_elem is not None and script_elem.get("id") == "banner":
                            banner = script_elem.get("output")
                        
                        result = ParsedScanResult(
                            host=host_ip,
                            port=port_id,
                            protocol=protocol,
                            state=state,
                            service=service,
                            banner=banner,
                            version=version,
                            scan_type="nmap"
                        )
                        results.append(result)
        
        except ET.ParseError as e:
            logger.error(f"Error parsing XML: {e}")
        except Exception as e:
            logger.error(f"Error processing Nmap XML: {e}")
        
        self.results = results
        return results
    
    def parse_text(self, text_data: str) -> List[ParsedScanResult]:
        """Parse text-based scan results."""
        results = []
        lines = text_data.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Try to parse common text formats
            # Format: host:port/protocol state [service] [banner]
            parts = line.split()
            if len(parts) < 2:
                continue
            
            try:
                # Parse host:port/protocol
                host_port = parts[0]
                if ':' in host_port:
                    host, port_protocol = host_port.split(':', 1)
                    if '/' in port_protocol:
                        port, protocol = port_protocol.split('/', 1)
                    else:
                        port, protocol = port_protocol, "tcp"
                else:
                    continue
                
                state = parts[1]
                service = parts[2] if len(parts) > 2 else None
                banner = ' '.join(parts[3:]) if len(parts) > 3 else None
                
                result = ParsedScanResult(
                    host=host,
                    port=int(port),
                    protocol=protocol,
                    state=state,
                    service=service,
                    banner=banner
                )
                results.append(result)
                
            except (ValueError, IndexError) as e:
                logger.debug(f"Error parsing text line: {line} - {e}")
                continue
        
        self.results = results
        return results
    
    def export_json(self, include_metadata: bool = True) -> str:
        """Export results to JSON format."""
        output = {
            "results": [asdict(result) for result in self.results]
        }
        
        if include_metadata and self.metadata:
            output["metadata"] = asdict(self.metadata)
        
        # Convert any enum values to strings for JSON serialization
        def convert_enums_to_strings(obj):
            if isinstance(obj, dict):
                return {str(k): convert_enums_to_strings(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_enums_to_strings(item) for item in obj]
            elif hasattr(obj, 'value') and hasattr(obj, '__class__') and hasattr(obj.__class__, '__name__'):  # Enum objects
                return str(obj.value)
            elif hasattr(obj, '__class__') and 'Enum' in str(obj.__class__.__bases__):  # Additional enum check
                return str(obj.value)
            else:
                return obj
        
        output = convert_enums_to_strings(output)
        
        return json.dumps(output, indent=2, default=str)
    
    def export_csv(self) -> str:
        """Export results to CSV format."""
        if not self.results:
            return ""
        
        output = []
        fieldnames = ["host", "port", "protocol", "state", "service", "banner", "version", "response_time", "scan_type", "timestamp"]
        
        for result in self.results:
            row = {
                "host": result.host,
                "port": result.port,
                "protocol": result.protocol,
                "state": result.state,
                "service": result.service or "",
                "banner": result.banner or "",
                "version": result.version or "",
                "response_time": result.response_time or "",
                "scan_type": result.scan_type or "",
                "timestamp": result.timestamp.isoformat() if result.timestamp else ""
            }
            output.append(row)
        
        # Convert to CSV string
        import io
        csv_buffer = io.StringIO()
        writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output)
        
        return csv_buffer.getvalue()
    
    def export_nmap_xml(self) -> str:
        """Export results to Nmap XML format."""
        root = ET.Element("nmaprun")
        root.set("scanner", "gingerscan")
        root.set("args", "gingerscan scan")
        root.set("start", str(int(datetime.now().timestamp())))
        root.set("startstr", datetime.now().isoformat())
        root.set("version", "1.0")
        root.set("xmloutputversion", "1.04")
        
        # Add scan info
        scaninfo = ET.SubElement(root, "scaninfo")
        scaninfo.set("type", "syn")
        scaninfo.set("protocol", "tcp")
        scaninfo.set("numservices", str(len(self.results)))
        scaninfo.set("services", "1-65535")
        
        # Group results by host
        hosts = {}
        for result in self.results:
            if result.host not in hosts:
                hosts[result.host] = []
            hosts[result.host].append(result)
        
        # Add hosts
        for host_ip, host_results in hosts.items():
            host_elem = ET.SubElement(root, "host")
            host_elem.set("starttime", str(int(datetime.now().timestamp())))
            host_elem.set("endtime", str(int(datetime.now().timestamp())))
            
            # Add address
            address = ET.SubElement(host_elem, "address")
            address.set("addr", host_ip)
            address.set("addrtype", "ipv4")
            
            # Add ports
            ports = ET.SubElement(host_elem, "ports")
            for result in host_results:
                port_elem = ET.SubElement(ports, "port")
                port_elem.set("portid", str(result.port))
                port_elem.set("protocol", result.protocol)
                
                # Add state
                state = ET.SubElement(port_elem, "state")
                state.set("state", result.state)
                state.set("reason", "syn-ack")
                state.set("reason_ttl", "64")
                
                # Add service if available
                if result.service:
                    service = ET.SubElement(port_elem, "service")
                    service.set("name", result.service)
                    if result.version:
                        service.set("version", result.version)
                    if result.banner:
                        service.set("product", result.banner)
        
        return ET.tostring(root, encoding="unicode")
    
    def compare_scans(self, other_parser: 'OutputParser') -> Dict[str, Any]:
        """Compare two scan results and return differences."""
        current_ports = {(r.host, r.port, r.protocol): r for r in self.results}
        other_ports = {(r.host, r.port, r.protocol): r for r in other_parser.results}
        
        # Find differences
        new_ports = []
        closed_ports = []
        changed_ports = []
        
        # New ports
        for key, result in other_ports.items():
            if key not in current_ports:
                new_ports.append(result)
        
        # Closed ports
        for key, result in current_ports.items():
            if key not in other_ports:
                closed_ports.append(result)
        
        # Changed ports
        for key, current_result in current_ports.items():
            if key in other_ports:
                other_result = other_ports[key]
                if (current_result.state != other_result.state or 
                    current_result.service != other_result.service or
                    current_result.banner != other_result.banner):
                    changed_ports.append({
                        "host": current_result.host,
                        "port": current_result.port,
                        "protocol": current_result.protocol,
                        "old": current_result,
                        "new": other_result
                    })
        
        return {
            "new_ports": new_ports,
            "closed_ports": closed_ports,
            "changed_ports": changed_ports,
            "summary": {
                "new_count": len(new_ports),
                "closed_count": len(closed_ports),
                "changed_count": len(changed_ports)
            }
        }
    
    def get_open_ports(self) -> List[ParsedScanResult]:
        """Get only open ports from results."""
        return [r for r in self.results if r.state in ["open", "open|filtered"]]
    
    def get_ports_by_host(self) -> Dict[str, List[ParsedScanResult]]:
        """Group results by host."""
        grouped = {}
        for result in self.results:
            if result.host not in grouped:
                grouped[result.host] = []
            grouped[result.host].append(result)
        return grouped
    
    def get_service_summary(self) -> Dict[str, int]:
        """Get summary of services found."""
        services = {}
        for result in self.results:
            if result.service:
                services[result.service] = services.get(result.service, 0) + 1
        return services
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scan statistics."""
        total_ports = len(self.results)
        open_ports = len(self.get_open_ports())
        hosts = len(set(r.host for r in self.results))
        
        protocols = {}
        for result in self.results:
            protocols[result.protocol] = protocols.get(result.protocol, 0) + 1
        
        return {
            "total_ports": total_ports,
            "open_ports": open_ports,
            "closed_ports": total_ports - open_ports,
            "hosts": hosts,
            "protocols": protocols,
            "services": self.get_service_summary()
        }
