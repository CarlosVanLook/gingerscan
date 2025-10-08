"""
Port Scanner Module

Provides async port scanning capabilities including:
- TCP connect scanning
- TCP SYN scanning (using Scapy)
- UDP scanning
- Rate limiting and throttling
- Custom port ranges
"""

import asyncio
import socket
import time
from typing import List, Dict, Optional, Union, Tuple
from dataclasses import dataclass
from enum import Enum
import ipaddress
import logging

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available. SYN scanning will be disabled.")

from .banner_grabber import BannerGrabber
from .discover import HostDiscovery
from .os_detection import OSDetector, OSInfo, OSFamily
from .ip_info import create_ip_info_gatherer, IPInfo
from .comprehensive_service_detector import ComprehensiveServiceDetector
from .parser import ParsedScanResult
from .vuln_checks import VulnerabilityChecker, VulnCheckConfig

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ScanType(Enum):
    """Types of port scans available."""
    TCP_CONNECT = "tcp_connect"
    TCP_SYN = "tcp_syn"
    UDP = "udp"


@dataclass
class ScanResult:
    """Result of a port scan."""
    host: str
    port: int
    protocol: str
    state: str  # open, closed, filtered, open|filtered
    service: Optional[str] = None
    banner: Optional[str] = None
    version: Optional[str] = None
    response_time: Optional[float] = None
    scan_type: Optional[ScanType] = None


@dataclass
class ScanConfig:
    """Configuration for port scanning."""
    targets: List[str]
    ports: List[Union[int, Tuple[int, int]]]
    scan_type: ScanType = ScanType.TCP_CONNECT
    timeout: float = 3.0
    rate_limit: int = 100  # ports per second
    threads: int = 50
    banner_grab: bool = False
    host_discovery: bool = False
    os_detection: bool = False
    ip_info: bool = False
    vuln_check: bool = False
    verbose: bool = False


class PortScanner:
    """Async port scanner with multiple scan types and rate limiting."""
    
    def __init__(self, config: ScanConfig, progress_callback=None):
        self.config = config
        self.results: List[ScanResult] = []
        self.banner_grabber = BannerGrabber() if config.banner_grab else None
        self.host_discovery = HostDiscovery() if config.host_discovery else None
        self.os_detector = OSDetector(timeout=config.timeout) if config.os_detection else None
        self.ip_info_gatherer = create_ip_info_gatherer(timeout=config.timeout) if config.ip_info else None
        self.comprehensive_service_detector = ComprehensiveServiceDetector(use_nmap=True, timeout=config.timeout)
        self._semaphore = asyncio.Semaphore(config.threads)
        self._rate_limiter = asyncio.Semaphore(config.rate_limit)
        self.progress_callback = progress_callback
        self.os_info: Dict[str, OSInfo] = {}  # Store OS detection results per host
        self.ip_info: Dict[str, IPInfo] = {}  # Store IP information per host
        self._cancelled = False  # Cancellation flag
    
    def cancel(self):
        """Cancel the current scan."""
        self._cancelled = True
        logger.info("Scan cancellation requested")
        
        # Also cancel OS detection if it's running
        if self.os_detector:
            self.os_detector.cancel()
        
    async def scan(self) -> List[ScanResult]:
        """Perform the port scan based on configuration."""
        logger.info(f"Starting {self.config.scan_type.value} scan on {len(self.config.targets)} targets")
        
        # Start from 0% with very gradual increments
        if self.progress_callback:
            await self.progress_callback(0.0, "running", "Initializing scan...")
        
        # Check for cancellation
        if self._cancelled:
            logger.info("Scan cancelled during initialization")
            return []
        
        # Phase 1: Host discovery (0-15%) with micro-steps
        if self.config.host_discovery:
            if self.progress_callback:
                await self.progress_callback(1.0, "running", "Starting host discovery...")
            
            if self.progress_callback:
                await self.progress_callback(3.0, "running", "Preparing host discovery...")
            
            logger.info("Performing host discovery...")
            
            # Simulate gradual progress during host discovery
            if self.progress_callback:
                await self.progress_callback(6.0, "running", "ICMP ping sweep...")
                
            if self.progress_callback:
                await self.progress_callback(9.0, "running", "ARP scanning...")
                
            # Check for cancellation before host discovery
            if self._cancelled:
                logger.info("Scan cancelled before host discovery")
                return []
                
            alive_hosts = await self.host_discovery.discover_hosts(self.config.targets)
            
            # Check for cancellation after host discovery
            if self._cancelled:
                logger.info("Scan cancelled after host discovery")
                return []
            
            if self.progress_callback:
                await self.progress_callback(12.0, "running", "DNS resolution...")
                await asyncio.sleep(0.2)
            
            if self.progress_callback:
                await self.progress_callback(14.0, "running", "Analyzing discovered hosts...")
                await asyncio.sleep(0.2)
            
            self.config.targets = alive_hosts
            logger.info(f"Found {len(alive_hosts)} alive hosts")
            
            if self.progress_callback:
                await self.progress_callback(15.0, "running", f"Host discovery completed - {len(alive_hosts)} hosts found")
        else:
            # Even when skipping, provide gradual updates
            if self.progress_callback:
                await self.progress_callback(1.0, "running", "Preparing scan targets...")
                await self.progress_callback(5.0, "running", "Skipping host discovery...")
                await self.progress_callback(10.0, "running", "Validating targets...")
                await self.progress_callback(15.0, "running", "Using provided targets")
        
        if not self.config.targets:
            if self.progress_callback:
                await self.progress_callback(100.0, "completed", "No alive hosts found")
            return []
        
        # Phase 2: OS Detection (15-25%)
        if self.config.os_detection and self.os_detector:
            if self.progress_callback:
                await self.progress_callback(16.0, "running", "Starting OS detection...")
            
            logger.info("Performing OS detection...")
            
            # Perform OS detection for each target host
            for i, host in enumerate(self.config.targets):
                # Check for cancellation before each OS detection
                if self._cancelled:
                    logger.info("Scan cancelled during OS detection")
                    return []
                    
                if self.progress_callback:
                    progress = 16.0 + (i / len(self.config.targets)) * 8.0
                    await self.progress_callback(progress, "running", f"Detecting OS for {host}...")
                
                try:
                    # OS detection doesn't need open ports, it can work with TTL analysis
                    os_info = await self.os_detector.detect_os(host, None)
                    self.os_info[host] = os_info
                    logger.info(f"OS detection for {host}: {os_info.family.value} (confidence: {os_info.confidence:.2f})")
                    
                    # Add a small delay to make the phase visible
                    await asyncio.sleep(0.5)
                except Exception as e:
                    logger.error(f"OS detection failed for {host}: {e}")
                    self.os_info[host] = OSInfo(family=OSFamily.UNKNOWN, confidence=0.0, method="error")
            
            if self.progress_callback:
                await self.progress_callback(24.0, "running", "OS detection completed")
        else:
            if self.progress_callback:
                await self.progress_callback(16.0, "running", "Skipping OS detection...")
                await self.progress_callback(24.0, "running", "OS detection disabled")

        # Phase 2.5: IP Information Gathering (24-30%)
        if self.config.ip_info and self.ip_info_gatherer:
            if self.progress_callback:
                await self.progress_callback(25.0, "running", "Starting IP information gathering...")
            
            logger.info("Performing IP information gathering...")
            
            # Gather IP information for each target host
            async with self.ip_info_gatherer as gatherer:
                for i, host in enumerate(self.config.targets):
                    # Check for cancellation before each IP info gathering
                    if self._cancelled:
                        logger.info("Scan cancelled during IP info gathering")
                        return []
                        
                    if self.progress_callback:
                        progress = 25.0 + (i / len(self.config.targets)) * 5.0
                        await self.progress_callback(progress, "running", f"Gathering IP info for {host}...")
                    
                    try:
                        ip_info = await gatherer.gather_info(host)
                        self.ip_info[host] = ip_info
                        logger.info(f"IP info for {host}: {ip_info.hostname or 'No hostname'} ({ip_info.country_name or 'Unknown country'})")
                        
                        # Add a small delay to make the phase visible
                        await asyncio.sleep(0.3)
                    except Exception as e:
                        logger.error(f"IP info gathering failed for {host}: {e}")
                        # Create a basic IP info object
                        self.ip_info[host] = IPInfo(ip=host, organization="Unknown", isp="Unknown")
            
            if self.progress_callback:
                await self.progress_callback(30.0, "running", "IP information gathering completed")
        else:
            if self.progress_callback:
                await self.progress_callback(25.0, "running", "Skipping IP information gathering...")
                await self.progress_callback(30.0, "running", "IP information gathering disabled")

        # Check for cancellation before port scanning
        if self._cancelled:
            logger.info("Scan cancelled before port scanning")
            return []
            
        # Phase 3: Port scanning (30-75%)
        if self.progress_callback:
            await self.progress_callback(30.0, "running", f"Preparing port scan for {len(self.config.targets)} hosts...")
            
        # Generate all scan tasks (as asyncio Tasks so they can be cancelled/awaited)
        tasks = []
        for target in self.config.targets:
            for port in self._expand_ports(self.config.ports):
                task = asyncio.create_task(self._scan_port(target, port))
                tasks.append(task)
        
        if self.progress_callback:
            await self.progress_callback(31.0, "running", f"Generated {len(tasks)} scan tasks...")
        
        # Execute scans with rate limiting and progress updates
        start_time = time.time()
        total_tasks = len(tasks)
        completed_tasks = 0
        
        if self.progress_callback:
            await self.progress_callback(32.0, "running", f"Starting port scan - {total_tasks} ports to check...")
        
        # Process tasks in very small batches for ultra-smooth progress
        batch_size = max(1, min(10, total_tasks // 20))  # More frequent updates with smaller batches
        results = []
        
        cancelled_early = False
        for i in range(0, len(tasks), batch_size):
            # Check for cancellation before each batch
            if self._cancelled:
                logger.info("Scan cancelled during port scanning")
                cancelled_early = True
                break
            
            batch = tasks[i:i + batch_size]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            results.extend(batch_results)
            
            # Store partial results immediately for stop functionality
            self.results = [r for r in results if isinstance(r, ScanResult)]
            
            completed_tasks += len(batch)
            # Ultra-smooth progress from 32% to 75% (43% range for port scanning)
            progress = 32.0 + (completed_tasks / total_tasks) * 43.0
            if self.progress_callback:
                percentage = int((completed_tasks / total_tasks) * 100)
                
                # Show just the current phase
                await self.progress_callback(progress, "running", f"Port scanning... {percentage}% ({completed_tasks}/{total_tasks})")
                # Small delay to ensure progress updates are processed
                await asyncio.sleep(0.01)
        
        self.results = results

        # If cancelled early, cancel any remaining pending tasks and await them to avoid warnings
        if cancelled_early:
            pending = [t for t in tasks if not t.done()]
            for t in pending:
                t.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            # Return partial results collected so far
            return self.results
        
        # Filter out exceptions and None results
        self.results = [r for r in self.results if isinstance(r, ScanResult)]
        
        # Check for cancellation before banner grabbing
        if self._cancelled:
            logger.info("Scan cancelled before banner grabbing")
            return self.results
            
        # If cancelled before service detection, return immediately
        if self._cancelled:
            logger.info("Scan cancelled before service detection phase")
            return self.results

        # Phase 4: Enhanced Service Detection (75-90%)
        if self.results:
            open_ports = [r for r in self.results if r.state == "open"]
            total_services = len(open_ports)
            
            if self.progress_callback:
                await self.progress_callback(77.0, "running", f"Starting enhanced service detection for {total_services} open ports...")
                
            if total_services > 0:
                # Group ports by host for efficient batch detection
                ports_by_host = {}
                for result in open_ports:
                    if result.host not in ports_by_host:
                        ports_by_host[result.host] = []
                    ports_by_host[result.host].append(result)
                
                processed = 0
                for host, host_ports in ports_by_host.items():
                    # Check for cancellation
                    if self._cancelled:
                        logger.info("Scan cancelled during service detection")
                        break
                    
                    try:
                        # Use comprehensive service detector for batch detection
                        port_numbers = [r.port for r in host_ports]
                        if self._cancelled:
                            break
                        service_results = await self.comprehensive_service_detector.detect_services_batch(
                            host, port_numbers, cancelled=lambda: self._cancelled
                        )
                        
                        # Update results with service information
                        for result in host_ports:
                            if result.port in service_results:
                                service_info = service_results[result.port]
                                result.service = service_info.name
                                result.version = service_info.version
                                result.banner = service_info.banner
                                
                                # Log interesting findings
                                if service_info.name == "unknown" and service_info.confidence < 0.5:
                                    logger.info(f"Unknown service detected on {host}:{result.port} - {service_info.extra_info}")
                                elif service_info.method == "nmap":
                                    logger.info(f"Nmap detected {service_info.name} on {host}:{result.port} (confidence: {service_info.confidence})")
                        
                        processed += len(host_ports)
                        
                        # Update progress
                        if processed % max(1, total_services // 10) == 0 or processed == total_services:
                            progress = 77.0 + (processed / total_services) * 13.0  # 77% to 90%
                            percentage = int((processed / total_services) * 100)
                            if self.progress_callback:
                                await self.progress_callback(progress, "running", f"Service detection... {percentage}% ({processed}/{total_services})")
                                
                    except Exception as e:
                        logger.error(f"Service detection failed for {host}: {e}")
                        # Fallback to basic banner grabbing
                        for result in host_ports:
                            if self.banner_grabber:
                                banner = await self.banner_grabber.grab_banner(result.host, result.port, result.protocol)
                                result.banner = banner
                                service_info = self.banner_grabber.identify_service(banner, result.port)
                                if service_info:
                                    result.service = service_info.name
                                    result.version = service_info.version
            else:
                if self.progress_callback:
                    await self.progress_callback(90.0, "running", "No open ports for service detection")
        else:
            if self.progress_callback:
                await self.progress_callback(80.0, "running", "Skipping service detection...")
                await self.progress_callback(90.0, "running", "Service detection disabled")
        
        duration = time.time() - start_time
        
        # Count total ports scanned
        expanded_ports = self._expand_ports(self.config.ports)
        total_ports_scanned = len(expanded_ports) * len(self.config.targets)
        open_ports = [r for r in self.results if r.state == "open"]
        closed_ports = [r for r in self.results if r.state in ["closed", "filtered"]]
        
        logger.info(f"Scan completed in {duration:.2f}s. Scanned {total_ports_scanned} ports, found {len(open_ports)} open ports and {len(closed_ports)} closed/filtered ports")
        
        if self.progress_callback:
            # Show completion message
            await self.progress_callback(95.0, "running", f"Scan completed - {len(open_ports)} open ports found out of {total_ports_scanned} scanned")
        
        return self.results
    
    def _expand_ports(self, ports: List[Union[int, Tuple[int, int]]]) -> List[int]:
        """Expand port ranges into individual ports."""
        expanded = []
        for port in ports:
            if isinstance(port, int):
                expanded.append(port)
            elif isinstance(port, tuple) and len(port) == 2:
                start, end = port
                expanded.extend(range(start, end + 1))
        return expanded
    
    async def _scan_port(self, host: str, port: int) -> Optional[ScanResult]:
        """Scan a single port with rate limiting."""
        async with self._semaphore:
            async with self._rate_limiter:
                try:
                    # Respect cancellation before starting
                    if self._cancelled:
                        return None
                    result = None
                    if self.config.scan_type == ScanType.TCP_CONNECT:
                        result = await self._tcp_connect_scan(host, port)
                    elif self.config.scan_type == ScanType.TCP_SYN:
                        result = await self._tcp_syn_scan(host, port)
                    elif self.config.scan_type == ScanType.UDP:
                        result = await self._udp_scan(host, port)
                    # Check for cancellation after scan
                    if self._cancelled:
                        return None
                    return result
                except asyncio.CancelledError:
                    # Task was cancelled; exit quietly
                    return None
                except Exception as e:
                    if self.config.verbose:
                        logger.debug(f"Error scanning {host}:{port} - {e}")
                    return None
    
    async def _tcp_connect_scan(self, host: str, port: int) -> Optional[ScanResult]:
        """Perform TCP connect scan."""
        try:
            if self._cancelled:
                return None
            # Create connection with timeout
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=self.config.timeout)
            if self._cancelled:
                writer.close()
                await writer.wait_closed()
                return None
            # Connection successful - port is open
            writer.close()
            await writer.wait_closed()
            if self._cancelled:
                return None
            result = ScanResult(
                host=host,
                port=port,
                protocol="tcp",
                state="open",
                scan_type=ScanType.TCP_CONNECT
            )
            # Comprehensive service detection (skip if cancelled)
            if not self._cancelled:
                try:
                    service_info = await self.comprehensive_service_detector.detect_service_comprehensive(host, port, cancelled=lambda: self._cancelled)
                    if self._cancelled:
                        return result
                    result.service = service_info.name
                    result.version = service_info.version
                    result.banner = service_info.banner
                except asyncio.CancelledError:
                    return result
                except Exception as e:
                    logger.debug(f"Enhanced service detection failed for {host}:{port}: {e}")
                    # Fallback to basic banner grabbing
                    if self.banner_grabber and not self._cancelled:
                        banner = await self.banner_grabber.grab_banner(host, port, "tcp")
                        result.banner = banner
                        service_info = self.banner_grabber.identify_service(banner, port)
                        if service_info:
                            result.service = service_info.name
                            result.version = service_info.version
            return result
        except asyncio.TimeoutError:
            return ScanResult(host, port, "tcp", "filtered", scan_type=ScanType.TCP_CONNECT)
        except ConnectionRefusedError:
            return ScanResult(host, port, "tcp", "closed", scan_type=ScanType.TCP_CONNECT)
        except Exception:
            return ScanResult(host, port, "tcp", "filtered", scan_type=ScanType.TCP_CONNECT)
    
    async def _tcp_syn_scan(self, host: str, port: int) -> Optional[ScanResult]:
        """Perform TCP SYN scan using Scapy."""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available, falling back to TCP connect scan")
            return await self._tcp_connect_scan(host, port)
        
        try:
            if self._cancelled:
                return None
            # Validate IP address before creating packet
            try:
                ipaddress.ip_address(host)
            except ValueError:
                logger.warning(f"Invalid IP address for SYN scan: {host}")
                return await self._tcp_connect_scan(host, port)
            
            # Create SYN packet
            packet = IP(dst=host) / TCP(dport=port, flags="S")
            
            # Send packet and wait for response
            response = await asyncio.get_event_loop().run_in_executor(
                None, 
                lambda: sr1(packet, timeout=self.config.timeout, verbose=0)
            )
            if self._cancelled:
                return None
            if response is None:
                return ScanResult(host, port, "tcp", "filtered", scan_type=ScanType.TCP_SYN)
            
            # Check TCP flags
            if response.haslayer(TCP):
                tcp_layer = response[TCP]
                if tcp_layer.flags & 0x12:  # SYN-ACK
                    return ScanResult(host, port, "tcp", "open", scan_type=ScanType.TCP_SYN)
                elif tcp_layer.flags & 0x04:  # RST
                    return ScanResult(host, port, "tcp", "closed", scan_type=ScanType.TCP_SYN)
            
            return ScanResult(host, port, "tcp", "filtered", scan_type=ScanType.TCP_SYN)
            
        except Exception as e:
            if self.config.verbose:
                logger.debug(f"TCP SYN scan error for {host}:{port} - {e}")
            return ScanResult(host, port, "tcp", "filtered", scan_type=ScanType.TCP_SYN)
    
    async def _udp_scan(self, host: str, port: int) -> Optional[ScanResult]:
        """Perform UDP scan."""
        try:
            if self._cancelled:
                return None
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.config.timeout)
            
            # Send empty UDP packet
            sock.sendto(b"", (host, port))
            if self._cancelled:
                sock.close()
                return None
            try:
                # Try to receive response
                data, addr = sock.recvfrom(1024)
                sock.close()
                return ScanResult(host, port, "udp", "open", scan_type=ScanType.UDP)
            except socket.timeout:
                # No response - could be open or filtered
                sock.close()
                return ScanResult(host, port, "udp", "open|filtered", scan_type=ScanType.UDP)
                
        except Exception as e:
            if self.config.verbose:
                logger.debug(f"UDP scan error for {host}:{port} - {e}")
            return ScanResult(host, port, "udp", "filtered", scan_type=ScanType.UDP)
    
    def get_open_ports(self) -> List[ScanResult]:
        """Get only open ports from scan results."""
        return [r for r in self.results if r.state in ["open", "open|filtered"]]
    
    def get_ports_by_host(self) -> Dict[str, List[ScanResult]]:
        """Group scan results by host."""
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


# CLI interface
async def main():
    """Main function for CLI usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Port Scanner")
    parser.add_argument("--target", "-t", required=True, help="Target host or network")
    parser.add_argument("--ports", "-p", default="1-1000", help="Port range or list (e.g., 1-1000, 22,80,443)")
    parser.add_argument("--scan-type", "-s", choices=["tcp_connect", "tcp_syn", "udp"], 
                       default="tcp_connect", help="Type of scan to perform")
    parser.add_argument("--timeout", default=3.0, type=float, help="Connection timeout")
    parser.add_argument("--rate-limit", default=100, type=int, help="Ports per second")
    parser.add_argument("--threads", default=50, type=int, help="Number of concurrent threads")
    parser.add_argument("--banner", action="store_true", help="Enable banner grabbing")
    parser.add_argument("--discover", action="store_true", help="Enable host discovery")
    parser.add_argument("--os-detection", action="store_true", help="Enable OS detection heuristics")
    parser.add_argument("--ip-info", action="store_true", help="Gather IP information (ASN/Geo/ISP)")
    parser.add_argument("--vuln-check", action="store_true", help="Run vulnerability checks on open ports")
    parser.add_argument("--all", action="store_true", help="Enable all features: discover, banner, OS detection, IP info, vuln checks")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--output", "-o", help="Output file")
    parser.add_argument("--format", choices=["json", "csv", "txt", "xml"], 
                       default="txt", help="Output format")
    
    args = parser.parse_args()

    # If --all is set, enable all feature flags
    if getattr(args, "all", False):
        args.banner = True
        args.discover = True
        args.os_detection = True
        args.ip_info = True
        args.vuln_check = True
    
    # Parse ports
    ports = []
    for port_str in args.ports.split(","):
        if "-" in port_str:
            start, end = map(int, port_str.split("-"))
            ports.append((start, end))
        else:
            ports.append(int(port_str))
    
    # Create configuration
    config = ScanConfig(
        targets=[args.target],
        ports=ports,
        scan_type=ScanType(args.scan_type),
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        threads=args.threads,
        banner_grab=args.banner,
        host_discovery=args.discover,
        os_detection=getattr(args, "os_detection", False),
        ip_info=getattr(args, "ip_info", False),
        vuln_check=getattr(args, "vuln_check", False),
        verbose=args.verbose
    )
    
    # Run scan
    scanner = PortScanner(config)
    results = await scanner.scan()
    
    # Output results
    if args.format == "json":
        import json
        output = json.dumps([r.__dict__ for r in results], indent=2)
    elif args.format == "csv":
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["host", "port", "protocol", "state", "service", "banner"])
        for r in results:
            writer.writerow([r.host, r.port, r.protocol, r.state, r.service or "", r.banner or ""])
        output = output.getvalue()
    else:
        # Default text format
        output = f"Scan Results ({len(results)} ports found):\n"
        for r in results:
            service_info = f" ({r.service})" if r.service else ""
            banner_info = f" - {r.banner}" if r.banner else ""
            output += f"{r.host}:{r.port}/{r.protocol} {r.state}{service_info}{banner_info}\n"
    
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Results saved to {args.output}")
    else:
        print(output)

    # Vulnerability checks (run after printing basic results)
    if getattr(args, "vuln_check", False):
        # Convert to ParsedScanResult list
        parsed_results = [
            ParsedScanResult(
                host=r.host,
                port=r.port,
                protocol=r.protocol,
                state=r.state,
                service=r.service,
                banner=r.banner,
                version=r.version,
                response_time=r.response_time,
                scan_type=r.scan_type.value if r.scan_type else None,
            )
            for r in results
        ]

        # Configure vuln checker (Shodan disabled unless configured elsewhere)
        vc_config = VulnCheckConfig(
            check_anonymous_ftp=True,
            check_default_credentials=True,
            check_ssl_certificates=True,
            check_http_headers=True,
            shodan_enabled=False,
            timeout=config.timeout,
            max_workers=10,
        )
        checker = VulnerabilityChecker(config=vc_config)
        vulns = await checker.check_vulnerabilities(parsed_results)

        if vulns:
            print(f"Vulnerabilities found: {len(vulns)}")
            for v in vulns[:50]:
                print(f"- {v.host}:{v.port}/{v.service} [{v.severity}] {v.vuln_type}: {v.description}")
            if len(vulns) > 50:
                print(f"... and {len(vulns) - 50} more")
        else:
            print("No vulnerabilities found.")


if __name__ == "__main__":
    asyncio.run(main())
