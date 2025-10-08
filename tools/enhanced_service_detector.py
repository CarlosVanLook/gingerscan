"""
Enhanced Service Detection Module

Provides comprehensive service detection using:
- Nmap integration
- Extended port-to-service mapping
- Banner analysis
- Protocol fingerprinting
"""

import asyncio
import subprocess
import json
import re
import socket
import ssl
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class ServiceInfo:
    """Enhanced service information."""
    name: str
    version: Optional[str] = None
    banner: Optional[str] = None
    confidence: float = 0.0
    method: str = "unknown"  # nmap, banner, port, protocol
    product: Optional[str] = None
    extra_info: Optional[str] = None

class EnhancedServiceDetector:
    """Enhanced service detection with Nmap integration."""
    
    def __init__(self, use_nmap: bool = True):
        self.use_nmap = use_nmap
        self.nmap_available = self._check_nmap_availability()
        self.extended_port_services = self._load_extended_port_services()
        self.service_patterns = self._load_service_patterns()
        
    def _check_nmap_availability(self) -> bool:
        """Check if Nmap is available on the system."""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            logger.warning("Nmap not available. Service detection will use limited methods.")
            return False
    
    def _load_extended_port_services(self) -> Dict[int, Dict]:
        """Load comprehensive port-to-service mapping."""
        return {
            # Common services
            21: {"name": "ftp", "description": "File Transfer Protocol"},
            22: {"name": "ssh", "description": "Secure Shell"},
            23: {"name": "telnet", "description": "Telnet"},
            25: {"name": "smtp", "description": "Simple Mail Transfer Protocol"},
            53: {"name": "dns", "description": "Domain Name System"},
            80: {"name": "http", "description": "Hypertext Transfer Protocol"},
            110: {"name": "pop3", "description": "Post Office Protocol v3"},
            143: {"name": "imap", "description": "Internet Message Access Protocol"},
            443: {"name": "https", "description": "HTTP Secure"},
            993: {"name": "imaps", "description": "IMAP over SSL"},
            995: {"name": "pop3s", "description": "POP3 over SSL"},
            1433: {"name": "mssql", "description": "Microsoft SQL Server"},
            3306: {"name": "mysql", "description": "MySQL Database"},
            3389: {"name": "rdp", "description": "Remote Desktop Protocol"},
            5432: {"name": "postgresql", "description": "PostgreSQL Database"},
            5900: {"name": "vnc", "description": "Virtual Network Computing"},
            6379: {"name": "redis", "description": "Redis Database"},
            8080: {"name": "http-alt", "description": "HTTP Alternative"},
            9200: {"name": "elasticsearch", "description": "Elasticsearch"},
            27017: {"name": "mongodb", "description": "MongoDB Database"},
            
            # Less common but important services
            69: {"name": "tftp", "description": "Trivial File Transfer Protocol"},
            135: {"name": "msrpc", "description": "Microsoft RPC"},
            139: {"name": "netbios-ssn", "description": "NetBIOS Session Service"},
            445: {"name": "microsoft-ds", "description": "Microsoft Directory Services"},
            993: {"name": "imaps", "description": "IMAP over SSL"},
            995: {"name": "pop3s", "description": "POP3 over SSL"},
            1723: {"name": "pptp", "description": "Point-to-Point Tunneling Protocol"},
            3389: {"name": "rdp", "description": "Remote Desktop Protocol"},
            5000: {"name": "upnp", "description": "Universal Plug and Play"},
            5060: {"name": "sip", "description": "Session Initiation Protocol"},
            5432: {"name": "postgresql", "description": "PostgreSQL Database"},
            5900: {"name": "vnc", "description": "Virtual Network Computing"},
            6000: {"name": "x11", "description": "X Window System"},
            6667: {"name": "irc", "description": "Internet Relay Chat"},
            8000: {"name": "http-alt", "description": "HTTP Alternative"},
            8443: {"name": "https-alt", "description": "HTTPS Alternative"},
            8888: {"name": "http-alt", "description": "HTTP Alternative"},
            9090: {"name": "http-alt", "description": "HTTP Alternative"},
            10000: {"name": "webmin", "description": "Webmin"},
            11211: {"name": "memcached", "description": "Memcached"},
            27017: {"name": "mongodb", "description": "MongoDB Database"},
            
            # Custom/Unknown ports (these will be investigated)
            711: {"name": "unknown", "description": "Unknown service - investigation needed"},
            982: {"name": "unknown", "description": "Unknown service - investigation needed"},
            1337: {"name": "unknown", "description": "Unknown service - investigation needed"},
            31337: {"name": "unknown", "description": "Unknown service - investigation needed"},
        }
    
    def _load_service_patterns(self) -> Dict[str, Dict]:
        """Load service identification patterns."""
        return {
            "ssh": {
                "pattern": r"SSH-(\d+\.\d+)",
                "ports": [22, 2222, 2200],
                "confidence": 0.9
            },
            "http": {
                "pattern": r"HTTP/(\d+\.\d+)",
                "ports": [80, 8080, 8000, 8008, 8888, 9090],
                "confidence": 0.8
            },
            "https": {
                "pattern": r"HTTP/(\d+\.\d+)",
                "ports": [443, 8443],
                "confidence": 0.8
            },
            "ftp": {
                "pattern": r"(\d{3}) (.*)",
                "ports": [21, 2121],
                "confidence": 0.9
            },
            "smtp": {
                "pattern": r"(\d{3}) (.*)",
                "ports": [25, 587, 465],
                "confidence": 0.8
            },
            "pop3": {
                "pattern": r"\+OK (.*)",
                "ports": [110, 995],
                "confidence": 0.9
            },
            "imap": {
                "pattern": r"\* OK (.*)",
                "ports": [143, 993],
                "confidence": 0.9
            },
            "telnet": {
                "pattern": r"(.+)",
                "ports": [23],
                "confidence": 0.7
            },
            "mysql": {
                "pattern": r"(\d+) (.*)",
                "ports": [3306],
                "confidence": 0.8
            },
            "postgresql": {
                "pattern": r"(\d+) (.*)",
                "ports": [5432],
                "confidence": 0.8
            },
            "redis": {
                "pattern": r"ERR (.*)",
                "ports": [6379],
                "confidence": 0.9
            },
            "elasticsearch": {
                "pattern": r'"version":\s*{"number":\s*"([^"]+)"',
                "ports": [9200, 9300],
                "confidence": 0.9
            },
            "mongodb": {
                "pattern": r"(\d+\.\d+\.\d+)",
                "ports": [27017, 27018, 27019],
                "confidence": 0.8
            },
            "rdp": {
                "pattern": r"(\d+\.\d+\.\d+\.\d+)",
                "ports": [3389],
                "confidence": 0.7
            },
            "vnc": {
                "pattern": r"RFB (\d+\.\d+)",
                "ports": [5900, 5901, 5902],
                "confidence": 0.9
            },
            "sip": {
                "pattern": r"SIP/(\d+\.\d+)",
                "ports": [5060, 5061],
                "confidence": 0.8
            },
            "irc": {
                "pattern": r":([^\s]+) (\d{3})",
                "ports": [6667, 6668, 6669],
                "confidence": 0.8
            }
        }
    
    async def detect_service_nmap(self, host: str, port: int) -> Optional[ServiceInfo]:
        """Use Nmap to detect service information."""
        if not self.nmap_available or not self.use_nmap:
            return None
        
        try:
            # Run nmap with service detection
            cmd = [
                'nmap', '-sV', '-sC', '--script=version',
                '--max-retries=1', '--host-timeout=30s',
                '-p', str(port), host
            ]
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                result.communicate(), timeout=60
            )
            
            if result.returncode != 0:
                logger.debug(f"Nmap failed for {host}:{port}: {stderr.decode()}")
                return None
            
            output = stdout.decode()
            return self._parse_nmap_output(output, host, port)
            
        except asyncio.TimeoutError:
            logger.debug(f"Nmap timeout for {host}:{port}")
            return None
        except Exception as e:
            logger.debug(f"Nmap error for {host}:{port}: {e}")
            return None
    
    def _parse_nmap_output(self, output: str, host: str, port: int) -> Optional[ServiceInfo]:
        """Parse Nmap output to extract service information."""
        lines = output.split('\n')
        
        for line in lines:
            if f"{port}/tcp" in line and "open" in line:
                # Parse line like: "80/tcp open  http    Apache httpd 2.4.41"
                parts = line.split()
                if len(parts) >= 4:
                    service_name = parts[2]
                    version = " ".join(parts[3:]) if len(parts) > 3 else None
                    
                    # Extract product and version
                    product = None
                    version_info = None
                    if version:
                        # Try to extract product and version
                        version_parts = version.split()
                        if len(version_parts) >= 2:
                            product = version_parts[0]
                            version_info = " ".join(version_parts[1:])
                        else:
                            product = version
                    
                    return ServiceInfo(
                        name=service_name,
                        version=version_info,
                        product=product,
                        confidence=0.9,
                        method="nmap",
                        extra_info=version
                    )
        
        return None
    
    async def detect_service_banner(self, host: str, port: int) -> Optional[ServiceInfo]:
        """Detect service using banner grabbing."""
        try:
            # Try to connect and grab banner
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=5.0)
            
            # Try to read banner
            banner = ""
            try:
                # Wait for banner with timeout
                banner = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                if banner:
                    banner = banner.decode('utf-8', errors='ignore').strip()
            except asyncio.TimeoutError:
                # No banner received, but connection successful
                pass
            except Exception:
                pass
            
            writer.close()
            await writer.wait_closed()
            
            if banner:
                return self._identify_service_from_banner(banner, port)
            else:
                # Connection successful but no banner
                return self._identify_service_from_port(port, "Connection successful")
            
        except asyncio.TimeoutError:
            logger.debug(f"Banner grab timeout for {host}:{port}")
            return None
        except Exception as e:
            logger.debug(f"Banner grab failed for {host}:{port}: {e}")
            return None
    
    def _identify_service_from_banner(self, banner: str, port: int) -> Optional[ServiceInfo]:
        """Identify service from banner text."""
        banner_lower = banner.lower()
        
        # Check patterns
        for service_name, service_info in self.service_patterns.items():
            if port not in service_info["ports"]:
                continue
            
            pattern = service_info["pattern"]
            match = re.search(pattern, banner, re.IGNORECASE)
            
            if match:
                confidence = service_info["confidence"]
                version = match.group(1) if match.groups() else None
                
                return ServiceInfo(
                    name=service_name,
                    version=version,
                    banner=banner,
                    confidence=confidence,
                    method="banner"
                )
        
        # Try to identify from banner content
        if "ssh" in banner_lower:
            return ServiceInfo(name="ssh", banner=banner, confidence=0.8, method="banner")
        elif "http" in banner_lower:
            return ServiceInfo(name="http", banner=banner, confidence=0.7, method="banner")
        elif "ftp" in banner_lower:
            return ServiceInfo(name="ftp", banner=banner, confidence=0.7, method="banner")
        elif "smtp" in banner_lower:
            return ServiceInfo(name="smtp", banner=banner, confidence=0.7, method="banner")
        
        return None
    
    def _identify_service_from_port(self, port: int, banner: str = None) -> Optional[ServiceInfo]:
        """Identify service from port number."""
        service_info = self.extended_port_services.get(port)
        if service_info:
            confidence = 0.6 if service_info["name"] == "unknown" else 0.7
            
            return ServiceInfo(
                name=service_info["name"],
                banner=banner,
                confidence=confidence,
                method="port",
                extra_info=service_info["description"]
            )
        
        return None
    
    async def detect_service_comprehensive(self, host: str, port: int) -> ServiceInfo:
        """Comprehensive service detection using multiple methods."""
        # Try Nmap first (most accurate)
        if self.nmap_available and self.use_nmap:
            nmap_result = await self.detect_service_nmap(host, port)
            if nmap_result and nmap_result.confidence >= 0.8:
                return nmap_result
        
        # Try banner grabbing
        banner_result = await self.detect_service_banner(host, port)
        if banner_result and banner_result.confidence >= 0.7:
            return banner_result
        
        # Fallback to port-based identification
        port_result = self._identify_service_from_port(port)
        if port_result:
            return port_result
        
        # Return unknown service
        return ServiceInfo(
            name="unknown",
            confidence=0.1,
            method="none",
            extra_info=f"Port {port} - no service detected"
        )
    
    async def detect_services_batch(self, host: str, ports: List[int]) -> Dict[int, ServiceInfo]:
        """Detect services for multiple ports efficiently."""
        results = {}
        
        # Use Nmap for batch detection if available
        if self.nmap_available and self.use_nmap:
            try:
                port_list = ",".join(map(str, ports))
                cmd = [
                    'nmap', '-sV', '-sC', '--script=version',
                    '--max-retries=1', '--host-timeout=60s',
                    '-p', port_list, host
                ]
                
                result = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    result.communicate(), timeout=120
                )
                
                if result.returncode == 0:
                    output = stdout.decode()
                    for port in ports:
                        service_info = self._parse_nmap_output(output, host, port)
                        if service_info:
                            results[port] = service_info
                
            except Exception as e:
                logger.debug(f"Batch Nmap detection failed: {e}")
        
        # Fill in missing ports with individual detection
        for port in ports:
            if port not in results:
                results[port] = await self.detect_service_comprehensive(host, port)
        
        return results
