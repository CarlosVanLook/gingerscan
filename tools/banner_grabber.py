"""
Banner Grabbing Module

Provides service detection and banner grabbing capabilities:
- Service identification from banners
- TLS/SSL certificate analysis
- Common service detection (HTTP, SSH, FTP, etc.)
- Custom service patterns
"""

import asyncio
import socket
import ssl
import re
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class ServiceInfo:
    """Information about a detected service."""
    name: str
    version: Optional[str] = None
    banner: Optional[str] = None
    ssl_info: Optional[Dict] = None
    confidence: float = 0.0


@dataclass
class SSLInfo:
    """SSL/TLS certificate information."""
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    serial_number: str
    cipher_suite: str
    is_valid: bool


class BannerGrabber:
    """Service banner grabbing and identification."""
    
    def __init__(self):
        self.service_patterns = self._load_service_patterns()
        self.ssl_ports = {443, 993, 995, 465, 587, 636, 990, 992, 994, 989, 990}
    
    def _load_service_patterns(self) -> Dict[str, Dict]:
        """Load service identification patterns."""
        return {
            "ssh": {
                "pattern": r"SSH-(\d+\.\d+)",
                "ports": [22, 2222],
                "confidence": 0.9
            },
            "http": {
                "pattern": r"HTTP/(\d+\.\d+)",
                "ports": [80, 8080, 8000, 8008, 8888],
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
            "mongodb": {
                "pattern": r"(\d+) (.*)",
                "ports": [27017],
                "confidence": 0.8
            },
            "elasticsearch": {
                "pattern": r"(\d+) (.*)",
                "ports": [9200, 9300],
                "confidence": 0.8
            },
            "memcached": {
                "pattern": r"ERROR",
                "ports": [11211],
                "confidence": 0.9
            },
            "vnc": {
                "pattern": r"RFB (\d+\.\d+)",
                "ports": [5900, 5901, 5902],
                "confidence": 0.9
            },
            "rdp": {
                "pattern": r"(\d+) (.*)",
                "ports": [3389],
                "confidence": 0.8
            }
        }
    
    async def grab_banner(self, host: str, port: int, protocol: str = "tcp") -> Optional[str]:
        """Grab banner from a service."""
        try:
            if protocol.lower() == "tcp":
                return await self._grab_tcp_banner(host, port)
            elif protocol.lower() == "udp":
                return await self._grab_udp_banner(host, port)
        except Exception as e:
            logger.debug(f"Error grabbing banner from {host}:{port} - {e}")
            return None
    
    async def _grab_tcp_banner(self, host: str, port: int) -> Optional[str]:
        """Grab TCP banner."""
        try:
            # Check if it's an SSL port
            if port in self.ssl_ports:
                return await self._grab_ssl_banner(host, port)
            
            # Regular TCP banner grab
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=5.0)
            
            # Send a simple probe
            writer.write(b"\n")
            await writer.drain()
            
            # Read response
            banner = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            
            writer.close()
            await writer.wait_closed()
            
            return banner_str if banner_str else None
            
        except asyncio.TimeoutError:
            return None
        except Exception as e:
            logger.debug(f"TCP banner grab error for {host}:{port} - {e}")
            return None
    
    async def _grab_ssl_banner(self, host: str, port: int) -> Optional[str]:
        """Grab SSL/TLS banner and certificate info."""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect with SSL
            future = asyncio.open_connection(host, port, ssl=context)
            reader, writer = await asyncio.wait_for(future, timeout=10.0)
            
            # Get SSL info
            ssl_object = writer.get_extra_info('ssl_object')
            if ssl_object:
                cert = ssl_object.getpeercert()
                cipher = ssl_object.cipher()
                
                # Create banner with SSL info
                banner_parts = []
                if cert:
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    banner_parts.append(f"Subject: {subject.get('commonName', 'Unknown')}")
                    banner_parts.append(f"Issuer: {issuer.get('commonName', 'Unknown')}")
                
                if cipher:
                    banner_parts.append(f"Cipher: {cipher[0]}")
                
                banner = "\n".join(banner_parts) if banner_parts else "SSL/TLS Service"
            else:
                banner = "SSL/TLS Service"
            
            writer.close()
            await writer.wait_closed()
            
            return banner
            
        except Exception as e:
            logger.debug(f"SSL banner grab error for {host}:{port} - {e}")
            return None
    
    async def _grab_udp_banner(self, host: str, port: int) -> Optional[str]:
        """Grab UDP banner."""
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            
            # Send probe
            sock.sendto(b"\n", (host, port))
            
            # Try to receive response
            data, addr = sock.recvfrom(1024)
            banner = data.decode('utf-8', errors='ignore').strip()
            
            sock.close()
            return banner if banner else None
            
        except socket.timeout:
            return None
        except Exception as e:
            logger.debug(f"UDP banner grab error for {host}:{port} - {e}")
            return None
    
    def identify_service(self, banner: str, port: int) -> Optional[ServiceInfo]:
        """Identify service from banner and port."""
        if not banner:
            return None
        
        best_match = None
        best_confidence = 0.0
        
        for service_name, service_info in self.service_patterns.items():
            # Check if port matches
            if port not in service_info["ports"]:
                continue
            
            # Try to match pattern
            pattern = service_info["pattern"]
            match = re.search(pattern, banner, re.IGNORECASE)
            
            if match:
                confidence = service_info["confidence"]
                
                # Boost confidence for exact port matches
                if port in service_info["ports"]:
                    confidence += 0.1
                
                if confidence > best_confidence:
                    best_confidence = confidence
                    version = match.group(1) if match.groups() else None
                    
                    best_match = ServiceInfo(
                        name=service_name,
                        version=version,
                        banner=banner,
                        confidence=confidence
                    )
        
        # If no pattern match, try port-based identification
        if not best_match:
            best_match = self._identify_by_port(port, banner)
        
        return best_match
    
    def _identify_by_port(self, port: int, banner: str) -> Optional[ServiceInfo]:
        """Identify service by port number when banner doesn't match patterns."""
        port_services = {
            21: "ftp",
            22: "ssh", 
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            6379: "redis",
            8080: "http-alt",
            9200: "elasticsearch",
            27017: "mongodb"
        }
        
        service_name = port_services.get(port)
        if service_name:
            return ServiceInfo(
                name=service_name,
                banner=banner,
                confidence=0.5  # Lower confidence for port-based identification
            )
        
        return None
    
    async def get_ssl_info(self, host: str, port: int) -> Optional[SSLInfo]:
        """Get detailed SSL/TLS certificate information."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            future = asyncio.open_connection(host, port, ssl=context)
            reader, writer = await asyncio.wait_for(future, timeout=10.0)
            
            ssl_object = writer.get_extra_info('ssl_object')
            if not ssl_object:
                return None
            
            cert = ssl_object.getpeercert()
            cipher = ssl_object.cipher()
            
            if not cert:
                return None
            
            # Parse certificate
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))
            
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            
            is_valid = datetime.now() < not_after
            
            ssl_info = SSLInfo(
                subject=subject.get('commonName', 'Unknown'),
                issuer=issuer.get('commonName', 'Unknown'),
                not_before=not_before,
                not_after=not_after,
                serial_number=cert.get('serialNumber', 'Unknown'),
                cipher_suite=cipher[0] if cipher else 'Unknown',
                is_valid=is_valid
            )
            
            writer.close()
            await writer.wait_closed()
            
            return ssl_info
            
        except Exception as e:
            logger.debug(f"SSL info error for {host}:{port} - {e}")
            return None
    
    def get_service_summary(self, results: List[ServiceInfo]) -> Dict[str, int]:
        """Get summary of detected services."""
        summary = {}
        for result in results:
            if result:
                summary[result.name] = summary.get(result.name, 0) + 1
        return summary
