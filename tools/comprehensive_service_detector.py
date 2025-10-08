"""
Comprehensive Service Detection Module

Implements multi-step service detection following best practices:
1. Banner grab (simple first step)
2. Try common application probes (HTTP, TLS, SSH, SMTP, FTP, etc.)
3. Use Nmap version detection (-sV) + NSE scripts
4. Check for TLS (is it an SSL/TLS service?)
5. Protocol fingerprinting / active probes
6. Passive capture analysis (future enhancement)
"""

import asyncio
import subprocess
import json
import re
import socket
import ssl
import struct
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import logging

try:
    from .shodan_client import ShodanClient, ShodanServiceInfo
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False
    logging.warning("Shodan client not available. Passive detection will be disabled.")

logger = logging.getLogger(__name__)

class DetectionMethod(Enum):
    """Service detection methods."""
    BANNER_GRAB = "banner_grab"
    APPLICATION_PROBE = "application_probe"
    NMAP_VERSION = "nmap_version"
    TLS_DETECTION = "tls_detection"
    PROTOCOL_FINGERPRINT = "protocol_fingerprint"
    NSE_SCRIPTS = "nse_scripts"
    SHODAN_PASSIVE = "shodan_passive"

@dataclass
class ServiceInfo:
    """Comprehensive service information."""
    name: str
    version: Optional[str] = None
    banner: Optional[str] = None
    confidence: float = 0.0
    method: str = "unknown"
    product: Optional[str] = None
    extra_info: Optional[str] = None
    tls_enabled: bool = False
    protocol: Optional[str] = None
    ciphers: Optional[List[str]] = None
    certificate_info: Optional[Dict] = None
    nse_scripts: Optional[List[str]] = None
    fingerprint_data: Optional[Dict] = None
    shodan_data: Optional[Dict] = None
    vulnerabilities: Optional[List[str]] = None

class ComprehensiveServiceDetector:
    """Comprehensive multi-step service detection with Shodan integration."""
    
    def __init__(self, use_nmap: bool = True, timeout: float = 10.0, 
                 shodan_client: Optional['ShodanClient'] = None,
                 use_shodan_passive: bool = False):
        self.use_nmap = use_nmap
        self.timeout = timeout
        self.shodan_client = shodan_client
        self.use_shodan_passive = use_shodan_passive and shodan_client is not None
        self.nmap_available = self._check_nmap_availability()
        self.service_patterns = self._load_service_patterns()
        self.probe_templates = self._load_probe_templates()
        
    def _check_nmap_availability(self) -> bool:
        """Check if Nmap is available on the system."""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            logger.warning("Nmap not available. Some detection methods will be disabled.")
            return False
    
    def _load_service_patterns(self) -> Dict[str, Dict]:
        """Load comprehensive service identification patterns."""
        return {
            "ssh": {
                "pattern": r"SSH-(\d+\.\d+)",
                "ports": [22, 2222, 2200],
                "confidence": 0.9,
                "probe": b"SSH-2.0-OpenSSH_8.0\r\n"
            },
            "http": {
                "pattern": r"HTTP/(\d+\.\d+)",
                "ports": [80, 8080, 8000, 8008, 8888, 9090],
                "confidence": 0.8,
                "probe": b"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            },
            "https": {
                "pattern": r"HTTP/(\d+\.\d+)",
                "ports": [443, 8443],
                "confidence": 0.8,
                "probe": b"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            },
            "ftp": {
                "pattern": r"(\d{3}) (.*)",
                "ports": [21, 2121],
                "confidence": 0.9,
                "probe": b""
            },
            "smtp": {
                "pattern": r"(\d{3}) (.*)",
                "ports": [25, 587, 465],
                "confidence": 0.8,
                "probe": b"EHLO test\r\n"
            },
            "pop3": {
                "pattern": r"\+OK (.*)",
                "ports": [110, 995],
                "confidence": 0.9,
                "probe": b""
            },
            "imap": {
                "pattern": r"\* OK (.*)",
                "ports": [143, 993],
                "confidence": 0.9,
                "probe": b""
            },
            "telnet": {
                "pattern": r"(.+)",
                "ports": [23],
                "confidence": 0.7,
                "probe": b""
            },
            "mysql": {
                "pattern": r"(\d+) (.*)",
                "ports": [3306],
                "confidence": 0.8,
                "probe": b"\x20\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x72\x6f\x6f\x74\x00\x00"
            },
            "postgresql": {
                "pattern": r"(\d+) (.*)",
                "ports": [5432],
                "confidence": 0.8,
                "probe": b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
            },
            "redis": {
                "pattern": r"ERR (.*)",
                "ports": [6379],
                "confidence": 0.9,
                "probe": b"PING\r\n"
            },
            "elasticsearch": {
                "pattern": r'"version":\s*{"number":\s*"([^"]+)"',
                "ports": [9200, 9300],
                "confidence": 0.9,
                "probe": b"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
            },
            "mongodb": {
                "pattern": r"(\d+\.\d+\.\d+)",
                "ports": [27017, 27018, 27019],
                "confidence": 0.8,
                "probe": b"\x3f\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00"
            },
            "rdp": {
                "pattern": r"(\d+\.\d+\.\d+\.\d+)",
                "ports": [3389],
                "confidence": 0.7,
                "probe": b""
            },
            "vnc": {
                "pattern": r"RFB (\d+\.\d+)",
                "ports": [5900, 5901, 5902],
                "confidence": 0.9,
                "probe": b"RFB 003.008\n"
            },
            "sip": {
                "pattern": r"SIP/(\d+\.\d+)",
                "ports": [5060, 5061],
                "confidence": 0.8,
                "probe": b"OPTIONS sip:test@{host} SIP/2.0\r\nVia: SIP/2.0/UDP {host}:5060\r\nFrom: <sip:test@{host}>\r\nTo: <sip:test@{host}>\r\nCall-ID: test@localhost\r\nCSeq: 1 OPTIONS\r\n\r\n"
            },
            "irc": {
                "pattern": r":([^\s]+) (\d{3})",
                "ports": [6667, 6668, 6669],
                "confidence": 0.8,
                "probe": b""
            },
            "snmp": {
                "pattern": r"",
                "ports": [161, 162],
                "confidence": 0.7,
                "probe": b"\x30\x0c\x02\x01\x00\x04\x06public\xa0\x05\x02\x03\x00\xff\xff"
            },
            "ldap": {
                "pattern": r"",
                "ports": [389, 636],
                "confidence": 0.8,
                "probe": b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
            },
            "smtp_starttls": {
                "pattern": r"(\d{3}) (.*)",
                "ports": [25, 587],
                "confidence": 0.8,
                "probe": b"EHLO test\r\nSTARTTLS\r\n"
            }
        }
    
    def _load_probe_templates(self) -> Dict[str, bytes]:
        """Load application probe templates."""
        return {
            "http_get": b"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (compatible; ServiceDetector/1.0)\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            "http_options": b"OPTIONS / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            "smtp_ehlo": b"EHLO test.example.com\r\n",
            "smtp_helo": b"HELO test.example.com\r\n",
            "ftp_user": b"USER anonymous\r\n",
            "pop3_user": b"USER test\r\n",
            "imap_login": b"a001 LOGIN test test\r\n",
            "mysql_handshake": b"\x20\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x72\x6f\x6f\x74\x00\x00",
            "postgresql_startup": b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
            "redis_ping": b"PING\r\n",
            "mongodb_isMaster": b"\x3f\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00",
            "vnc_version": b"RFB 003.008\n",
            "sip_options": b"OPTIONS sip:test@{host} SIP/2.0\r\nVia: SIP/2.0/UDP {host}:5060\r\nFrom: <sip:test@{host}>\r\nTo: <sip:test@{host}>\r\nCall-ID: test@localhost\r\nCSeq: 1 OPTIONS\r\n\r\n"
        }
    
    async def detect_service_comprehensive(self, host: str, port: int, cancelled: Optional[callable] = None) -> ServiceInfo:
        """Perform comprehensive multi-step service detection with Shodan integration."""
        if cancelled and cancelled():
            return ServiceInfo(name="unknown", confidence=0.0, method="cancelled")
        logger.info(f"Starting comprehensive service detection for {host}:{port}")
        
        # Step 0: Shodan passive detection (if enabled and available)
        if self.use_shodan_passive:
            shodan_result = await self._step0_shodan_passive_detection(host, port)
            if shodan_result and shodan_result.confidence >= 0.8:
                logger.info(f"Step 0 (Shodan): Detected {shodan_result.name} with confidence {shodan_result.confidence}")
                return shodan_result
        
        # Step 1: Banner grab (simple first step)
        if cancelled and cancelled():
            return ServiceInfo(name="unknown", confidence=0.0, method="cancelled")
        banner_result = await self._step1_banner_grab(host, port, cancelled=cancelled)
        if banner_result and banner_result.confidence >= 0.8:
            logger.info(f"Step 1 (Banner): Detected {banner_result.name} with confidence {banner_result.confidence}")
            # Enrich with Shodan data if available
            if self.shodan_client:
                banner_result = await self._enrich_with_shodan_data(banner_result, host, port)
            return banner_result
        
        # Step 2: Try common application probes
        if cancelled and cancelled():
            return ServiceInfo(name="unknown", confidence=0.0, method="cancelled")
        probe_result = await self._step2_application_probes(host, port, cancelled=cancelled)
        if probe_result and probe_result.confidence >= 0.7:
            logger.info(f"Step 2 (Probes): Detected {probe_result.name} with confidence {probe_result.confidence}")
            # Enrich with Shodan data if available
            if self.shodan_client:
                probe_result = await self._enrich_with_shodan_data(probe_result, host, port)
            return probe_result
        
        # Step 3: Check for TLS/SSL
        if cancelled and cancelled():
            return ServiceInfo(name="unknown", confidence=0.0, method="cancelled")
        tls_result = await self._step3_tls_detection(host, port)
        if tls_result and tls_result.confidence >= 0.8:
            logger.info(f"Step 3 (TLS): Detected {tls_result.name} with confidence {tls_result.confidence}")
            # Enrich with Shodan data if available
            if self.shodan_client:
                tls_result = await self._enrich_with_shodan_data(tls_result, host, port)
            return tls_result
        
        # Step 4: Use Nmap version detection
        if self.nmap_available:
            if cancelled and cancelled():
                return ServiceInfo(name="unknown", confidence=0.0, method="cancelled")
            nmap_result = await self._step4_nmap_detection(host, port)
            if nmap_result and nmap_result.confidence >= 0.7:
                logger.info(f"Step 4 (Nmap): Detected {nmap_result.name} with confidence {nmap_result.confidence}")
                # Enrich with Shodan data if available
                if self.shodan_client:
                    nmap_result = await self._enrich_with_shodan_data(nmap_result, host, port)
                return nmap_result
        
        # Step 5: Protocol fingerprinting
        if cancelled and cancelled():
            return ServiceInfo(name="unknown", confidence=0.0, method="cancelled")
        fingerprint_result = await self._step5_protocol_fingerprinting(host, port)
        if fingerprint_result and fingerprint_result.confidence >= 0.6:
            logger.info(f"Step 5 (Fingerprint): Detected {fingerprint_result.name} with confidence {fingerprint_result.confidence}")
            # Enrich with Shodan data if available
            if self.shodan_client:
                fingerprint_result = await self._enrich_with_shodan_data(fingerprint_result, host, port)
            return fingerprint_result
        
        # Step 6: NSE scripts (if Nmap available)
        if self.nmap_available:
            if cancelled and cancelled():
                return ServiceInfo(name="unknown", confidence=0.0, method="cancelled")
            nse_result = await self._step6_nse_scripts(host, port)
            if nse_result and nse_result.confidence >= 0.6:
                logger.info(f"Step 6 (NSE): Detected {nse_result.name} with confidence {nse_result.confidence}")
                # Enrich with Shodan data if available
                if self.shodan_client:
                    nse_result = await self._enrich_with_shodan_data(nse_result, host, port)
                return nse_result
        
        # Fallback: Return unknown with investigation info, but still try Shodan enrichment
        fallback_result = ServiceInfo(
            name="unknown",
            confidence=0.1,
            method="comprehensive_failed",
            extra_info=f"Port {port} - All detection methods failed. Manual investigation required."
        )
        
        # Try to enrich even unknown services with Shodan data
        if self.shodan_client:
            fallback_result = await self._enrich_with_shodan_data(fallback_result, host, port)
        
        return fallback_result
    
    async def _step1_banner_grab(self, host: str, port: int, cancelled: Optional[callable] = None) -> Optional[ServiceInfo]:
        """Step 1: Simple banner grabbing."""
        try:
            if cancelled and cancelled():
                return None
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=self.timeout)
            if cancelled and cancelled():
                writer.close()
                await writer.wait_closed()
                return None
            # Try to read banner
            banner = ""
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                if cancelled and cancelled():
                    writer.close()
                    await writer.wait_closed()
                    return None
                if banner:
                    banner = banner.decode('utf-8', errors='ignore').strip()
            except asyncio.TimeoutError:
                # No banner received, but connection successful
                pass
            writer.close()
            await writer.wait_closed()
            if cancelled and cancelled():
                return None
            if banner:
                return self._identify_service_from_banner(banner, port)
            else:
                # Connection successful but no banner - could be binary protocol
                return ServiceInfo(
                    name="unknown",
                    banner="Connection successful, no banner",
                    confidence=0.3,
                    method=DetectionMethod.BANNER_GRAB.value,
                    extra_info="Port accepts connections but no text banner"
                )
        except Exception as e:
            logger.debug(f"Banner grab failed for {host}:{port}: {e}")
            return None
    
    async def _step2_application_probes(self, host: str, port: int, cancelled: Optional[callable] = None) -> Optional[ServiceInfo]:
        """Step 2: Try common application probes."""
        # Try different probes based on port
        probes_to_try = self._get_probes_for_port(port)
        for probe_name, probe_data in probes_to_try:
            if cancelled and cancelled():
                return None
            try:
                result = await self._send_probe(host, port, probe_data, probe_name, cancelled=cancelled)
                if cancelled and cancelled():
                    return None
                if result and result.confidence >= 0.7:
                    return result
            except Exception as e:
                logger.debug(f"Probe {probe_name} failed for {host}:{port}: {e}")
                continue
        return None
    
    def _get_probes_for_port(self, port: int) -> List[Tuple[str, bytes]]:
        """Get appropriate probes for a specific port."""
        port_probes = {
            80: [("http_get", self.probe_templates["http_get"])],
            443: [("http_get", self.probe_templates["http_get"])],
            8080: [("http_get", self.probe_templates["http_get"])],
            8000: [("http_get", self.probe_templates["http_get"])],
            8888: [("http_get", self.probe_templates["http_get"])],
            9090: [("http_get", self.probe_templates["http_get"])],
            25: [("smtp_ehlo", self.probe_templates["smtp_ehlo"])],
            587: [("smtp_ehlo", self.probe_templates["smtp_ehlo"])],
            21: [("ftp_user", self.probe_templates["ftp_user"])],
            110: [("pop3_user", self.probe_templates["pop3_user"])],
            143: [("imap_login", self.probe_templates["imap_login"])],
            3306: [("mysql_handshake", self.probe_templates["mysql_handshake"])],
            5432: [("postgresql_startup", self.probe_templates["postgresql_startup"])],
            6379: [("redis_ping", self.probe_templates["redis_ping"])],
            27017: [("mongodb_isMaster", self.probe_templates["mongodb_isMaster"])],
            5900: [("vnc_version", self.probe_templates["vnc_version"])],
            5060: [("sip_options", self.probe_templates["sip_options"])],
        }
        
        return port_probes.get(port, [])
    
    async def _send_probe(self, host: str, port: int, probe_data: bytes, probe_name: str, cancelled: Optional[callable] = None) -> Optional[ServiceInfo]:
        """Send a specific probe and analyze response."""
        try:
            if cancelled and cancelled():
                return None
            # Format probe data with host if needed
            formatted_probe = probe_data.replace(b"{host}", host.encode())
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=self.timeout)
            if cancelled and cancelled():
                writer.close()
                await writer.wait_closed()
                return None
            # Send probe
            writer.write(formatted_probe)
            await writer.drain()
            if cancelled and cancelled():
                writer.close()
                await writer.wait_closed()
                return None
            # Read response
            response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            if cancelled and cancelled():
                writer.close()
                await writer.wait_closed()
                return None
            response_str = response.decode('utf-8', errors='ignore').strip()
            writer.close()
            await writer.wait_closed()
            return self._analyze_probe_response(response_str, port, probe_name)
        except Exception as e:
            logger.debug(f"Probe {probe_name} failed for {host}:{port}: {e}")
            return None
    
    def _analyze_probe_response(self, response: str, port: int, probe_name: str) -> Optional[ServiceInfo]:
        """Analyze probe response to identify service."""
        response_lower = response.lower()
        
        # HTTP responses
        if "http" in response_lower and ("200" in response or "301" in response or "302" in response):
            return ServiceInfo(
                name="http",
                banner=response[:200],
                confidence=0.9,
                method=DetectionMethod.APPLICATION_PROBE.value,
                extra_info=f"HTTP response to {probe_name}"
            )
        
        # SMTP responses
        if probe_name.startswith("smtp") and any(code in response for code in ["220", "250", "554"]):
            return ServiceInfo(
                name="smtp",
                banner=response[:200],
                confidence=0.9,
                method=DetectionMethod.APPLICATION_PROBE.value,
                extra_info=f"SMTP response to {probe_name}"
            )
        
        # FTP responses
        if probe_name.startswith("ftp") and any(code in response for code in ["220", "331", "530"]):
            return ServiceInfo(
                name="ftp",
                banner=response[:200],
                confidence=0.9,
                method=DetectionMethod.APPLICATION_PROBE.value,
                extra_info=f"FTP response to {probe_name}"
            )
        
        # MySQL responses
        if probe_name == "mysql_handshake" and len(response) > 0:
            return ServiceInfo(
                name="mysql",
                banner=response[:200],
                confidence=0.8,
                method=DetectionMethod.APPLICATION_PROBE.value,
                extra_info="MySQL handshake response"
            )
        
        # Redis responses
        if probe_name == "redis_ping" and "+PONG" in response:
            return ServiceInfo(
                name="redis",
                banner=response[:200],
                confidence=0.9,
                method=DetectionMethod.APPLICATION_PROBE.value,
                extra_info="Redis PONG response"
            )
        
        # VNC responses
        if probe_name == "vnc_version" and "RFB" in response:
            return ServiceInfo(
                name="vnc",
                banner=response[:200],
                confidence=0.9,
                method=DetectionMethod.APPLICATION_PROBE.value,
                extra_info="VNC version response"
            )
        
        return None
    
    async def _step3_tls_detection(self, host: str, port: int) -> Optional[ServiceInfo]:
        """Step 3: Check for TLS/SSL services."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            future = asyncio.open_connection(host, port, ssl=context)
            reader, writer = await asyncio.wait_for(future, timeout=self.timeout)
            
            # Get SSL info
            ssl_object = writer.get_extra_info('ssl_object')
            if ssl_object:
                cipher = ssl_object.cipher()
                cert = ssl_object.getpeercert()
                
                # Determine service type based on port and SSL
                service_name = "https" if port == 443 else "ssl"
                
                return ServiceInfo(
                    name=service_name,
                    confidence=0.9,
                    method=DetectionMethod.TLS_DETECTION.value,
                    tls_enabled=True,
                    protocol="TLS",
                    ciphers=[cipher[0]] if cipher else None,
                    certificate_info=cert,
                    extra_info=f"TLS enabled with cipher: {cipher[0] if cipher else 'Unknown'}"
                )
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            logger.debug(f"TLS detection failed for {host}:{port}: {e}")
            return None
        
        return None
    
    async def _step4_nmap_detection(self, host: str, port: int) -> Optional[ServiceInfo]:
        """Step 4: Use Nmap version detection."""
        if not self.nmap_available:
            return None
        
        try:
            cmd = [
                'nmap', '-sV', '--version-intensity=9',
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
                return None
            
            output = stdout.decode()
            return self._parse_nmap_output(output, host, port)
            
        except Exception as e:
            logger.debug(f"Nmap detection failed for {host}:{port}: {e}")
            return None
    
    async def _step5_protocol_fingerprinting(self, host: str, port: int) -> Optional[ServiceInfo]:
        """Step 5: Protocol fingerprinting using custom probes."""
        # This is a simplified version - in practice, you'd implement more sophisticated fingerprinting
        try:
            # Try to connect and analyze the connection behavior
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=self.timeout)
            
            # Send a generic probe
            writer.write(b"\x00\x01\x02\x03")
            await writer.drain()
            
            # Read response
            response = await asyncio.wait_for(reader.read(256), timeout=3.0)
            
            writer.close()
            await writer.wait_closed()
            
            # Analyze response pattern
            if len(response) > 0:
                # Basic pattern analysis
                if response.startswith(b"HTTP"):
                    return ServiceInfo(
                        name="http",
                        confidence=0.7,
                        method=DetectionMethod.PROTOCOL_FINGERPRINT.value,
                        extra_info="HTTP response pattern detected"
                    )
                elif b"SSH" in response:
                    return ServiceInfo(
                        name="ssh",
                        confidence=0.8,
                        method=DetectionMethod.PROTOCOL_FINGERPRINT.value,
                        extra_info="SSH response pattern detected"
                    )
                else:
                    return ServiceInfo(
                        name="unknown",
                        confidence=0.4,
                        method=DetectionMethod.PROTOCOL_FINGERPRINT.value,
                        extra_info=f"Binary response detected, length: {len(response)}"
                    )
            
        except Exception as e:
            logger.debug(f"Protocol fingerprinting failed for {host}:{port}: {e}")
            return None
        
        return None
    
    async def _step6_nse_scripts(self, host: str, port: int) -> Optional[ServiceInfo]:
        """Step 6: Use Nmap NSE scripts for additional detection."""
        if not self.nmap_available:
            return None
        
        try:
            # Run specific NSE scripts based on port
            scripts = self._get_nse_scripts_for_port(port)
            if not scripts:
                return None
            
            cmd = [
                'nmap', '--script', ','.join(scripts),
                '--script-timeout=30s', '--max-retries=1',
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
                return None
            
            output = stdout.decode()
            return self._parse_nse_output(output, port)
            
        except Exception as e:
            logger.debug(f"NSE scripts failed for {host}:{port}: {e}")
            return None
    
    def _get_nse_scripts_for_port(self, port: int) -> List[str]:
        """Get appropriate NSE scripts for a specific port."""
        port_scripts = {
            80: ["http-methods", "http-headers", "http-enum"],
            443: ["ssl-enum-ciphers", "ssl-cert", "https-enum"],
            21: ["ftp-anon", "ftp-banner", "ftp-vsftpd-backdoor"],
            22: ["ssh-hostkey", "ssh2-enum-algos", "sshv1"],
            25: ["smtp-commands", "smtp-enum-users", "smtp-vuln-cve2010-4344"],
            110: ["pop3-capabilities", "pop3-ntlm-info"],
            143: ["imap-capabilities", "imap-ntlm-info"],
            443: ["ssl-enum-ciphers", "ssl-cert", "https-enum"],
            993: ["ssl-enum-ciphers", "ssl-cert"],
            995: ["ssl-enum-ciphers", "ssl-cert"],
            3306: ["mysql-info", "mysql-enum", "mysql-vuln-cve2012-2122"],
            5432: ["pgsql-brute", "pgsql-hashdump"],
            6379: ["redis-info", "redis-brute"],
            9200: ["elasticsearch-enum"],
            27017: ["mongodb-info", "mongodb-brute"],
        }
        
        return port_scripts.get(port, [])
    
    def _parse_nse_output(self, output: str, port: int) -> Optional[ServiceInfo]:
        """Parse NSE script output."""
        # This is a simplified parser - in practice, you'd implement more sophisticated parsing
        lines = output.split('\n')
        
        for line in lines:
            if "|" in line and ":" in line:
                # Parse NSE script output
                parts = line.split("|")
                if len(parts) >= 2:
                    script_name = parts[0].strip()
                    script_output = parts[1].strip()
                    
                    # Determine service based on script output
                    if "http" in script_name.lower():
                        return ServiceInfo(
                            name="http",
                            confidence=0.8,
                            method=DetectionMethod.NSE_SCRIPTS.value,
                            nse_scripts=[script_name],
                            extra_info=f"NSE: {script_output}"
                        )
                    elif "ssl" in script_name.lower():
                        return ServiceInfo(
                            name="https",
                            confidence=0.8,
                            method=DetectionMethod.NSE_SCRIPTS.value,
                            tls_enabled=True,
                            nse_scripts=[script_name],
                            extra_info=f"NSE: {script_output}"
                        )
        
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
                    
                    return ServiceInfo(
                        name=service_name,
                        version=version,
                        confidence=0.9,
                        method=DetectionMethod.NMAP_VERSION.value,
                        extra_info=f"Nmap version detection: {version}"
                    )
        
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
                    method=DetectionMethod.BANNER_GRAB.value
                )
        
        # Try to identify from banner content
        if "ssh" in banner_lower:
            return ServiceInfo(name="ssh", banner=banner, confidence=0.8, method=DetectionMethod.BANNER_GRAB.value)
        elif "http" in banner_lower:
            return ServiceInfo(name="http", banner=banner, confidence=0.7, method=DetectionMethod.BANNER_GRAB.value)
        elif "ftp" in banner_lower:
            return ServiceInfo(name="ftp", banner=banner, confidence=0.7, method=DetectionMethod.BANNER_GRAB.value)
        elif "smtp" in banner_lower:
            return ServiceInfo(name="smtp", banner=banner, confidence=0.7, method=DetectionMethod.BANNER_GRAB.value)
        
        return None
    
    async def detect_services_batch(self, host: str, ports: List[int], cancelled: Optional[callable] = None) -> Dict[int, ServiceInfo]:
        """Detect services for multiple ports using comprehensive detection."""
        results = {}
        
        # Process ports in parallel (but limit concurrency)
        semaphore = asyncio.Semaphore(5)  # Max 5 concurrent detections
        
        async def detect_single_port(port: int) -> Tuple[int, ServiceInfo]:
            async with semaphore:
                if cancelled and cancelled():
                    return port, ServiceInfo(name="unknown", confidence=0.0, method="cancelled")
                service_info = await self.detect_service_comprehensive(host, port, cancelled=cancelled)
                return port, service_info
        
        tasks = [detect_single_port(port) for port in ports]
        detection_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in detection_results:
            if isinstance(result, Exception):
                logger.error(f"Service detection failed: {result}")
                continue
            
            port, service_info = result
            results[port] = service_info
        
        return results
    
    async def _step0_shodan_passive_detection(self, host: str, port: int) -> Optional[ServiceInfo]:
        """Step 0: Shodan passive detection - get service info without active scanning."""
        if not self.shodan_client:
            return None
        
        try:
            logger.debug(f"Attempting Shodan passive detection for {host}:{port}")
            
            # Get service information from Shodan
            service_info = await self.shodan_client.get_service_info(host, port)
            
            if not service_info:
                return None
            
            # Convert Shodan service info to our ServiceInfo format
            service_name = service_info.service or "unknown"
            if service_info.product:
                service_name = service_info.product.lower()
            
            # Build comprehensive service information
            shodan_service = ServiceInfo(
                name=service_name,
                version=service_info.version,
                banner=service_info.banner,
                confidence=service_info.confidence,
                method=DetectionMethod.SHODAN_PASSIVE.value,
                product=service_info.product,
                protocol=service_info.protocol,
                vulnerabilities=service_info.vulnerabilities,
                shodan_data={
                    "timestamp": service_info.timestamp,
                    "ssl_info": service_info.ssl_info,
                    "confidence": service_info.confidence
                }
            )
            
            # Add SSL information if available
            if service_info.ssl_info:
                shodan_service.tls_enabled = True
                shodan_service.certificate_info = service_info.ssl_info
            
            logger.info(f"Shodan passive detection successful: {service_name} (confidence: {service_info.confidence:.2f})")
            return shodan_service
            
        except Exception as e:
            logger.debug(f"Shodan passive detection failed for {host}:{port}: {e}")
            return None
    
    async def _enrich_with_shodan_data(self, service_info: ServiceInfo, host: str, port: int) -> ServiceInfo:
        """Enrich existing service detection results with Shodan data."""
        if not self.shodan_client:
            return service_info
        
        try:
            logger.debug(f"Enriching service info with Shodan data for {host}:{port}")
            
            # Get Shodan service information
            shodan_service = await self.shodan_client.get_service_info(host, port)
            
            if shodan_service:
                # Enrich version information if not already detected
                if not service_info.version and shodan_service.version:
                    service_info.version = shodan_service.version
                
                # Enrich product information
                if not service_info.product and shodan_service.product:
                    service_info.product = shodan_service.product
                
                # Add vulnerabilities
                if shodan_service.vulnerabilities:
                    service_info.vulnerabilities = shodan_service.vulnerabilities
                
                # Add SSL information
                if shodan_service.ssl_info:
                    service_info.tls_enabled = True
                    if not service_info.certificate_info:
                        service_info.certificate_info = shodan_service.ssl_info
                
                # Add Shodan-specific data
                service_info.shodan_data = {
                    "timestamp": shodan_service.timestamp,
                    "ssl_info": shodan_service.ssl_info,
                    "confidence": shodan_service.confidence,
                    "banner": shodan_service.banner
                }
                
                # Improve confidence if Shodan provides additional confirmation
                if (service_info.name.lower() == shodan_service.service or 
                    (shodan_service.product and service_info.name.lower() in shodan_service.product.lower())):
                    service_info.confidence = min(1.0, service_info.confidence + 0.1)
                
                logger.debug(f"Service info enriched with Shodan data")
            
            # Also get host-level information for additional context
            host_info = await self.shodan_client.get_host_info(host)
            if host_info:
                # Add extra context from host information
                if not service_info.extra_info:
                    service_info.extra_info = ""
                
                extra_context = []
                if host_info.organization:
                    extra_context.append(f"Org: {host_info.organization}")
                if host_info.country:
                    extra_context.append(f"Country: {host_info.country}")
                if host_info.tags:
                    extra_context.append(f"Tags: {', '.join(host_info.tags)}")
                
                if extra_context:
                    context_str = " | ".join(extra_context)
                    if service_info.extra_info:
                        service_info.extra_info += f" | Shodan: {context_str}"
                    else:
                        service_info.extra_info = f"Shodan: {context_str}"
        
        except Exception as e:
            logger.debug(f"Failed to enrich service info with Shodan data for {host}:{port}: {e}")
        
        return service_info
