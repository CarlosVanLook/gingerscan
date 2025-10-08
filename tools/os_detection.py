"""
OS Detection Module

Provides operating system detection capabilities using:
- TCP/IP stack fingerprinting
- Banner analysis
- Service version detection
- TTL analysis
- Window size analysis
"""

import asyncio
import socket
import struct
import random
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class OSFamily(Enum):
    """Operating system families."""
    WINDOWS = "Windows"
    LINUX = "Linux"
    MACOS = "macOS"
    BSD = "BSD"
    SOLARIS = "Solaris"
    AIX = "AIX"
    HPUX = "HP-UX"
    UNKNOWN = "Unknown"

@dataclass
class OSInfo:
    """Operating system information."""
    family: OSFamily
    version: Optional[str] = None
    confidence: float = 0.0
    method: str = ""
    details: Dict = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}

class OSDetector:
    """Operating system detection using various fingerprinting techniques."""
    
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.fingerprints = self._load_fingerprints()
        self._cancelled = False
    
    def cancel(self):
        """Cancel the OS detection."""
        self._cancelled = True
        logger.info("OS detection cancellation requested")
    
    def _load_fingerprints(self) -> Dict:
        """Load OS fingerprinting database."""
        return {
            # TTL values (common ranges)
            "ttl": {
                32: OSFamily.LINUX,
                64: OSFamily.LINUX,
                128: OSFamily.WINDOWS,
                255: OSFamily.WINDOWS,
                60: OSFamily.MACOS,
                64: OSFamily.MACOS,
            },
            # Window size patterns
            "window_size": {
                65535: OSFamily.LINUX,
                8192: OSFamily.WINDOWS,
                65535: OSFamily.MACOS,
                16384: OSFamily.WINDOWS,
            },
            # TCP options patterns
            "tcp_options": {
                "mss,ws,nop,nop,sackOK": OSFamily.LINUX,
                "mss,ws,nop,nop,sackOK,timestamp": OSFamily.LINUX,
                "mss,ws,nop,nop,sackOK,timestamp,eol": OSFamily.WINDOWS,
                "mss,ws,nop,nop,sackOK,timestamp,nop,nop": OSFamily.MACOS,
            }
        }
    
    async def detect_os(self, host: str, open_ports: List[int] = None) -> OSInfo:
        """
        Detect operating system for a given host.
        
        Args:
            host: Target host IP address
            open_ports: List of open ports for additional analysis
            
        Returns:
            OSInfo object with detection results
        """
        try:
            logger.info(f"Starting OS detection for {host}")
            
            # Try multiple detection methods
            results = []
            
            # 1. TTL Analysis
            if not self._cancelled:
                ttl_result = await self._analyze_ttl(host)
                if ttl_result:
                    results.append(ttl_result)
            
            # Check for cancellation after TTL analysis
            if self._cancelled:
                logger.info(f"OS detection cancelled during TTL analysis for {host}")
                return OSInfo(family=OSFamily.UNKNOWN, confidence=0.0, method="cancelled")
            
            # 2. TCP Stack Fingerprinting
            if not self._cancelled:
                tcp_result = await self._tcp_fingerprint(host, open_ports or [80, 22, 443])
                if tcp_result:
                    results.append(tcp_result)
            
            # Check for cancellation after TCP fingerprinting
            if self._cancelled:
                logger.info(f"OS detection cancelled during TCP fingerprinting for {host}")
                return OSInfo(family=OSFamily.UNKNOWN, confidence=0.0, method="cancelled")
            
            # 3. Banner Analysis
            if not self._cancelled:
                banner_result = await self._analyze_banners(host, open_ports or [80, 22, 443])
                if banner_result:
                    results.append(banner_result)
            
            # Check for cancellation after banner analysis
            if self._cancelled:
                logger.info(f"OS detection cancelled during banner analysis for {host}")
                return OSInfo(family=OSFamily.UNKNOWN, confidence=0.0, method="cancelled")
            
            # 4. Service Version Analysis
            if not self._cancelled:
                service_result = await self._analyze_services(host, open_ports or [80, 22, 443])
                if service_result:
                    results.append(service_result)
            
            # Combine results
            return self._combine_results(results, host)
            
        except Exception as e:
            logger.error(f"OS detection failed for {host}: {e}")
            return OSInfo(
                family=OSFamily.UNKNOWN,
                confidence=0.0,
                method="error",
                details={"error": str(e)}
            )
    
    async def _analyze_ttl(self, host: str) -> Optional[OSInfo]:
        """Analyze TTL values to determine OS."""
        try:
            # Send ICMP ping to get TTL
            ttl = await self._get_ttl(host)
            if ttl is None:
                return None
            
            # Normalize TTL (account for router hops)
            normalized_ttl = self._normalize_ttl(ttl)
            
            # Look up in fingerprint database
            os_family = self.fingerprints["ttl"].get(normalized_ttl, OSFamily.UNKNOWN)
            confidence = 0.6 if os_family != OSFamily.UNKNOWN else 0.1
            
            return OSInfo(
                family=os_family,
                confidence=confidence,
                method="ttl_analysis",
                details={"ttl": ttl, "normalized_ttl": normalized_ttl}
            )
            
        except Exception as e:
            logger.debug(f"TTL analysis failed for {host}: {e}")
            return None
    
    async def _get_ttl(self, host: str) -> Optional[int]:
        """Get TTL value by sending ICMP ping."""
        try:
            # Check for cancellation before starting
            if self._cancelled:
                logger.debug(f"OS detection cancelled before TTL check for {host}")
                return None
                
            # Use subprocess ping instead of raw socket to avoid blocking
            process = await asyncio.create_subprocess_exec(
                'ping', '-c', '1', '-W', '1', host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Use a much shorter timeout for immediate cancellation response
            short_timeout = 1.0  # 1 second instead of 3 seconds
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=short_timeout)
                
                # Check for cancellation after ping completes
                if self._cancelled:
                    logger.debug(f"OS detection cancelled after TTL check for {host}")
                    return None
                
                if process.returncode == 0:
                    # Parse TTL from ping output (format: "64 bytes from host: icmp_seq=1 ttl=64")
                    output = stdout.decode()
                    if 'ttl=' in output:
                        ttl_part = output.split('ttl=')[1].split()[0]
                        return int(ttl_part)
                
                return None
                
            except asyncio.TimeoutError:
                # Kill the process if it times out
                process.kill()
                await process.wait()
                logger.debug(f"TTL check timed out for {host}")
                return None
            
        except Exception as e:
            logger.debug(f"Failed to get TTL for {host}: {e}")
            return None
    
    def _create_icmp_packet(self) -> bytes:
        """Create ICMP echo request packet."""
        # ICMP header
        icmp_type = 8  # Echo request
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = random.randint(1, 65535)
        icmp_seq = 1
        
        # Create ICMP header
        icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        
        # Calculate checksum
        icmp_checksum = self._calculate_checksum(icmp_header)
        icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        
        return icmp_header
    
    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum."""
        checksum = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                checksum += (data[i] << 8) + data[i + 1]
            else:
                checksum += data[i] << 8
        
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        return ~checksum & 0xFFFF
    
    def _normalize_ttl(self, ttl: int) -> int:
        """Normalize TTL to common initial values."""
        if ttl <= 32:
            return 32
        elif ttl <= 64:
            return 64
        elif ttl <= 128:
            return 128
        elif ttl <= 255:
            return 255
        else:
            return ttl
    
    async def _tcp_fingerprint(self, host: str, ports: List[int]) -> Optional[OSInfo]:
        """Perform TCP stack fingerprinting."""
        try:
            results = []
            short_timeout = 1.0  # Use shorter timeout for faster cancellation
            
            for port in ports[:3]:  # Limit to first 3 ports
                # Check for cancellation before each port
                if self._cancelled:
                    logger.debug(f"TCP fingerprinting cancelled for {host}")
                    return None
                    
                try:
                    # Use asyncio for non-blocking connection
                    try:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(host, port),
                            timeout=short_timeout
                        )
                        writer.close()
                        await writer.wait_closed()
                        
                        # Connection successful, analyze TCP options
                        tcp_info = await self._get_tcp_info(host, port)
                        if tcp_info:
                            results.append(tcp_info)
                            
                    except asyncio.TimeoutError:
                        # Port is closed or filtered, continue to next
                        continue
                            
                except Exception as e:
                    logger.debug(f"TCP fingerprint failed for {host}:{port}: {e}")
                    continue
            
            if not results:
                return None
            
            # Analyze TCP patterns
            return self._analyze_tcp_patterns(results)
            
        except Exception as e:
            logger.debug(f"TCP fingerprinting failed for {host}: {e}")
            return None
    
    async def _get_tcp_info(self, host: str, port: int) -> Optional[Dict]:
        """Get TCP connection information."""
        try:
            # Use asyncio for non-blocking connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=1.0
            )
            
            # Get socket info
            sock = writer.get_extra_info('socket')
            local_addr, local_port = sock.getsockname()
            remote_addr, remote_port = sock.getpeername()
            
            writer.close()
            await writer.wait_closed()
            
            return {
                "host": host,
                "port": port,
                "local_addr": local_addr,
                "local_port": local_port,
                "remote_addr": remote_addr,
                "remote_port": remote_port
            }
            
        except Exception as e:
            logger.debug(f"Failed to get TCP info for {host}:{port}: {e}")
            return None
    
    def _analyze_tcp_patterns(self, tcp_results: List[Dict]) -> OSInfo:
        """Analyze TCP connection patterns."""
        # Simple pattern analysis based on connection behavior
        # This is a simplified version - real OS detection would be more complex
        
        if not tcp_results:
            return OSInfo(family=OSFamily.UNKNOWN, confidence=0.0, method="tcp_fingerprint")
        
        # Basic heuristics
        if len(tcp_results) > 0:
            # Multiple responsive ports indicates a general-purpose OS, not a specific family
            if len(tcp_results) >= 2:
                return OSInfo(
                    family=OSFamily.UNKNOWN,
                    confidence=0.2,
                    method="tcp_fingerprint",
                    details={"connections": len(tcp_results)}
                )
        
        return OSInfo(family=OSFamily.UNKNOWN, confidence=0.1, method="tcp_fingerprint")
    
    async def _analyze_banners(self, host: str, ports: List[int]) -> Optional[OSInfo]:
        """Analyze service banners for OS hints."""
        try:
            os_hints = []
            
            for port in ports[:5]:  # Limit to first 5 ports
                try:
                    banner = await self._get_banner(host, port)
                    if banner:
                        os_family = self._extract_os_from_banner(banner)
                        if os_family:
                            os_hints.append(os_family)
                            
                except Exception as e:
                    logger.debug(f"Banner analysis failed for {host}:{port}: {e}")
                    continue
            
            if not os_hints:
                return None
            
            # Count most common OS hints
            os_counts = {}
            for os_family in os_hints:
                os_counts[os_family] = os_counts.get(os_family, 0) + 1
            
            # Get most common OS
            most_common = max(os_counts.items(), key=lambda x: x[1])
            confidence = min(0.7, 0.3 + (most_common[1] * 0.1))
            
            return OSInfo(
                family=most_common[0],
                confidence=confidence,
                method="banner_analysis",
                details={"banner_hints": os_counts}
            )
            
        except Exception as e:
            logger.debug(f"Banner analysis failed for {host}: {e}")
            return None
    
    async def _get_banner(self, host: str, port: int) -> Optional[str]:
        """Get service banner from a port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            sock.connect((host, port))
            
            # Try to read banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return banner.strip() if banner else None
            
        except Exception as e:
            logger.debug(f"Failed to get banner from {host}:{port}: {e}")
            return None
    
    def _extract_os_from_banner(self, banner: str) -> Optional[OSFamily]:
        """Extract OS information from service banner."""
        banner_lower = banner.lower()
        
        # Common OS indicators in banners
        if any(indicator in banner_lower for indicator in ['windows', 'microsoft', 'iis']):
            return OSFamily.WINDOWS
        elif any(indicator in banner_lower for indicator in ['linux', 'ubuntu', 'debian', 'centos', 'redhat']):
            return OSFamily.LINUX
        elif any(indicator in banner_lower for indicator in ['darwin', 'macos', 'mac os']):
            return OSFamily.MACOS
        elif any(indicator in banner_lower for indicator in ['freebsd', 'openbsd', 'netbsd']):
            return OSFamily.BSD
        elif any(indicator in banner_lower for indicator in ['solaris', 'sunos']):
            return OSFamily.SOLARIS
        elif any(indicator in banner_lower for indicator in ['aix']):
            return OSFamily.AIX
        elif any(indicator in banner_lower for indicator in ['hp-ux', 'hpux']):
            return OSFamily.HPUX
        
        return None
    
    async def _analyze_services(self, host: str, ports: List[int]) -> Optional[OSInfo]:
        """Analyze running services for OS hints."""
        try:
            service_os_hints = {
                # Windows-specific indicators
                135: OSFamily.WINDOWS,  # RPC
                139: OSFamily.WINDOWS,  # NetBIOS
                445: OSFamily.WINDOWS,  # SMB
                3389: OSFamily.WINDOWS,  # RDP
                # Note: generic services (21/22/80/443) are cross-platform and should not bias OS
            }
            
            os_hints = []
            for port in ports:
                if port in service_os_hints:
                    os_hints.append(service_os_hints[port])
            
            if not os_hints:
                return None
            
            # Count OS hints
            os_counts = {}
            for os_family in os_hints:
                os_counts[os_family] = os_counts.get(os_family, 0) + 1
            
            # Get most common OS
            most_common = max(os_counts.items(), key=lambda x: x[1])
            confidence = min(0.6, 0.2 + (most_common[1] * 0.1))
            
            return OSInfo(
                family=most_common[0],
                confidence=confidence,
                method="service_analysis",
                details={"service_hints": os_counts}
            )
            
        except Exception as e:
            logger.debug(f"Service analysis failed for {host}: {e}")
            return None
    
    def _combine_results(self, results: List[OSInfo], host: str) -> OSInfo:
        """Combine multiple OS detection results."""
        if not results:
            return OSInfo(family=OSFamily.UNKNOWN, confidence=0.0, method="combined")
        
        # Weight different methods
        method_weights = {
            "ttl_analysis": 0.3,
            "tcp_fingerprint": 0.2,
            "banner_analysis": 0.3,
            "service_analysis": 0.2
        }
        
        # Calculate weighted scores for each OS
        os_scores = {}
        total_weight = 0
        
        for result in results:
            weight = method_weights.get(result.method, 0.1)
            score = result.confidence * weight
            
            if result.family not in os_scores:
                os_scores[result.family] = 0
            os_scores[result.family] += score
            total_weight += weight
        
        if not os_scores:
            return OSInfo(family=OSFamily.UNKNOWN, confidence=0.0, method="combined")
        
        # Get best match
        best_os = max(os_scores.items(), key=lambda x: x[1])
        confidence = best_os[1] / total_weight if total_weight > 0 else 0.0
        
        # Combine details
        combined_details = {}
        for result in results:
            combined_details[result.method] = {
                "family": result.family.value,
                "confidence": result.confidence,
                "details": result.details
            }
        
        return OSInfo(
            family=best_os[0],
            confidence=min(confidence, 0.95),  # Cap confidence at 95%
            method="combined",
            details=combined_details
        )
