"""
Host Discovery Module

Provides host discovery capabilities:
- ICMP ping sweeps
- ARP scanning (using Scapy)
- DNS resolution
- Network enumeration
"""

import asyncio
import socket
import ipaddress
from typing import List, Set, Optional, Dict
from dataclasses import dataclass
import logging

try:
    from scapy.all import *
    from scapy.layers.inet import IP, ICMP
    from scapy.layers.l2 import ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available. ARP scanning will be disabled.")

logger = logging.getLogger(__name__)


@dataclass
class HostInfo:
    """Information about a discovered host."""
    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    response_time: Optional[float] = None
    discovery_method: Optional[str] = None


class HostDiscovery:
    """Host discovery using multiple methods."""
    
    def __init__(self):
        self.discovered_hosts: Set[str] = set()
        self.host_info: Dict[str, HostInfo] = {}
        self.mac_vendors = self._load_mac_vendors()
    
    def _load_mac_vendors(self) -> Dict[str, str]:
        """Load MAC address vendor database (simplified)."""
        return {
            "00:50:56": "VMware",
            "08:00:27": "VirtualBox",
            "52:54:00": "QEMU",
            "00:0c:29": "VMware",
            "00:1c:42": "Parallels",
            "00:15:5d": "Microsoft Hyper-V",
            "00:16:3e": "Xen",
            "00:1b:21": "Intel",
            "00:1f:5b": "Apple",
            "00:25:00": "Apple",
            "00:26:bb": "Apple",
            "00:50:56": "VMware",
            "00:0d:93": "Apple",
            "00:03:93": "Apple",
            "00:05:02": "Apple",
            "00:0a:95": "Apple",
            "00:0a:27": "Apple",
            "00:0a:28": "Apple",
            "00:0a:29": "Apple",
            "00:0a:2a": "Apple",
            "00:0a:2b": "Apple",
            "00:0a:2c": "Apple",
            "00:0a:2d": "Apple",
            "00:0a:2e": "Apple",
            "00:0a:2f": "Apple",
            "00:0a:30": "Apple",
            "00:0a:31": "Apple",
            "00:0a:32": "Apple",
            "00:0a:33": "Apple",
            "00:0a:34": "Apple",
            "00:0a:35": "Apple",
            "00:0a:36": "Apple",
            "00:0a:37": "Apple",
            "00:0a:38": "Apple",
            "00:0a:39": "Apple",
            "00:0a:3a": "Apple",
            "00:0a:3b": "Apple",
            "00:0a:3c": "Apple",
            "00:0a:3d": "Apple",
            "00:0a:3e": "Apple",
            "00:0a:3f": "Apple",
            "00:0a:40": "Apple",
            "00:0a:41": "Apple",
            "00:0a:42": "Apple",
            "00:0a:43": "Apple",
            "00:0a:44": "Apple",
            "00:0a:45": "Apple",
            "00:0a:46": "Apple",
            "00:0a:47": "Apple",
            "00:0a:48": "Apple",
            "00:0a:49": "Apple",
            "00:0a:4a": "Apple",
            "00:0a:4b": "Apple",
            "00:0a:4c": "Apple",
            "00:0a:4d": "Apple",
            "00:0a:4e": "Apple",
            "00:0a:4f": "Apple",
            "00:0a:50": "Apple",
            "00:0a:51": "Apple",
            "00:0a:52": "Apple",
            "00:0a:53": "Apple",
            "00:0a:54": "Apple",
            "00:0a:55": "Apple",
            "00:0a:56": "Apple",
            "00:0a:57": "Apple",
            "00:0a:58": "Apple",
            "00:0a:59": "Apple",
            "00:0a:5a": "Apple",
            "00:0a:5b": "Apple",
            "00:0a:5c": "Apple",
            "00:0a:5d": "Apple",
            "00:0a:5e": "Apple",
            "00:0a:5f": "Apple",
            "00:0a:60": "Apple",
            "00:0a:61": "Apple",
            "00:0a:62": "Apple",
            "00:0a:63": "Apple",
            "00:0a:64": "Apple",
            "00:0a:65": "Apple",
            "00:0a:66": "Apple",
            "00:0a:67": "Apple",
            "00:0a:68": "Apple",
            "00:0a:69": "Apple",
            "00:0a:6a": "Apple",
            "00:0a:6b": "Apple",
            "00:0a:6c": "Apple",
            "00:0a:6d": "Apple",
            "00:0a:6e": "Apple",
            "00:0a:6f": "Apple",
            "00:0a:70": "Apple",
            "00:0a:71": "Apple",
            "00:0a:72": "Apple",
            "00:0a:73": "Apple",
            "00:0a:74": "Apple",
            "00:0a:75": "Apple",
            "00:0a:76": "Apple",
            "00:0a:77": "Apple",
            "00:0a:78": "Apple",
            "00:0a:79": "Apple",
            "00:0a:7a": "Apple",
            "00:0a:7b": "Apple",
            "00:0a:7c": "Apple",
            "00:0a:7d": "Apple",
            "00:0a:7e": "Apple",
            "00:0a:7f": "Apple",
            "00:0a:80": "Apple",
            "00:0a:81": "Apple",
            "00:0a:82": "Apple",
            "00:0a:83": "Apple",
            "00:0a:84": "Apple",
            "00:0a:85": "Apple",
            "00:0a:86": "Apple",
            "00:0a:87": "Apple",
            "00:0a:88": "Apple",
            "00:0a:89": "Apple",
            "00:0a:8a": "Apple",
            "00:0a:8b": "Apple",
            "00:0a:8c": "Apple",
            "00:0a:8d": "Apple",
            "00:0a:8e": "Apple",
            "00:0a:8f": "Apple",
            "00:0a:90": "Apple",
            "00:0a:91": "Apple",
            "00:0a:92": "Apple",
            "00:0a:93": "Apple",
            "00:0a:94": "Apple",
            "00:0a:95": "Apple",
            "00:0a:96": "Apple",
            "00:0a:97": "Apple",
            "00:0a:98": "Apple",
            "00:0a:99": "Apple",
            "00:0a:9a": "Apple",
            "00:0a:9b": "Apple",
            "00:0a:9c": "Apple",
            "00:0a:9d": "Apple",
            "00:0a:9e": "Apple",
            "00:0a:9f": "Apple",
            "00:0a:a0": "Apple",
            "00:0a:a1": "Apple",
            "00:0a:a2": "Apple",
            "00:0a:a3": "Apple",
            "00:0a:a4": "Apple",
            "00:0a:a5": "Apple",
            "00:0a:a6": "Apple",
            "00:0a:a7": "Apple",
            "00:0a:a8": "Apple",
            "00:0a:a9": "Apple",
            "00:0a:aa": "Apple",
            "00:0a:ab": "Apple",
            "00:0a:ac": "Apple",
            "00:0a:ad": "Apple",
            "00:0a:ae": "Apple",
            "00:0a:af": "Apple",
            "00:0a:b0": "Apple",
            "00:0a:b1": "Apple",
            "00:0a:b2": "Apple",
            "00:0a:b3": "Apple",
            "00:0a:b4": "Apple",
            "00:0a:b5": "Apple",
            "00:0a:b6": "Apple",
            "00:0a:b7": "Apple",
            "00:0a:b8": "Apple",
            "00:0a:b9": "Apple",
            "00:0a:ba": "Apple",
            "00:0a:bb": "Apple",
            "00:0a:bc": "Apple",
            "00:0a:bd": "Apple",
            "00:0a:be": "Apple",
            "00:0a:bf": "Apple",
            "00:0a:c0": "Apple",
            "00:0a:c1": "Apple",
            "00:0a:c2": "Apple",
            "00:0a:c3": "Apple",
            "00:0a:c4": "Apple",
            "00:0a:c5": "Apple",
            "00:0a:c6": "Apple",
            "00:0a:c7": "Apple",
            "00:0a:c8": "Apple",
            "00:0a:c9": "Apple",
            "00:0a:ca": "Apple",
            "00:0a:cb": "Apple",
            "00:0a:cc": "Apple",
            "00:0a:cd": "Apple",
            "00:0a:ce": "Apple",
            "00:0a:cf": "Apple",
            "00:0a:d0": "Apple",
            "00:0a:d1": "Apple",
            "00:0a:d2": "Apple",
            "00:0a:d3": "Apple",
            "00:0a:d4": "Apple",
            "00:0a:d5": "Apple",
            "00:0a:d6": "Apple",
            "00:0a:d7": "Apple",
            "00:0a:d8": "Apple",
            "00:0a:d9": "Apple",
            "00:0a:da": "Apple",
            "00:0a:db": "Apple",
            "00:0a:dc": "Apple",
            "00:0a:dd": "Apple",
            "00:0a:de": "Apple",
            "00:0a:df": "Apple",
            "00:0a:e0": "Apple",
            "00:0a:e1": "Apple",
            "00:0a:e2": "Apple",
            "00:0a:e3": "Apple",
            "00:0a:e4": "Apple",
            "00:0a:e5": "Apple",
            "00:0a:e6": "Apple",
            "00:0a:e7": "Apple",
            "00:0a:e8": "Apple",
            "00:0a:e9": "Apple",
            "00:0a:ea": "Apple",
            "00:0a:eb": "Apple",
            "00:0a:ec": "Apple",
            "00:0a:ed": "Apple",
            "00:0a:ee": "Apple",
            "00:0a:ef": "Apple",
            "00:0a:f0": "Apple",
            "00:0a:f1": "Apple",
            "00:0a:f2": "Apple",
            "00:0a:f3": "Apple",
            "00:0a:f4": "Apple",
            "00:0a:f5": "Apple",
            "00:0a:f6": "Apple",
            "00:0a:f7": "Apple",
            "00:0a:f8": "Apple",
            "00:0a:f9": "Apple",
            "00:0a:fa": "Apple",
            "00:0a:fb": "Apple",
            "00:0a:fc": "Apple",
            "00:0a:fd": "Apple",
            "00:0a:fe": "Apple",
            "00:0a:ff": "Apple"
        }
    
    async def discover_hosts(self, targets: List[str]) -> List[str]:
        """Discover alive hosts from target list."""
        logger.info(f"Starting host discovery for {len(targets)} targets")
        
        # Expand targets to individual IPs
        ip_list = []
        for target in targets:
            try:
                if "/" in target:
                    # CIDR notation
                    network = ipaddress.ip_network(target, strict=False)
                    ip_list.extend([str(ip) for ip in network.hosts()])
                else:
                    # Try to validate as IP address first
                    try:
                        ipaddress.ip_address(target)
                        ip_list.append(target)
                    except ValueError:
                        # If not a valid IP, try to resolve hostname
                        try:
                            resolved_ips = await asyncio.get_event_loop().run_in_executor(
                                None,
                                lambda: [str(addr[4][0]) for addr in socket.getaddrinfo(target, None)]
                            )
                            ip_list.extend(resolved_ips)
                            logger.info(f"Resolved hostname {target} to {resolved_ips}")
                        except Exception as resolve_error:
                            logger.warning(f"Could not resolve hostname {target}: {resolve_error}")
                            continue
            except Exception as e:
                logger.warning(f"Invalid target: {target} - {e}")
                continue
        
        logger.info(f"Expanded to {len(ip_list)} individual IPs")
        
        # Run discovery methods
        tasks = []
        
        # ICMP ping
        tasks.append(self._icmp_ping_sweep(ip_list))
        
        # ARP scan (if Scapy available)
        if SCAPY_AVAILABLE:
            tasks.append(self._arp_scan(ip_list))
        
        # DNS resolution
        tasks.append(self._dns_resolution(ip_list))
        
        # Wait for all discovery methods
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combine results
        alive_hosts = set()
        for result in results:
            if isinstance(result, list):
                alive_hosts.update(result)
            elif isinstance(result, Exception):
                logger.warning(f"Discovery method failed: {result}")
        
        alive_list = list(alive_hosts)
        logger.info(f"Discovered {len(alive_list)} alive hosts")
        
        return alive_list
    
    async def _icmp_ping_sweep(self, ip_list: List[str]) -> List[str]:
        """Perform ICMP ping sweep."""
        logger.info("Starting ICMP ping sweep")
        alive_hosts = []
        
        async def ping_host(ip: str) -> Optional[str]:
            try:
                # Create ICMP ping using subprocess (requires ping command)
                process = await asyncio.create_subprocess_exec(
                    'ping', '-c', '1', '-W', '1', ip,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=3)
                
                if process.returncode == 0:
                    return ip
                return None
                
            except asyncio.TimeoutError:
                return None
            except Exception as e:
                logger.debug(f"Ping error for {ip}: {e}")
                return None
        
        # Ping hosts in parallel
        tasks = [ping_host(ip) for ip in ip_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, str):
                alive_hosts.append(result)
                self.discovered_hosts.add(result)
        
        logger.info(f"ICMP ping found {len(alive_hosts)} alive hosts")
        return alive_hosts
    
    async def _arp_scan(self, ip_list: List[str]) -> List[str]:
        """Perform ARP scan using Scapy."""
        if not SCAPY_AVAILABLE:
            return []
        
        logger.info("Starting ARP scan")
        alive_hosts = []
        
        try:
            # Filter and validate IP addresses
            valid_ips = []
            for ip in ip_list:
                try:
                    # Validate IP address
                    ip_obj = ipaddress.ip_address(ip)
                    # Only scan IPv4 addresses for ARP
                    if ip_obj.version == 4:
                        valid_ips.append(ip)
                except ValueError:
                    logger.warning(f"Invalid IP address for ARP scan: {ip}")
                    continue
            
            if not valid_ips:
                logger.warning("No valid IPv4 addresses for ARP scan")
                return []
            
            logger.info(f"ARP scanning {len(valid_ips)} valid IPv4 addresses")
            
            # Create ARP request with comma-separated IP list
            arp_request = ARP(pdst=",".join(valid_ips))
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send ARP request and get responses with cancellation support
            def arp_scan_task():
                try:
                    return srp(arp_request_broadcast, timeout=2, verbose=0)[0]
                except Exception as e:
                    logger.warning(f"ARP scan failed: {e}")
                    return []
            
            answered_list = await asyncio.get_event_loop().run_in_executor(
                None, arp_scan_task
            )
            
            for element in answered_list:
                if element[1].haslayer(ARP):
                    ip = element[1][ARP].psrc
                    mac = element[1][ARP].hwsrc
                    
                    alive_hosts.append(ip)
                    self.discovered_hosts.add(ip)
                    
                    # Store host info
                    host_info = HostInfo(
                        ip=ip,
                        mac_address=mac,
                        vendor=self._get_vendor(mac),
                        discovery_method="arp"
                    )
                    self.host_info[ip] = host_info
            
            logger.info(f"ARP scan found {len(alive_hosts)} alive hosts")
            
        except Exception as e:
            logger.warning(f"ARP scan failed: {e}")
        
        return alive_hosts
    
    async def _dns_resolution(self, ip_list: List[str]) -> List[str]:
        """Perform DNS resolution."""
        logger.info("Starting DNS resolution")
        alive_hosts = []
        
        async def resolve_host(ip: str) -> Optional[str]:
            try:
                # Try reverse DNS lookup
                hostname = await asyncio.get_event_loop().run_in_executor(
                    None,
                    socket.gethostbyaddr,
                    ip
                )
                
                if hostname:
                    # Store host info
                    host_info = HostInfo(
                        ip=ip,
                        hostname=hostname[0],
                        discovery_method="dns"
                    )
                    self.host_info[ip] = host_info
                    
                    return ip
                return None
                
            except Exception:
                return None
        
        # Resolve hosts in parallel
        tasks = [resolve_host(ip) for ip in ip_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, str):
                alive_hosts.append(result)
                self.discovered_hosts.add(result)
        
        logger.info(f"DNS resolution found {len(alive_hosts)} hosts with names")
        return alive_hosts
    
    def _get_vendor(self, mac: str) -> Optional[str]:
        """Get vendor from MAC address."""
        if not mac:
            return None
        
        # Get first 3 octets (OUI)
        oui = mac.replace(":", "").replace("-", "").upper()[:6]
        oui_formatted = f"{oui[:2]}:{oui[2:4]}:{oui[4:6]}"
        
        return self.mac_vendors.get(oui_formatted, "Unknown")
    
    def get_host_info(self, ip: str) -> Optional[HostInfo]:
        """Get detailed information about a host."""
        return self.host_info.get(ip)
    
    def get_all_host_info(self) -> Dict[str, HostInfo]:
        """Get information about all discovered hosts."""
        return self.host_info.copy()
    
    def get_vendor_summary(self) -> Dict[str, int]:
        """Get summary of discovered vendors."""
        vendors = {}
        for host_info in self.host_info.values():
            if host_info.vendor and host_info.vendor != "Unknown":
                vendors[host_info.vendor] = vendors.get(host_info.vendor, 0) + 1
        return vendors
