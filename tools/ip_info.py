"""
IP Information Module

Provides IP geolocation and reverse DNS lookup capabilities including:
- Hostname resolution
- Domain extraction
- Country and city information
- Organization and ISP details
- ASN (Autonomous System Number) information
"""

import asyncio
import socket
import json
import logging
from typing import Dict, Optional, List
from dataclasses import dataclass
import aiohttp
import ipaddress

logger = logging.getLogger(__name__)

@dataclass
class IPInfo:
    """Information about an IP address."""
    ip: str
    hostname: Optional[str] = None
    domain: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    organization: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    region: Optional[str] = None
    postal_code: Optional[str] = None

class IPInfoGatherer:
    """Gathers comprehensive information about IP addresses."""
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.session = None
        
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout))
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def gather_info(self, ip: str) -> IPInfo:
        """Gather comprehensive information about an IP address."""
        ip_info = IPInfo(ip=ip)
        
        try:
            # Skip private IPs for external services
            if self._is_private_ip(ip):
                ip_info.hostname = await self._reverse_dns_lookup(ip)
                ip_info.domain = self._extract_domain(ip_info.hostname)
                ip_info.organization = "Private Network"
                ip_info.isp = "Private Network"
                return ip_info
            
            # Gather information concurrently
            tasks = [
                self._reverse_dns_lookup(ip),
                self._get_geolocation_info(ip),
                self._get_geolocation_info_fallback(ip),  # Fallback service
                self._get_asn_info(ip)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process reverse DNS result
            if not isinstance(results[0], Exception):
                ip_info.hostname = results[0]
                ip_info.domain = self._extract_domain(ip_info.hostname)
            
            # Process geolocation result (try primary first, then fallback)
            geo_data = None
            for result_idx in [1, 2]:  # Primary and fallback geolocation
                if not isinstance(results[result_idx], Exception) and results[result_idx]:
                    geo_data = results[result_idx]
                    if isinstance(geo_data, dict):
                        break
                    else:
                        logger.debug(f"Geolocation data is not a dictionary for {ip}: {type(geo_data)} - {geo_data}")
                        geo_data = None
            
            if geo_data:
                ip_info.country_name = geo_data.get('country_name', {}).get('name') if isinstance(geo_data.get('country_name'), dict) else geo_data.get('country_name')
                ip_info.city = geo_data.get('city', {}).get('name') if isinstance(geo_data.get('city'), dict) else geo_data.get('city')
                ip_info.region = geo_data.get('region', {}).get('name') if isinstance(geo_data.get('region'), dict) else geo_data.get('region')
                ip_info.postal_code = geo_data.get('postal')
                ip_info.latitude = geo_data.get('location', {}).get('lat') if isinstance(geo_data.get('location'), dict) else geo_data.get('latitude')
                ip_info.longitude = geo_data.get('location', {}).get('lng') if isinstance(geo_data.get('location'), dict) else geo_data.get('longitude')
                ip_info.timezone = geo_data.get('timezone')
                ip_info.organization = geo_data.get('organization')
                ip_info.isp = geo_data.get('isp')
            
            # Process ASN result
            if not isinstance(results[3], Exception) and results[3]:
                asn_data = results[3]
                # Ensure asn_data is a dictionary
                if isinstance(asn_data, dict):
                    ip_info.asn = asn_data.get('asn')
                    ip_info.asn_name = asn_data.get('name')
                    if not ip_info.organization and asn_data.get('organization'):
                        ip_info.organization = asn_data.get('organization')
                    if not ip_info.isp and asn_data.get('isp'):
                        ip_info.isp = asn_data.get('isp')
                else:
                    logger.debug(f"ASN data is not a dictionary for {ip}: {type(asn_data)} - {asn_data}")
            
        except Exception as e:
            logger.error(f"Error gathering IP info for {ip}: {e}")
        
        return ip_info
    
    def _debug_api_response(self, ip: str, service_name: str, response_data):
        """Debug helper to log API response details."""
        if response_data:
            logger.debug(f"{service_name} response for {ip}: type={type(response_data)}, content={str(response_data)[:200]}")
        else:
            logger.debug(f"{service_name} returned no data for {ip}")
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is private."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False
    
    async def _reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup."""
        try:
            loop = asyncio.get_event_loop()
            hostname = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            return hostname[0] if hostname else None
        except (socket.herror, socket.gaierror, OSError):
            return None
    
    def _extract_domain(self, hostname: Optional[str]) -> Optional[str]:
        """Extract domain from hostname."""
        if not hostname:
            return None
        
        # Remove common prefixes
        domain = hostname.lower()
        prefixes = ['www.', 'ftp.', 'mail.', 'smtp.', 'pop.', 'imap.', 'ns.', 'dns.']
        for prefix in prefixes:
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
                break
        
        return domain if domain != hostname.lower() else None
    
    async def _get_geolocation_info(self, ip: str) -> Optional[Dict]:
        """Get geolocation information using ipapi.co (free tier)."""
        if not self.session:
            return None
            
        try:
            url = f"https://ipapi.co/{ip}/json/"
            async with self.session.get(url) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        # Ensure data is a dictionary
                        if isinstance(data, dict) and not data.get('error'):
                            return data
                        else:
                            logger.debug(f"Invalid geolocation data for {ip}: {data}")
                    except (ValueError, TypeError) as json_error:
                        # Try to get text content if JSON parsing fails
                        text_content = await response.text()
                        logger.debug(f"JSON parsing failed for {ip}, response: {text_content[:200]}")
                else:
                    logger.debug(f"Geolocation API returned status {response.status} for {ip}")
        except Exception as e:
            logger.debug(f"Geolocation lookup failed for {ip}: {e}")
        
        return None
    
    async def _get_geolocation_info_fallback(self, ip: str) -> Optional[Dict]:
        """Get geolocation information using ip-api.com (fallback service)."""
        if not self.session:
            return None
            
        try:
            url = f"http://ip-api.com/json/{ip}"
            async with self.session.get(url) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        # Ensure data is a dictionary and status is success
                        if isinstance(data, dict) and data.get('status') == 'success':
                            return {
                                'country_name': data.get('country_name'),
                                'city': data.get('city'),
                                'region': data.get('regionName'),
                                'postal': data.get('zip'),
                                'latitude': data.get('lat'),
                                'longitude': data.get('lon'),
                                'timezone': data.get('timezone'),
                                'organization': data.get('org'),
                                'isp': data.get('isp')
                            }
                        else:
                            logger.debug(f"Fallback geolocation failed for {ip}: {data}")
                    except (ValueError, TypeError) as json_error:
                        # Try to get text content if JSON parsing fails
                        text_content = await response.text()
                        logger.debug(f"Fallback JSON parsing failed for {ip}, response: {text_content[:200]}")
                else:
                    logger.debug(f"Fallback geolocation API returned status {response.status} for {ip}")
        except Exception as e:
            logger.debug(f"Fallback geolocation lookup failed for {ip}: {e}")
        
        return None
    
    async def _get_asn_info(self, ip: str) -> Optional[Dict]:
        """Get ASN information using ipapi.co."""
        if not self.session:
            return None
            
        try:
            url = f"https://ipapi.co/{ip}/json/"
            async with self.session.get(url) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        # Ensure data is a dictionary
                        if isinstance(data, dict) and not data.get('error'):
                            return {
                                'asn': data.get('asn'),
                                'name': data.get('org'),
                                'organization': data.get('org'),
                                'isp': data.get('org')
                            }
                        else:
                            logger.debug(f"Invalid ASN data for {ip}: {data}")
                    except (ValueError, TypeError) as json_error:
                        # Try to get text content if JSON parsing fails
                        text_content = await response.text()
                        logger.debug(f"JSON parsing failed for {ip}, response: {text_content[:200]}")
                else:
                    logger.debug(f"ASN API returned status {response.status} for {ip}")
        except Exception as e:
            logger.debug(f"ASN lookup failed for {ip}: {e}")
        
        return None

# Fallback implementation for when aiohttp is not available
class SimpleIPInfoGatherer:
    """Simple IP info gatherer using only built-in libraries."""
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
    
    async def gather_info(self, ip: str) -> IPInfo:
        """Gather basic information about an IP address."""
        ip_info = IPInfo(ip=ip)
        
        try:
            # Reverse DNS lookup
            loop = asyncio.get_event_loop()
            hostname = await loop.run_in_executor(None, self._reverse_dns_lookup, ip)
            ip_info.hostname = hostname
            ip_info.domain = self._extract_domain(hostname)
            
            # Set basic info for private IPs
            if self._is_private_ip(ip):
                ip_info.organization = "Private Network"
                ip_info.isp = "Private Network"
            else:
                ip_info.organization = "Unknown"
                ip_info.isp = "Unknown"
                
        except Exception as e:
            logger.error(f"Error gathering basic IP info for {ip}: {e}")
        
        return ip_info
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is private."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False
    
    def _reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup."""
        try:
            hostname = socket.gethostbyaddr(ip)
            return hostname[0] if hostname else None
        except (socket.herror, socket.gaierror, OSError):
            return None
    
    def _extract_domain(self, hostname: Optional[str]) -> Optional[str]:
        """Extract domain from hostname."""
        if not hostname:
            return None
        
        # Remove common prefixes
        domain = hostname.lower()
        prefixes = ['www.', 'ftp.', 'mail.', 'smtp.', 'pop.', 'imap.', 'ns.', 'dns.']
        for prefix in prefixes:
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
                break
        
        return domain if domain != hostname.lower() else None

# Factory function to create the appropriate gatherer
def create_ip_info_gatherer(timeout: float = 5.0):
    """Create an IP info gatherer, preferring the full version if aiohttp is available."""
    try:
        import aiohttp
        return IPInfoGatherer(timeout)
    except ImportError:
        logger.warning("aiohttp not available, using simple IP info gatherer")
        return SimpleIPInfoGatherer(timeout)
