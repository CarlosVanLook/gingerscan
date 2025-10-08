#!/usr/bin/env python3
"""
Shodan API Integration Module

This module provides comprehensive Shodan API integration for threat intelligence,
passive reconnaissance, and vulnerability assessment capabilities.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
import aiohttp
import shodan
from dataclasses import dataclass, asdict
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ShodanError(Exception):
    """Custom exception for Shodan API errors"""
    pass


class ConfidenceLevel(Enum):
    """Confidence levels for Shodan data"""
    HIGH = "high"
    MEDIUM = "medium" 
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class ShodanHostInfo:
    """Structured Shodan host information"""
    ip: str
    hostnames: List[str]
    country: Optional[str]
    city: Optional[str]
    organization: Optional[str]
    isp: Optional[str]
    asn: Optional[str]
    ports: List[int]
    vulnerabilities: List[str]
    tags: List[str]
    last_update: Optional[str]
    confidence: ConfidenceLevel
    raw_data: Dict[str, Any]


@dataclass
class ShodanServiceInfo:
    """Structured Shodan service information"""
    port: int
    protocol: str
    service: Optional[str]
    product: Optional[str]
    version: Optional[str]
    banner: Optional[str]
    ssl_info: Optional[Dict[str, Any]]
    vulnerabilities: List[str]
    timestamp: Optional[str]
    confidence: float


@dataclass
class ShodanVulnerabilityInfo:
    """Structured vulnerability information from Shodan"""
    cve: str
    cvss: Optional[float]
    summary: Optional[str]
    verified: bool
    references: List[str]
    exploit_available: bool


class ShodanCache:
    """Simple caching mechanism for Shodan API responses"""
    
    def __init__(self, cache_duration: int = 3600):
        self.cache_duration = cache_duration
        self.cache: Dict[str, Dict[str, Any]] = {}
    
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached data if not expired"""
        if key in self.cache:
            cached_data = self.cache[key]
            if datetime.now() < cached_data['expires']:
                return cached_data['data']
            else:
                del self.cache[key]
        return None
    
    def set(self, key: str, data: Dict[str, Any]) -> None:
        """Cache data with expiration"""
        self.cache[key] = {
            'data': data,
            'expires': datetime.now() + timedelta(seconds=self.cache_duration)
        }
    
    def clear(self) -> None:
        """Clear all cached data"""
        self.cache.clear()


class ShodanRateLimiter:
    """Rate limiting for Shodan API calls"""
    
    def __init__(self, max_requests: int = 100, time_window: int = 3600):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests: List[float] = []
    
    async def acquire(self) -> bool:
        """Check if request can be made within rate limits"""
        now = time.time()
        
        # Remove old requests outside time window
        self.requests = [req_time for req_time in self.requests 
                        if now - req_time < self.time_window]
        
        if len(self.requests) >= self.max_requests:
            return False
        
        self.requests.append(now)
        return True
    
    def get_remaining_requests(self) -> int:
        """Get number of remaining requests in current window"""
        now = time.time()
        self.requests = [req_time for req_time in self.requests 
                        if now - req_time < self.time_window]
        return max(0, self.max_requests - len(self.requests))


class ShodanClient:
    """
    Comprehensive Shodan API client with caching, rate limiting, and error handling
    """
    
    def __init__(self, api_key: Optional[str] = None, 
                 cache_duration: int = 3600,
                 rate_limit: int = 100,
                 timeout: int = 30):
        """
        Initialize Shodan client
        
        Args:
            api_key: Shodan API key
            cache_duration: Cache duration in seconds
            rate_limit: Maximum requests per hour
            timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.timeout = timeout
        self.cache = ShodanCache(cache_duration)
        self.rate_limiter = ShodanRateLimiter(rate_limit)
        
        # Initialize Shodan API client if key provided
        if api_key:
            try:
                self.api = shodan.Shodan(api_key)
                self._verify_api_key()
            except Exception as e:
                logger.error(f"Failed to initialize Shodan API: {e}")
                self.api = None
        else:
            self.api = None
            logger.warning("No Shodan API key provided - some features will be unavailable")
    
    def _verify_api_key(self) -> bool:
        """Verify API key is valid"""
        try:
            if self.api:
                info = self.api.info()
                logger.info(f"Shodan API initialized - Plan: {info.get('plan', 'Unknown')}")
                return True
        except Exception as e:
            logger.error(f"Invalid Shodan API key: {e}")
            return False
        return False
    
    async def get_host_info(self, ip: str, history: bool = False) -> Optional[ShodanHostInfo]:
        """
        Get comprehensive host information from Shodan
        
        Args:
            ip: IP address to lookup
            history: Include historical data
            
        Returns:
            ShodanHostInfo object or None if not found
        """
        if not self.api:
            logger.warning("Shodan API not available")
            return None
        
        # Check cache first
        cache_key = f"host_{ip}_{history}"
        cached_data = self.cache.get(cache_key)
        if cached_data:
            return self._parse_host_info(cached_data, ip)
        
        # Check rate limits
        if not await self.rate_limiter.acquire():
            logger.warning("Shodan rate limit exceeded")
            return None
        
        try:
            host_data = self.api.host(ip, history=history)
            self.cache.set(cache_key, host_data)
            return self._parse_host_info(host_data, ip)
            
        except shodan.APIError as e:
            if "No information available" in str(e):
                logger.info(f"No Shodan data available for {ip}")
            else:
                logger.error(f"Shodan API error for {ip}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting host info for {ip}: {e}")
            return None
    
    def _parse_host_info(self, data: Dict[str, Any], ip: str) -> ShodanHostInfo:
        """Parse raw Shodan host data into structured format"""
        try:
            # Extract basic information
            hostnames = data.get('hostnames', [])
            country = data.get('country_name')
            city = data.get('city')
            org = data.get('org')
            isp = data.get('isp')
            asn = data.get('asn')
            
            # Extract ports and services
            ports = []
            vulnerabilities = set()
            
            for service in data.get('data', []):
                port = service.get('port')
                if port:
                    ports.append(port)
                
                # Extract vulnerabilities
                vulns = service.get('vulns', {})
                vulnerabilities.update(vulns.keys())
            
            # Extract tags
            tags = data.get('tags', [])
            
            # Determine confidence level
            confidence = self._determine_confidence(data)
            
            return ShodanHostInfo(
                ip=ip,
                hostnames=hostnames,
                country=country,
                city=city,
                organization=org,
                isp=isp,
                asn=asn,
                ports=sorted(list(set(ports))),
                vulnerabilities=sorted(list(vulnerabilities)),
                tags=tags,
                last_update=data.get('last_update'),
                confidence=confidence,
                raw_data=data
            )
            
        except Exception as e:
            logger.error(f"Error parsing host info: {e}")
            return ShodanHostInfo(
                ip=ip, hostnames=[], country=None, city=None,
                organization=None, isp=None, asn=None, ports=[],
                vulnerabilities=[], tags=[], last_update=None,
                confidence=ConfidenceLevel.UNKNOWN, raw_data=data
            )
    
    def _determine_confidence(self, data: Dict[str, Any]) -> ConfidenceLevel:
        """Determine confidence level based on data quality"""
        score = 0
        
        # Check data freshness
        last_update = data.get('last_update')
        if last_update:
            try:
                update_date = datetime.fromisoformat(last_update.replace('Z', '+00:00'))
                days_old = (datetime.now().replace(tzinfo=None) - 
                           update_date.replace(tzinfo=None)).days
                if days_old < 30:
                    score += 3
                elif days_old < 90:
                    score += 2
                else:
                    score += 1
            except:
                score += 1
        
        # Check data richness
        if data.get('data'):
            score += len(data['data']) * 0.5
        
        if data.get('hostnames'):
            score += 1
        
        if data.get('org'):
            score += 1
        
        # Determine confidence level
        if score >= 5:
            return ConfidenceLevel.HIGH
        elif score >= 3:
            return ConfidenceLevel.MEDIUM
        elif score >= 1:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.UNKNOWN
    
    async def get_service_info(self, ip: str, port: int) -> Optional[ShodanServiceInfo]:
        """
        Get detailed service information for a specific port
        
        Args:
            ip: IP address
            port: Port number
            
        Returns:
            ShodanServiceInfo object or None
        """
        host_info = await self.get_host_info(ip)
        if not host_info or not host_info.raw_data:
            return None
        
        # Find service data for the specific port
        for service_data in host_info.raw_data.get('data', []):
            if service_data.get('port') == port:
                return self._parse_service_info(service_data, port)
        
        return None
    
    def _parse_service_info(self, data: Dict[str, Any], port: int) -> ShodanServiceInfo:
        """Parse service data from Shodan"""
        return ShodanServiceInfo(
            port=port,
            protocol=data.get('transport', 'tcp'),
            service=data.get('_shodan', {}).get('module'),
            product=data.get('product'),
            version=data.get('version'),
            banner=data.get('data', '').strip(),
            ssl_info=data.get('ssl'),
            vulnerabilities=list(data.get('vulns', {}).keys()),
            timestamp=data.get('timestamp'),
            confidence=self._calculate_service_confidence(data)
        )
    
    def _calculate_service_confidence(self, data: Dict[str, Any]) -> float:
        """Calculate confidence score for service detection"""
        confidence = 0.1  # Base confidence
        
        if data.get('product'):
            confidence += 0.3
        if data.get('version'):
            confidence += 0.2
        if data.get('data'):  # Has banner
            confidence += 0.2
        if data.get('ssl'):  # SSL information
            confidence += 0.1
        if data.get('_shodan', {}).get('module'):  # Service module detected
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    async def get_vulnerabilities(self, ip: str) -> List[ShodanVulnerabilityInfo]:
        """
        Get vulnerability information for a host
        
        Args:
            ip: IP address to check
            
        Returns:
            List of vulnerability information
        """
        host_info = await self.get_host_info(ip)
        if not host_info or not host_info.raw_data:
            return []
        
        vulnerabilities = []
        
        # Extract vulnerabilities from all services
        for service_data in host_info.raw_data.get('data', []):
            vulns = service_data.get('vulns', {})
            for cve, vuln_data in vulns.items():
                vuln_info = ShodanVulnerabilityInfo(
                    cve=cve,
                    cvss=vuln_data.get('cvss'),
                    summary=vuln_data.get('summary'),
                    verified=vuln_data.get('verified', False),
                    references=vuln_data.get('references', []),
                    exploit_available=self._check_exploit_availability(cve)
                )
                vulnerabilities.append(vuln_info)
        
        return vulnerabilities
    
    def _check_exploit_availability(self, cve: str) -> bool:
        """Check if exploits are available for a CVE (simplified)"""
        # This is a simplified check - in practice, you might want to
        # integrate with exploit databases or use Shodan's exploit data
        exploit_keywords = ['exploit', 'metasploit', 'poc', 'proof of concept']
        return any(keyword in cve.lower() for keyword in exploit_keywords)
    
    async def search_organization(self, org_name: str, limit: int = 100) -> List[ShodanHostInfo]:
        """
        Search for all hosts belonging to an organization
        
        Args:
            org_name: Organization name to search for
            limit: Maximum number of results
            
        Returns:
            List of host information
        """
        if not self.api:
            return []
        
        # Check rate limits
        if not await self.rate_limiter.acquire():
            logger.warning("Shodan rate limit exceeded")
            return []
        
        try:
            query = f'org:"{org_name}"'
            results = self.api.search(query, limit=limit)
            
            hosts = []
            for result in results.get('matches', []):
                ip = result.get('ip_str')
                if ip:
                    host_info = self._parse_host_info(result, ip)
                    hosts.append(host_info)
            
            return hosts
            
        except Exception as e:
            logger.error(f"Error searching organization {org_name}: {e}")
            return []
    
    async def get_honeypot_score(self, ip: str) -> Optional[float]:
        """
        Get honeypot probability score for an IP
        
        Args:
            ip: IP address to check
            
        Returns:
            Honeypot score (0.0-1.0) or None if unavailable
        """
        if not self.api:
            return None
        
        # Check rate limits
        if not await self.rate_limiter.acquire():
            return None
        
        try:
            score = self.api.labs.honeyscore(ip)
            return float(score)
        except Exception as e:
            logger.debug(f"Could not get honeypot score for {ip}: {e}")
            return None
    
    def get_api_info(self) -> Optional[Dict[str, Any]]:
        """Get API account information and limits"""
        if not self.api:
            return None
        
        try:
            return self.api.info()
        except Exception as e:
            logger.error(f"Error getting API info: {e}")
            return None
    
    def get_remaining_credits(self) -> int:
        """Get remaining API credits"""
        info = self.get_api_info()
        if info:
            return info.get('query_credits', 0)
        return 0
    
    def to_dict(self, obj: Union[ShodanHostInfo, ShodanServiceInfo, ShodanVulnerabilityInfo]) -> Dict[str, Any]:
        """Convert dataclass objects to dictionary"""
        if hasattr(obj, '__dict__'):
            result = asdict(obj)
            # Convert enum to string
            if 'confidence' in result and hasattr(result['confidence'], 'value'):
                result['confidence'] = result['confidence'].value
            return result
        return {}


# Convenience functions for easy integration
async def quick_host_lookup(ip: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Quick host lookup function"""
    client = ShodanClient(api_key)
    host_info = await client.get_host_info(ip)
    return client.to_dict(host_info) if host_info else None


async def quick_vulnerability_check(ip: str, api_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """Quick vulnerability check function"""
    client = ShodanClient(api_key)
    vulns = await client.get_vulnerabilities(ip)
    return [client.to_dict(vuln) for vuln in vulns]


if __name__ == "__main__":
    # Example usage
    async def main():
        # Initialize client (replace with your API key)
        client = ShodanClient("YOUR_API_KEY_HERE")
        
        # Test host lookup
        host_info = await client.get_host_info("8.8.8.8")
        if host_info:
            print(f"Host: {host_info.ip}")
            print(f"Organization: {host_info.organization}")
            print(f"Ports: {host_info.ports}")
            print(f"Vulnerabilities: {host_info.vulnerabilities}")
    
    # Run example
    # asyncio.run(main())
