"""
Vulnerability Checks Module

Provides basic vulnerability detection capabilities:
- Anonymous FTP checks
- Default credentials testing
- SSL/TLS certificate validation
- Common service vulnerabilities
- Shodan API integration
"""

import asyncio
import socket
import ssl
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logging.warning("Requests not available. HTTP-based checks will be disabled.")

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False
    logging.warning("Shodan not available. Shodan integration will be disabled.")

from .parser import ParsedScanResult
from .shodan_client import ShodanClient, ShodanHostInfo, ShodanVulnerabilityInfo

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    """Vulnerability information."""
    host: str
    port: int
    service: str
    vuln_type: str
    severity: str  # low, medium, high, critical
    description: str
    recommendation: str
    cve: Optional[str] = None
    references: Optional[List[str]] = None


@dataclass
class VulnCheckConfig:
    """Configuration for vulnerability checks."""
    check_anonymous_ftp: bool = True
    check_default_credentials: bool = True
    check_ssl_certificates: bool = True
    check_http_headers: bool = True
    shodan_api_key: Optional[str] = None
    timeout: float = 5.0
    max_workers: int = 10
    
    # Enhanced Shodan configuration
    shodan_enabled: bool = False
    shodan_cache_duration: int = 3600
    shodan_rate_limit: int = 100
    shodan_include_historical: bool = False
    shodan_check_honeypots: bool = True
    shodan_honeypot_threshold: float = 0.5
    shodan_min_cvss_score: float = 4.0


class VulnerabilityChecker:
    """Perform comprehensive vulnerability checks on scan results with Shodan integration."""
    
    def __init__(self, config: Optional[VulnCheckConfig] = None, progress_callback=None):
        self.config = config or VulnCheckConfig()
        self.vulnerabilities: List[Vulnerability] = []
        self.shodan_api = None
        self.shodan_client = None
        self.progress_callback = progress_callback
        
        # Initialize legacy Shodan API for backwards compatibility
        if self.config.shodan_api_key and SHODAN_AVAILABLE:
            try:
                self.shodan_api = shodan.Shodan(self.config.shodan_api_key)
            except Exception as e:
                logger.warning(f"Failed to initialize legacy Shodan API: {e}")
        
        # Initialize enhanced Shodan client
        if self.config.shodan_enabled and self.config.shodan_api_key:
            try:
                self.shodan_client = ShodanClient(
                    api_key=self.config.shodan_api_key,
                    cache_duration=self.config.shodan_cache_duration,
                    rate_limit=self.config.shodan_rate_limit,
                    timeout=self.config.timeout
                )
                logger.info("Enhanced Shodan client initialized successfully")
            except Exception as e:
                logger.warning(f"Failed to initialize enhanced Shodan client: {e}")
    
    async def check_vulnerabilities(self, scan_results: List[ParsedScanResult]) -> List[Vulnerability]:
        """Check vulnerabilities for all scan results."""
        # Filter open ports only
        open_ports = [r for r in scan_results if r.state == "open"]
        
        if not open_ports:
            logger.info("No open ports found - skipping vulnerability checks")
            if self.progress_callback:
                await self.progress_callback(100.0, "running", "No open ports to check for vulnerabilities")
            return []
        
        logger.info(f"Starting vulnerability checks for {len(open_ports)} open ports (out of {len(scan_results)} total results)")
        
        if self.progress_callback:
            await self.progress_callback(87.0, "running", f"Starting vulnerability checks on {len(open_ports)} open ports...")
        
        # Execute checks with concurrency limit and progress updates
        semaphore = asyncio.Semaphore(self.config.max_workers)
        completed_checks = 0
        total_checks = len(open_ports)
        
        async def limited_check(result):
            nonlocal completed_checks
            async with semaphore:
                vuln_result = await self._check_single_result(result)
                completed_checks += 1
                
                # Update progress more frequently for smoother experience
                if completed_checks % max(1, total_checks // 15) == 0 or completed_checks == total_checks:
                    progress = 87.0 + (completed_checks / total_checks) * 8.0  # 87% to 95%
                    percentage = int((completed_checks / total_checks) * 100)
                    if self.progress_callback:
                        await self.progress_callback(progress, "running", f"Vulnerability checks... {percentage}% ({completed_checks}/{total_checks})")
                
                return vuln_result
        
        limited_tasks = [limited_check(result) for result in open_ports]
        results = await asyncio.gather(*limited_tasks, return_exceptions=True)
        
        # Collect vulnerabilities
        for result in results:
            if isinstance(result, list):
                self.vulnerabilities.extend(result)
            elif isinstance(result, Exception):
                logger.warning(f"Vulnerability check failed: {result}")
        
        logger.info(f"Found {len(self.vulnerabilities)} vulnerabilities")
        
        if self.progress_callback:
            await self.progress_callback(95.0, "running", f"Vulnerability checks completed - {len(self.vulnerabilities)} vulnerabilities found")
            
        return self.vulnerabilities
    
    async def _check_single_result(self, result: ParsedScanResult) -> List[Vulnerability]:
        """Check vulnerabilities for a single scan result."""
        vulnerabilities = []
        
        try:
            # Check based on service type
            if result.service:
                service = result.service.lower()
                
                if service == "ftp":
                    vulns = await self._check_ftp_vulnerabilities(result)
                    vulnerabilities.extend(vulns)
                
                elif service in ["http", "https"]:
                    vulns = await self._check_http_vulnerabilities(result)
                    vulnerabilities.extend(vulns)
                
                elif service == "ssh":
                    vulns = await self._check_ssh_vulnerabilities(result)
                    vulnerabilities.extend(vulns)
                
                elif service in ["mysql", "postgresql", "mssql"]:
                    vulns = await self._check_database_vulnerabilities(result)
                    vulnerabilities.extend(vulns)
            
            # Check SSL/TLS if applicable
            if result.port in [443, 993, 995, 465, 587, 636, 990, 992, 994, 989, 990]:
                vulns = await self._check_ssl_vulnerabilities(result)
                vulnerabilities.extend(vulns)
            
            # Enhanced Shodan enrichment if available
            if self.shodan_client:
                vulns = await self._check_enhanced_shodan_vulnerabilities(result)
                vulnerabilities.extend(vulns)
            elif self.shodan_api:
                # Fallback to legacy Shodan API
                vulns = await self._check_shodan_vulnerabilities(result)
                vulnerabilities.extend(vulns)
        
        except Exception as e:
            logger.debug(f"Error checking vulnerabilities for {result.host}:{result.port} - {e}")
        
        return vulnerabilities
    
    async def _check_ftp_vulnerabilities(self, result: ParsedScanResult) -> List[Vulnerability]:
        """Check FTP-specific vulnerabilities."""
        vulnerabilities = []
        
        if not self.config.check_anonymous_ftp:
            return vulnerabilities
        
        try:
            # Test anonymous FTP access
            future = asyncio.open_connection(result.host, result.port)
            reader, writer = await asyncio.wait_for(future, timeout=self.config.timeout)
            
            # Read welcome message
            welcome = await asyncio.wait_for(reader.readline(), timeout=self.config.timeout)
            welcome_str = welcome.decode('utf-8', errors='ignore').strip()
            
            # Try anonymous login
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            
            user_response = await asyncio.wait_for(reader.readline(), timeout=self.config.timeout)
            user_response_str = user_response.decode('utf-8', errors='ignore').strip()
            
            if "331" in user_response_str:  # Password required
                writer.write(b"PASS anonymous\r\n")
                await writer.drain()
                
                pass_response = await asyncio.wait_for(reader.readline(), timeout=self.config.timeout)
                pass_response_str = pass_response.decode('utf-8', errors='ignore').strip()
                
                if "230" in pass_response_str:  # Login successful
                    vuln = Vulnerability(
                        host=result.host,
                        port=result.port,
                        service=result.service,
                        vuln_type="Anonymous FTP Access",
                        severity="medium",
                        description="Anonymous FTP access is enabled",
                        recommendation="Disable anonymous FTP access or restrict it to read-only",
                        references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"]
                    )
                    vulnerabilities.append(vuln)
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            logger.debug(f"FTP vulnerability check failed for {result.host}:{result.port} - {e}")
        
        return vulnerabilities
    
    async def _check_http_vulnerabilities(self, result: ParsedScanResult) -> List[Vulnerability]:
        """Check HTTP-specific vulnerabilities."""
        vulnerabilities = []
        
        if not REQUESTS_AVAILABLE or not self.config.check_http_headers:
            return vulnerabilities
        
        try:
            protocol = "https" if result.port == 443 else "http"
            url = f"{protocol}://{result.host}:{result.port}"
            
            # Check for missing security headers
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: requests.get(url, timeout=self.config.timeout, verify=False)
            )
            
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block",
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'"
            }
            
            for header, expected in security_headers.items():
                if header not in headers:
                    vuln = Vulnerability(
                        host=result.host,
                        port=result.port,
                        service=result.service,
                        vuln_type=f"Missing Security Header: {header}",
                        severity="low",
                        description=f"Missing security header: {header}",
                        recommendation=f"Add {header} header with value: {expected}",
                        references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
                    )
                    vulnerabilities.append(vuln)
            
            # Check for server information disclosure
            if "Server" in headers:
                server_info = headers["Server"]
                if any(version in server_info.lower() for version in ["apache/", "nginx/", "iis/"]):
                    vuln = Vulnerability(
                        host=result.host,
                        port=result.port,
                        service=result.service,
                        vuln_type="Server Information Disclosure",
                        severity="low",
                        description=f"Server information disclosed: {server_info}",
                        recommendation="Remove or obfuscate server information in headers",
                        references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
                    )
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            logger.debug(f"HTTP vulnerability check failed for {result.host}:{result.port} - {e}")
        
        return vulnerabilities
    
    async def _check_ssh_vulnerabilities(self, result: ParsedScanResult) -> List[Vulnerability]:
        """Check SSH-specific vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Check SSH banner for version information
            if result.banner:
                banner_lower = result.banner.lower()
                
                # Check for old SSH versions
                if "openssh_7" in banner_lower or "openssh_6" in banner_lower:
                    vuln = Vulnerability(
                        host=result.host,
                        port=result.port,
                        service=result.service,
                        vuln_type="Outdated SSH Version",
                        severity="medium",
                        description=f"Potentially outdated SSH version: {result.banner}",
                        recommendation="Update SSH to the latest version",
                        references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0777"]
                    )
                    vulnerabilities.append(vuln)
                
                # Check for weak algorithms
                if "ssh-1" in banner_lower:
                    vuln = Vulnerability(
                        host=result.host,
                        port=result.port,
                        service=result.service,
                        vuln_type="Weak SSH Protocol",
                        severity="high",
                        description="SSH-1 protocol is vulnerable and should not be used",
                        recommendation="Disable SSH-1 and use only SSH-2",
                        references=["https://tools.ietf.org/html/rfc4253"]
                    )
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            logger.debug(f"SSH vulnerability check failed for {result.host}:{result.port} - {e}")
        
        return vulnerabilities
    
    async def _check_database_vulnerabilities(self, result: ParsedScanResult) -> List[Vulnerability]:
        """Check database-specific vulnerabilities."""
        vulnerabilities = []
        
        if not self.config.check_default_credentials:
            return vulnerabilities
        
        try:
            # Test for default credentials (simplified check)
            default_creds = {
                "mysql": [("root", ""), ("root", "root"), ("admin", "admin")],
                "postgresql": [("postgres", "postgres"), ("postgres", "")],
                "mssql": [("sa", ""), ("sa", "sa"), ("admin", "admin")]
            }
            
            service = result.service.lower()
            if service in default_creds:
                # This is a simplified check - in practice, you'd need proper database clients
                vuln = Vulnerability(
                    host=result.host,
                    port=result.port,
                    service=result.service,
                    vuln_type="Potential Default Credentials",
                    severity="high",
                    description=f"Database service {service} may be using default credentials",
                    recommendation="Change default credentials and use strong passwords",
                    references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"]
                )
                vulnerabilities.append(vuln)
        
        except Exception as e:
            logger.debug(f"Database vulnerability check failed for {result.host}:{result.port} - {e}")
        
        return vulnerabilities
    
    async def _check_ssl_vulnerabilities(self, result: ParsedScanResult) -> List[Vulnerability]:
        """Check SSL/TLS vulnerabilities."""
        vulnerabilities = []
        
        if not self.config.check_ssl_certificates:
            return vulnerabilities
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect with SSL
            future = asyncio.open_connection(result.host, result.port, ssl=context)
            reader, writer = await asyncio.wait_for(future, timeout=self.config.timeout)
            
            ssl_object = writer.get_extra_info('ssl_object')
            if ssl_object:
                cert = ssl_object.getpeercert()
                cipher = ssl_object.cipher()
                
                if cert:
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        severity = "critical" if days_until_expiry < 7 else "high"
                        vuln = Vulnerability(
                            host=result.host,
                            port=result.port,
                            service=result.service,
                            vuln_type="SSL Certificate Expiring Soon",
                            severity=severity,
                            description=f"SSL certificate expires in {days_until_expiry} days",
                            recommendation="Renew SSL certificate before expiration",
                            references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"]
                        )
                        vulnerabilities.append(vuln)
                    
                    # Check for self-signed certificate
                    if cert.get('issuer') == cert.get('subject'):
                        vuln = Vulnerability(
                            host=result.host,
                            port=result.port,
                            service=result.service,
                            vuln_type="Self-Signed SSL Certificate",
                            severity="medium",
                            description="SSL certificate is self-signed",
                            recommendation="Use a certificate from a trusted Certificate Authority",
                            references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"]
                        )
                        vulnerabilities.append(vuln)
                
                # Check cipher strength
                if cipher:
                    cipher_name = cipher[0]
                    if any(weak in cipher_name.lower() for weak in ['rc4', 'des', 'md5', 'sha1']):
                        vuln = Vulnerability(
                            host=result.host,
                            port=result.port,
                            service=result.service,
                            vuln_type="Weak SSL Cipher",
                            severity="medium",
                            description=f"Weak SSL cipher in use: {cipher_name}",
                            recommendation="Use strong ciphers (AES-256, SHA-256 or better)",
                            references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"]
                        )
                        vulnerabilities.append(vuln)
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            logger.debug(f"SSL vulnerability check failed for {result.host}:{result.port} - {e}")
        
        return vulnerabilities
    
    async def _check_shodan_vulnerabilities(self, result: ParsedScanResult) -> List[Vulnerability]:
        """Check vulnerabilities using Shodan API."""
        vulnerabilities = []
        
        if not self.shodan_api:
            return vulnerabilities
        
        try:
            # Query Shodan for host information
            host_info = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.shodan_api.host(result.host)
            )
            
            # Check for known vulnerabilities
            if 'vulns' in host_info:
                for vuln_id in host_info['vulns']:
                    vuln = Vulnerability(
                        host=result.host,
                        port=result.port,
                        service=result.service,
                        vuln_type=f"Shodan Vulnerability: {vuln_id}",
                        severity="medium",
                        description=f"Vulnerability found in Shodan database: {vuln_id}",
                        recommendation="Check CVE database for details and apply patches",
                        cve=vuln_id,
                        references=[f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln_id}"]
                    )
                    vulnerabilities.append(vuln)
            
            # Check for outdated software
            if 'data' in host_info:
                for service_data in host_info['data']:
                    if service_data.get('port') == result.port:
                        product = service_data.get('product', '')
                        version = service_data.get('version', '')
                        
                        if product and version:
                            vuln = Vulnerability(
                                host=result.host,
                                port=result.port,
                                service=result.service,
                                vuln_type=f"Outdated Software: {product} {version}",
                                severity="low",
                                description=f"Software version found: {product} {version}",
                                recommendation="Update software to latest version",
                                references=["https://cve.mitre.org/"]
                            )
                            vulnerabilities.append(vuln)
        
        except Exception as e:
            logger.debug(f"Shodan vulnerability check failed for {result.host}:{result.port} - {e}")
        
        return vulnerabilities
    
    async def _check_enhanced_shodan_vulnerabilities(self, result: ParsedScanResult) -> List[Vulnerability]:
        """Enhanced vulnerability checking using the new Shodan client."""
        vulnerabilities = []
        
        if not self.shodan_client:
            return vulnerabilities
        
        try:
            # Get comprehensive host information
            host_info = await self.shodan_client.get_host_info(
                result.host, 
                history=self.config.shodan_include_historical
            )
            
            if not host_info:
                return vulnerabilities
            
            # Check for honeypot
            if self.config.shodan_check_honeypots:
                honeypot_score = await self.shodan_client.get_honeypot_score(result.host)
                if honeypot_score and honeypot_score > self.config.shodan_honeypot_threshold:
                    vuln = Vulnerability(
                        host=result.host,
                        port=result.port,
                        service=result.service,
                        vuln_type="Potential Honeypot",
                        severity="low",
                        description=f"High honeypot probability: {honeypot_score:.2f}",
                        recommendation="Exercise caution - this may be a honeypot system",
                        references=["https://www.shodan.io/labs/honeyscore"]
                    )
                    vulnerabilities.append(vuln)
            
            # Get detailed vulnerability information
            shodan_vulns = await self.shodan_client.get_vulnerabilities(result.host)
            
            for shodan_vuln in shodan_vulns:
                # Filter by CVSS score if configured
                if (shodan_vuln.cvss and 
                    shodan_vuln.cvss < self.config.shodan_min_cvss_score):
                    continue
                
                # Determine severity based on CVSS score
                severity = self._cvss_to_severity(shodan_vuln.cvss)
                
                vuln = Vulnerability(
                    host=result.host,
                    port=result.port,
                    service=result.service,
                    vuln_type=f"Shodan CVE: {shodan_vuln.cve}",
                    severity=severity,
                    description=shodan_vuln.summary or f"Vulnerability: {shodan_vuln.cve}",
                    recommendation="Review CVE details and apply appropriate patches",
                    cve=shodan_vuln.cve,
                    references=shodan_vuln.references
                )
                vulnerabilities.append(vuln)
            
            # Check for outdated software based on service information
            service_info = await self.shodan_client.get_service_info(result.host, result.port)
            if service_info and service_info.product and service_info.version:
                # Check if this is an old version (simplified heuristic)
                if self._is_potentially_outdated(service_info.product, service_info.version):
                    vuln = Vulnerability(
                        host=result.host,
                        port=result.port,
                        service=result.service,
                        vuln_type=f"Potentially Outdated Software",
                        severity="medium",
                        description=f"Software detected: {service_info.product} {service_info.version}",
                        recommendation="Verify if this software version is up-to-date and apply updates if needed",
                        references=["https://cve.mitre.org/"]
                    )
                    vulnerabilities.append(vuln)
            
            # Check for suspicious tags
            if host_info.tags:
                suspicious_tags = ['malware', 'compromised', 'botnet', 'suspicious']
                found_tags = [tag for tag in host_info.tags if tag.lower() in suspicious_tags]
                
                if found_tags:
                    vuln = Vulnerability(
                        host=result.host,
                        port=result.port,
                        service=result.service,
                        vuln_type="Suspicious Activity Tags",
                        severity="high",
                        description=f"Suspicious tags found: {', '.join(found_tags)}",
                        recommendation="Investigate potential security compromise",
                        references=["https://www.shodan.io/"]
                    )
                    vulnerabilities.append(vuln)
            
            # Add informational vulnerability for Shodan data availability
            if host_info.confidence.value in ['high', 'medium']:
                vuln = Vulnerability(
                    host=result.host,
                    port=result.port,
                    service=result.service,
                    vuln_type="Internet Exposure",
                    severity="low",
                    description=f"Host is publicly indexed by Shodan (confidence: {host_info.confidence.value})",
                    recommendation="Review if this exposure is intentional and necessary",
                    references=["https://www.shodan.io/"]
                )
                vulnerabilities.append(vuln)
        
        except Exception as e:
            logger.debug(f"Enhanced Shodan vulnerability check failed for {result.host}:{result.port} - {e}")
        
        return vulnerabilities
    
    def _cvss_to_severity(self, cvss_score: Optional[float]) -> str:
        """Convert CVSS score to severity level."""
        if not cvss_score:
            return "medium"
        
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        else:
            return "low"
    
    def _is_potentially_outdated(self, product: str, version: str) -> bool:
        """Simple heuristic to check if software might be outdated."""
        # This is a simplified check - in practice, you'd want a proper vulnerability database
        outdated_patterns = {
            'apache': ['2.2', '2.0', '1.'],
            'nginx': ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5'],
            'openssh': ['6.', '7.0', '7.1', '7.2', '7.3'],
            'mysql': ['5.0', '5.1', '5.5'],
            'postgresql': ['9.', '10.', '11.'],
        }
        
        product_lower = product.lower()
        for prod, old_versions in outdated_patterns.items():
            if prod in product_lower:
                return any(version.startswith(old_ver) for old_ver in old_versions)
        
        return False
    
    def get_vulnerabilities_by_severity(self) -> Dict[str, List[Vulnerability]]:
        """Group vulnerabilities by severity."""
        grouped = {}
        for vuln in self.vulnerabilities:
            if vuln.severity not in grouped:
                grouped[vuln.severity] = []
            grouped[vuln.severity].append(vuln)
        return grouped
    
    def get_vulnerability_summary(self) -> Dict[str, int]:
        """Get summary of vulnerabilities by type."""
        summary = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.vuln_type
            summary[vuln_type] = summary.get(vuln_type, 0) + 1
        return summary
    
    def get_critical_vulnerabilities(self) -> List[Vulnerability]:
        """Get only critical vulnerabilities."""
        return [v for v in self.vulnerabilities if v.severity == "critical"]
    
    def export_vulnerabilities_json(self) -> str:
        """Export vulnerabilities to JSON format."""
        import json
        vuln_data = []
        for vuln in self.vulnerabilities:
            vuln_dict = {
                "host": vuln.host,
                "port": vuln.port,
                "service": vuln.service,
                "vuln_type": vuln.vuln_type,
                "severity": vuln.severity,
                "description": vuln.description,
                "recommendation": vuln.recommendation,
                "cve": vuln.cve,
                "references": vuln.references
            }
            vuln_data.append(vuln_dict)
        
        return json.dumps(vuln_data, indent=2)
