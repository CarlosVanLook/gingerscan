# Shodan API Integration Guide

The Ginger Scan network tools now include comprehensive Shodan API integration for enhanced threat intelligence, passive reconnaissance, and vulnerability assessment capabilities.

## Overview

Shodan is a search engine for Internet-connected devices that provides valuable intelligence about hosts, services, and vulnerabilities. Our integration adds the following capabilities to your network scans:

### 🔍 **Threat Intelligence**
- Historical vulnerability data from Shodan's database
- CVE correlation with CVSS scores
- Exploit availability information
- Honeypot detection and reputation scoring

### 🌐 **Passive Reconnaissance**
- Service detection without active scanning
- Historical service information and banners
- Organization and geolocation intelligence
- SSL/TLS certificate analysis

### 🚨 **Enhanced Security Assessment**
- Vulnerability timeline analysis
- Internet exposure monitoring
- Suspicious activity detection
- Compliance and risk scoring

## Features

### Core Functionality

#### 1. **Host Intelligence Lookup**
```python
from tools.shodan_client import ShodanClient

client = ShodanClient("your_api_key")
host_info = await client.get_host_info("8.8.8.8")

print(f"Organization: {host_info.organization}")
print(f"Open Ports: {host_info.ports}")
print(f"Vulnerabilities: {host_info.vulnerabilities}")
```

#### 2. **Passive Service Detection**
```python
from tools.comprehensive_service_detector import ComprehensiveServiceDetector

detector = ComprehensiveServiceDetector(
    shodan_client=client,
    use_shodan_passive=True
)

service = await detector.detect_service_comprehensive("target.com", 80)
print(f"Service: {service.name} (via {service.method})")
```

#### 3. **Enhanced Vulnerability Assessment**
```python
from tools.vuln_checks import VulnerabilityChecker, VulnCheckConfig

config = VulnCheckConfig(
    shodan_enabled=True,
    shodan_api_key="your_key",
    shodan_min_cvss_score=4.0
)

checker = VulnerabilityChecker(config)
vulnerabilities = await checker.check_vulnerabilities(scan_results)
```

#### 4. **Organization Asset Discovery**
```python
hosts = await client.search_organization("Example Corp", limit=100)
for host in hosts:
    print(f"{host.ip}: {host.organization} ({host.country})")
```

### Integration Points

#### **Scanner Integration**
The Shodan client integrates seamlessly with your existing scanning workflow:

- **Step 0**: Shodan passive detection (if enabled)
- **Step 1-6**: Traditional active scanning methods
- **Enrichment**: All results enhanced with Shodan intelligence

#### **Vulnerability Assessment**
Enhanced vulnerability checking includes:

- **CVE Correlation**: Match discovered services with known vulnerabilities
- **CVSS Scoring**: Severity assessment based on industry standards
- **Exploit Detection**: Identify vulnerabilities with available exploits
- **Honeypot Detection**: Avoid scanning honeypot systems

#### **Reporting Integration**
HTML reports now include a dedicated Shodan intelligence section with:

- **Threat Intelligence Dashboard**: Visual overview of findings
- **Vulnerability Tables**: Detailed CVE information with severity indicators
- **Host Intelligence**: Organization, geolocation, and reputation data
- **Confidence Indicators**: Data quality and reliability metrics

## Configuration

### Basic Configuration

Edit `config/default.yaml`:

```yaml
shodan:
  # API Configuration
  api_key: "YOUR_SHODAN_API_KEY"
  enabled: true
  timeout: 30
  
  # Features to enable
  features:
    host_lookup: true
    vulnerability_check: true
    passive_detection: true
    organization_search: true
    honeypot_detection: true
```

### Advanced Configuration

```yaml
shodan:
  # Caching settings
  cache:
    enabled: true
    duration: 3600  # 1 hour
    max_entries: 1000
    
  # Rate limiting
  rate_limit:
    max_requests: 100  # Per time window
    time_window: 3600  # 1 hour
    
  # Vulnerability assessment
  vulnerability_assessment:
    enabled: true
    include_cvss: true
    check_exploits: true
    severity_filter: "medium"  # minimum severity
    
  # Threat intelligence
  threat_intelligence:
    enabled: true
    check_reputation: true
    check_malware: true
    check_honeypots: true
    honeypot_threshold: 0.5
```

## Usage Examples

### Command Line Usage

```bash
# Basic scan with Shodan integration
python -m tools.scanner --target 192.168.1.1 --ports 1-1000 --shodan

# Comprehensive scan with vulnerability assessment
python -m tools.scanner --target example.com --ports 1-1000 --shodan --vuln-check

# Generate HTML report with Shodan intelligence
python -m tools.scanner --target 192.168.1.0/24 --shodan --output report.html --format html
```

### Web Dashboard

The web dashboard includes real-time Shodan integration:

```bash
python -m tools.web_dashboard
```

Access at `http://localhost:8000` to see:
- Live threat intelligence overlay
- Vulnerability severity indicators
- Historical exposure tracking
- Interactive Shodan data exploration

### Programmatic Usage

```python
import asyncio
from tools.shodan_client import ShodanClient

async def scan_with_shodan():
    client = ShodanClient("your_api_key")
    
    # Get host information
    host_info = await client.get_host_info("target.com")
    
    # Check for vulnerabilities
    vulns = await client.get_vulnerabilities("target.com")
    
    # Get honeypot score
    honeypot_score = await client.get_honeypot_score("target.com")
    
    print(f"Vulnerabilities: {len(vulns)}")
    print(f"Honeypot probability: {honeypot_score}")

asyncio.run(scan_with_shodan())
```

## API Reference

### ShodanClient Class

#### Methods

- `get_host_info(ip, history=False)` - Get comprehensive host information
- `get_service_info(ip, port)` - Get detailed service information
- `get_vulnerabilities(ip)` - Get vulnerability information
- `get_honeypot_score(ip)` - Get honeypot probability score
- `search_organization(org_name, limit=100)` - Search organization assets
- `get_api_info()` - Get API account information
- `get_remaining_credits()` - Get remaining API credits

#### Data Classes

- `ShodanHostInfo` - Structured host information
- `ShodanServiceInfo` - Detailed service information
- `ShodanVulnerabilityInfo` - Vulnerability details with CVSS

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `api_key` | string | "" | Your Shodan API key |
| `enabled` | boolean | false | Enable Shodan integration |
| `cache.duration` | int | 3600 | Cache duration in seconds |
| `rate_limit.max_requests` | int | 100 | Max requests per time window |
| `vulnerability_assessment.severity_filter` | string | "medium" | Minimum vulnerability severity |
| `threat_intelligence.honeypot_threshold` | float | 0.5 | Honeypot detection threshold |

## Best Practices

### API Key Management

1. **Secure Storage**: Store API keys in environment variables or secure config files
2. **Access Control**: Limit API key access to authorized users only
3. **Monitoring**: Track API usage to avoid exceeding rate limits

```bash
# Environment variable approach
export SHODAN_API_KEY="your_key_here"
```

### Rate Limiting

1. **Respect Limits**: Free accounts have 100 queries/month
2. **Caching**: Enable caching to reduce API calls
3. **Batch Operations**: Group related queries when possible

### Data Interpretation

1. **Confidence Levels**: Always check confidence scores
2. **Data Freshness**: Consider timestamp information
3. **False Positives**: Validate critical findings manually

### Security Considerations

1. **Honeypot Detection**: Enable honeypot checking to avoid traps
2. **Rate Limiting**: Implement proper rate limiting to avoid blocking
3. **Data Sensitivity**: Be careful with sensitive target information

## Troubleshooting

### Common Issues

#### API Key Issues
```
Error: Invalid Shodan API key
Solution: Verify your API key at https://www.shodan.io/
```

#### Rate Limit Exceeded
```
Error: Shodan rate limit exceeded
Solution: Wait for rate limit reset or upgrade your plan
```

#### No Data Found
```
Warning: No Shodan data available for host
Solution: This is normal - not all hosts are in Shodan's database
```

### Debug Mode

Enable debug logging for troubleshooting:

```python
import logging
logging.getLogger('tools.shodan_client').setLevel(logging.DEBUG)
```

### API Status Check

```python
client = ShodanClient("your_key")
api_info = client.get_api_info()
print(f"Plan: {api_info['plan']}")
print(f"Credits: {client.get_remaining_credits()}")
```

## Limitations

### Free Account Limits
- 100 API queries per month
- No search functionality
- Limited historical data access

### Paid Account Benefits
- Higher query limits (1,000-10,000+ per month)
- Full search capabilities
- Historical data access
- Priority support

### Technical Limitations
- Not all hosts are in Shodan's database
- Data may be outdated for some hosts
- Rate limiting applies to all operations
- Network connectivity required

## Integration Roadmap

### Current Features ✅
- [x] Host information lookup
- [x] Vulnerability assessment integration
- [x] Passive service detection
- [x] HTML report integration
- [x] Configuration management
- [x] Rate limiting and caching

### Planned Features 🚧
- [ ] Real-time monitoring alerts
- [ ] Custom vulnerability rules
- [ ] Advanced search filters
- [ ] Bulk organization analysis
- [ ] Integration with other threat intel sources
- [ ] Machine learning threat scoring

### Future Enhancements 🔮
- [ ] Mobile app integration
- [ ] Cloud deployment templates
- [ ] Enterprise dashboard features
- [ ] Custom API endpoints
- [ ] Advanced analytics and reporting

## Support and Resources

### Documentation
- [Shodan API Documentation](https://developer.shodan.io/)
- [Ginger Scan Documentation](../README.md)
- [Configuration Reference](../config/default.yaml)

### Examples
- [Basic Integration Example](../examples/shodan_integration_example.py)
- [Advanced Usage Patterns](../examples/)
- [Web Dashboard Demo](../tools/web_dashboard.py)

### Community
- [GitHub Issues](https://github.com/mrxcherif/gingerscan/issues)
- [Discussion Forum](https://github.com/mrxcherif/gingerscan/discussions)
- [Security Reports](mailto:mrxcherif@hotmail.com)

## License and Legal

### Usage Terms
- Respect Shodan's Terms of Service
- Follow responsible disclosure practices
- Obtain proper authorization before scanning
- Comply with local and international laws

### Data Privacy
- Shodan data is publicly available information
- Be mindful of sensitive target information
- Follow your organization's data handling policies
- Consider data retention and disposal requirements

---

**⚠️ Security Notice**: This tool is for authorized security testing only. Always ensure you have permission to scan target networks. The authors are not responsible for any misuse of this software.
