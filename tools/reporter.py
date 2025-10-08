"""
Report Generator Module

Provides comprehensive reporting capabilities:
- HTML reports with charts and tables
- PDF report generation
- Data visualization with matplotlib/plotly
- Custom report templates
"""

import json
import base64
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import logging

try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    logging.warning("Matplotlib not available. Chart generation will be disabled.")

try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.offline import plot
    import plotly.utils
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    logging.warning("Plotly not available. Interactive charts will be disabled.")

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logging.warning("ReportLab not available. PDF generation will be disabled.")

from .parser import OutputParser, ParsedScanResult

logger = logging.getLogger(__name__)


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    title: str = "Network Scan Report"
    author: str = "Ginger Scan"
    include_charts: bool = True
    include_tables: bool = True
    include_summary: bool = True
    chart_theme: str = "plotly_white"
    output_format: str = "html"  # html, pdf, both


class ReportGenerator:
    """Generate comprehensive reports from scan results."""
    
    def __init__(self, parser: OutputParser, config: Optional[ReportConfig] = None):
        self.parser = parser
        self.config = config or ReportConfig()
        self.results = parser.results
        self.metadata = parser.metadata
    
    def generate_html_report(self) -> str:
        """Generate HTML report with charts and tables."""
        html_content = self._generate_html_template()
        
        # Add charts if available
        if self.config.include_charts and PLOTLY_AVAILABLE:
            charts_html = self._generate_charts_html()
            html_content = html_content.replace("<!-- CHARTS_PLACEHOLDER -->", charts_html)
        
        # Add tables
        if self.config.include_tables:
            tables_html = self._generate_tables_html()
            html_content = html_content.replace("<!-- TABLES_PLACEHOLDER -->", tables_html)
        
        # Add summary
        if self.config.include_summary:
            summary_html = self._generate_summary_html()
            html_content = html_content.replace("<!-- SUMMARY_PLACEHOLDER -->", summary_html)
        
        # Add Shodan intelligence section
        shodan_html = self._generate_shodan_intelligence_html()
        if shodan_html:
            html_content = html_content.replace("<!-- SHODAN_PLACEHOLDER -->", shodan_html)
        else:
            html_content = html_content.replace("<!-- SHODAN_PLACEHOLDER -->", "")
        
        return html_content
    
    def _generate_html_template(self) -> str:
        """Generate basic HTML template."""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.config.title}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 2px solid #007acc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #007acc;
            margin: 0;
            font-size: 2.5em;
        }}
        .header p {{
            color: #666;
            margin: 10px 0 0 0;
        }}
        .section {{
            margin: 30px 0;
        }}
        .section h2 {{
            color: #333;
            border-left: 4px solid #007acc;
            padding-left: 15px;
            margin-bottom: 20px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }}
        .stat-card h3 {{
            margin: 0 0 10px 0;
            font-size: 2em;
        }}
        .stat-card p {{
            margin: 0;
            opacity: 0.9;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #007acc;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
        .status-open {{
            color: #28a745;
            font-weight: bold;
        }}
        .status-closed {{
            color: #dc3545;
        }}
        .status-filtered {{
            color: #ffc107;
        }}
        .chart-container {{
            margin: 20px 0;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
        }}
    </style>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{self.config.title}</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Author: {self.config.author}</p>
        </div>
        
        <!-- SUMMARY_PLACEHOLDER -->
        
        <!-- SHODAN_PLACEHOLDER -->
        
        <!-- CHARTS_PLACEHOLDER -->
        
        <!-- TABLES_PLACEHOLDER -->
        
        <div class="footer">
            <p>Report generated by Ginger Scan v1.0.0</p>
        </div>
    </div>
</body>
</html>
        """
    
    def _generate_summary_html(self) -> str:
        """Generate summary section HTML."""
        stats = self.parser.get_statistics()
        
        return f"""
        <div class="section">
            <h2>Scan Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>{stats['total_ports']}</h3>
                    <p>Total Ports Scanned</p>
                </div>
                <div class="stat-card">
                    <h3>{stats['open_ports']}</h3>
                    <p>Open Ports</p>
                </div>
                <div class="stat-card">
                    <h3>{stats['hosts']}</h3>
                    <p>Hosts Scanned</p>
                </div>
                <div class="stat-card">
                    <h3>{len(stats['services'])}</h3>
                    <p>Services Found</p>
                </div>
            </div>
        </div>
        """
    
    def _generate_charts_html(self) -> str:
        """Generate charts section HTML."""
        if not PLOTLY_AVAILABLE:
            return "<div class='section'><h2>Charts</h2><p>Charts require Plotly to be installed.</p></div>"
        
        charts_html = "<div class='section'><h2>Charts</h2>"
        
        # Port distribution chart
        port_chart = self._create_port_distribution_chart()
        if port_chart:
            charts_html += f"<div class='chart-container'>{port_chart}</div>"
        
        # Service distribution chart
        service_chart = self._create_service_distribution_chart()
        if service_chart:
            charts_html += f"<div class='chart-container'>{service_chart}</div>"
        
        # Host activity chart
        host_chart = self._create_host_activity_chart()
        if host_chart:
            charts_html += f"<div class='chart-container'>{host_chart}</div>"
        
        charts_html += "</div>"
        return charts_html
    
    def _create_port_distribution_chart(self) -> Optional[str]:
        """Create port distribution chart."""
        try:
            # Group ports by range
            port_ranges = {
                "1-1023": 0,
                "1024-49151": 0,
                "49152-65535": 0
            }
            
            for result in self.results:
                if result.state == "open":
                    if 1 <= result.port <= 1023:
                        port_ranges["1-1023"] += 1
                    elif 1024 <= result.port <= 49151:
                        port_ranges["1024-49151"] += 1
                    else:
                        port_ranges["49152-65535"] += 1
            
            fig = go.Figure(data=[go.Bar(
                x=list(port_ranges.keys()),
                y=list(port_ranges.values()),
                marker_color=['#FF6B6B', '#4ECDC4', '#45B7D1']
            )])
            
            fig.update_layout(
                title="Open Ports by Range",
                xaxis_title="Port Range",
                yaxis_title="Number of Open Ports",
                template=self.config.chart_theme
            )
            
            return plot(fig, output_type='div', include_plotlyjs=False)
        except Exception as e:
            logger.error(f"Error creating port distribution chart: {e}")
            return None
    
    def _create_service_distribution_chart(self) -> Optional[str]:
        """Create service distribution chart."""
        try:
            services = self.parser.get_service_summary()
            if not services:
                return None
            
            # Get top 10 services
            top_services = dict(sorted(services.items(), key=lambda x: x[1], reverse=True)[:10])
            
            fig = go.Figure(data=[go.Pie(
                labels=list(top_services.keys()),
                values=list(top_services.values()),
                hole=0.3
            )])
            
            fig.update_layout(
                title="Top Services Distribution",
                template=self.config.chart_theme
            )
            
            return plot(fig, output_type='div', include_plotlyjs=False)
        except Exception as e:
            logger.error(f"Error creating service distribution chart: {e}")
            return None
    
    def _create_host_activity_chart(self) -> Optional[str]:
        """Create host activity chart."""
        try:
            hosts = self.parser.get_ports_by_host()
            host_names = list(hosts.keys())
            open_port_counts = [len([r for r in results if r.state == "open"]) for results in hosts.values()]
            
            fig = go.Figure(data=[go.Bar(
                x=host_names,
                y=open_port_counts,
                marker_color='#28a745'
            )])
            
            fig.update_layout(
                title="Open Ports per Host",
                xaxis_title="Host",
                yaxis_title="Number of Open Ports",
                template=self.config.chart_theme
            )
            
            return plot(fig, output_type='div', include_plotlyjs=False)
        except Exception as e:
            logger.error(f"Error creating host activity chart: {e}")
            return None
    
    def _generate_tables_html(self) -> str:
        """Generate tables section HTML."""
        tables_html = "<div class='section'><h2>Detailed Results</h2>"
        
        # Open ports table
        open_ports = self.parser.get_open_ports()
        if open_ports:
            tables_html += "<h3>Open Ports</h3>"
            tables_html += self._create_ports_table(open_ports)
        
        # All results table
        tables_html += "<h3>All Results</h3>"
        tables_html += self._create_ports_table(self.results)
        
        tables_html += "</div>"
        return tables_html
    
    def _create_ports_table(self, results: List[ParsedScanResult]) -> str:
        """Create HTML table for port results."""
        table_html = """
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Banner</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for result in results:
            state_class = f"status-{result.state.replace('|', '-')}"
            table_html += f"""
                <tr>
                    <td>{result.host}</td>
                    <td>{result.port}</td>
                    <td>{result.protocol}</td>
                    <td class="{state_class}">{result.state}</td>
                    <td>{result.service or '-'}</td>
                    <td>{result.banner or '-'}</td>
                </tr>
            """
        
        table_html += """
            </tbody>
        </table>
        """
        
        return table_html
    
    def generate_pdf_report(self, output_path: str) -> bool:
        """Generate PDF report."""
        if not REPORTLAB_AVAILABLE:
            logger.error("ReportLab not available. Cannot generate PDF report.")
            return False
        
        try:
            doc = SimpleDocTemplate(output_path, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                alignment=TA_CENTER
            )
            story.append(Paragraph(self.config.title, title_style))
            story.append(Spacer(1, 12))
            
            # Metadata
            story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            story.append(Paragraph(f"Author: {self.config.author}", styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Summary
            if self.config.include_summary:
                story.append(Paragraph("Scan Summary", styles['Heading2']))
                stats = self.parser.get_statistics()
                
                summary_data = [
                    ['Metric', 'Value'],
                    ['Total Ports Scanned', str(stats['total_ports'])],
                    ['Open Ports', str(stats['open_ports'])],
                    ['Hosts Scanned', str(stats['hosts'])],
                    ['Services Found', str(len(stats['services']))]
                ]
                
                summary_table = Table(summary_data)
                summary_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 14),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(summary_table)
                story.append(Spacer(1, 20))
            
            # Open ports table
            if self.config.include_tables:
                story.append(Paragraph("Open Ports", styles['Heading2']))
                open_ports = self.parser.get_open_ports()
                
                if open_ports:
                    table_data = [['Host', 'Port', 'Protocol', 'State', 'Service', 'Banner']]
                    for result in open_ports[:50]:  # Limit to first 50 for PDF
                        table_data.append([
                            result.host,
                            str(result.port),
                            result.protocol,
                            result.state,
                            result.service or '-',
                            (result.banner or '-')[:50]  # Truncate banner
                        ])
                    
                    ports_table = Table(table_data)
                    ports_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('FONTSIZE', (0, 1), (-1, -1), 8)
                    ]))
                    
                    story.append(ports_table)
                else:
                    story.append(Paragraph("No open ports found.", styles['Normal']))
            
            # Build PDF
            doc.build(story)
            logger.info(f"PDF report generated: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            return False
    
    def save_report(self, output_path: str, format: str = "html") -> bool:
        """Save report to file."""
        try:
            if format.lower() == "html":
                content = self.generate_html_report()
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                logger.info(f"HTML report saved: {output_path}")
                return True
            
            elif format.lower() == "pdf":
                return self.generate_pdf_report(output_path)
            
            else:
                logger.error(f"Unsupported format: {format}")
                return False
                
        except Exception as e:
            logger.error(f"Error saving report: {e}")
            return False
    
    def _generate_shodan_intelligence_html(self) -> Optional[str]:
        """Generate Shodan intelligence section HTML."""
        shodan_data = self._extract_shodan_data()
        
        if not shodan_data['has_shodan_data']:
            return None
        
        html = f"""
        <div class="section">
            <h2>🔍 Threat Intelligence (Shodan)</h2>
            <div class="stats-grid">
                <div class="stat-card" style="background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);">
                    <h3>{shodan_data['total_vulnerabilities']}</h3>
                    <p>CVEs Found</p>
                </div>
                <div class="stat-card" style="background: linear-gradient(135deg, #feca57 0%, #ff9ff3 100%);">
                    <h3>{shodan_data['hosts_with_data']}</h3>
                    <p>Hosts in Shodan</p>
                </div>
                <div class="stat-card" style="background: linear-gradient(135deg, #48dbfb 0%, #0abde3 100%);">
                    <h3>{shodan_data['unique_organizations']}</h3>
                    <p>Organizations</p>
                </div>
                <div class="stat-card" style="background: linear-gradient(135deg, #1dd1a1 0%, #10ac84 100%);">
                    <h3>{shodan_data['confidence_score']:.1f}%</h3>
                    <p>Avg Confidence</p>
                </div>
            </div>
        """
        
        # Add vulnerability summary if available
        if shodan_data['vulnerabilities']:
            html += """
            <div class="vulnerability-section">
                <h3>🚨 Critical Vulnerabilities</h3>
                <table class="vulnerability-table">
                    <thead>
                        <tr>
                            <th>Host</th>
                            <th>Port</th>
                            <th>CVE</th>
                            <th>CVSS</th>
                            <th>Severity</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for vuln in shodan_data['vulnerabilities'][:10]:  # Show top 10
                severity_color = self._get_severity_color(vuln.get('severity', 'unknown'))
                html += f"""
                        <tr>
                            <td>{vuln.get('host', 'N/A')}</td>
                            <td>{vuln.get('port', 'N/A')}</td>
                            <td><code>{vuln.get('cve', 'N/A')}</code></td>
                            <td>{vuln.get('cvss', 'N/A')}</td>
                            <td><span class="severity-badge" style="background-color: {severity_color};">{vuln.get('severity', 'Unknown')}</span></td>
                            <td>{vuln.get('description', 'N/A')[:100]}...</td>
                        </tr>
                """
            
            html += """
                    </tbody>
                </table>
            </div>
            """
        
        # Add host intelligence summary
        if shodan_data['host_intelligence']:
            html += """
            <div class="host-intelligence-section">
                <h3>🌐 Host Intelligence</h3>
                <table class="host-table">
                    <thead>
                        <tr>
                            <th>Host</th>
                            <th>Organization</th>
                            <th>Country</th>
                            <th>Last Seen</th>
                            <th>Tags</th>
                            <th>Confidence</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for host_info in shodan_data['host_intelligence'][:15]:  # Show top 15
                tags_str = ', '.join(host_info.get('tags', [])[:3])  # Show first 3 tags
                if len(host_info.get('tags', [])) > 3:
                    tags_str += '...'
                
                confidence_color = self._get_confidence_color(host_info.get('confidence', 'unknown'))
                
                html += f"""
                        <tr>
                            <td><code>{host_info.get('ip', 'N/A')}</code></td>
                            <td>{host_info.get('organization', 'N/A')}</td>
                            <td>{host_info.get('country', 'N/A')}</td>
                            <td>{host_info.get('last_update', 'N/A')}</td>
                            <td><small>{tags_str}</small></td>
                            <td><span class="confidence-badge" style="background-color: {confidence_color};">{host_info.get('confidence', 'Unknown')}</span></td>
                        </tr>
                """
            
            html += """
                    </tbody>
                </table>
            </div>
            """
        
        html += """
        </div>
        <style>
            .vulnerability-table, .host-table {
                width: 100%;
                border-collapse: collapse;
                margin: 15px 0;
                font-size: 0.9em;
            }
            .vulnerability-table th, .vulnerability-table td,
            .host-table th, .host-table td {
                padding: 8px 12px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }
            .vulnerability-table th, .host-table th {
                background-color: #f8f9fa;
                font-weight: bold;
            }
            .severity-badge, .confidence-badge {
                padding: 2px 8px;
                border-radius: 12px;
                color: white;
                font-size: 0.8em;
                font-weight: bold;
            }
            .vulnerability-section, .host-intelligence-section {
                margin: 25px 0;
            }
        </style>
        """
        
        return html
    
    def _extract_shodan_data(self) -> Dict[str, Any]:
        """Extract Shodan data from scan results."""
        shodan_data = {
            'has_shodan_data': False,
            'total_vulnerabilities': 0,
            'hosts_with_data': 0,
            'unique_organizations': 0,
            'confidence_score': 0.0,
            'vulnerabilities': [],
            'host_intelligence': []
        }
        
        organizations = set()
        confidence_scores = []
        
        for result in self.results:
            # Check if result has Shodan data
            has_shodan = False
            
            # Check for Shodan data in service information
            if hasattr(result, 'service_info') and result.service_info:
                if hasattr(result.service_info, 'shodan_data') and result.service_info.shodan_data:
                    has_shodan = True
                    
                    # Extract vulnerabilities
                    if hasattr(result.service_info, 'vulnerabilities') and result.service_info.vulnerabilities:
                        for vuln in result.service_info.vulnerabilities:
                            shodan_data['vulnerabilities'].append({
                                'host': result.host,
                                'port': result.port,
                                'cve': vuln,
                                'cvss': None,  # Would need to be enhanced with actual CVSS data
                                'severity': 'medium',  # Default severity
                                'description': f'Vulnerability {vuln} found via Shodan'
                            })
                            shodan_data['total_vulnerabilities'] += 1
            
            # Check for Shodan data in vulnerability results
            if hasattr(result, 'vulnerabilities'):
                for vuln in result.vulnerabilities:
                    if hasattr(vuln, 'vuln_type') and 'shodan' in vuln.vuln_type.lower():
                        has_shodan = True
                        shodan_data['vulnerabilities'].append({
                            'host': vuln.host,
                            'port': vuln.port,
                            'cve': vuln.cve or 'N/A',
                            'cvss': None,
                            'severity': vuln.severity,
                            'description': vuln.description
                        })
                        shodan_data['total_vulnerabilities'] += 1
            
            # Extract host intelligence from extra_info
            if hasattr(result, 'extra_info') and result.extra_info and 'Shodan:' in result.extra_info:
                has_shodan = True
                shodan_info = result.extra_info.split('Shodan:')[1].strip()
                
                # Parse organization, country, tags from extra_info
                org = country = tags = None
                if 'Org:' in shodan_info:
                    org = shodan_info.split('Org:')[1].split('|')[0].strip()
                    organizations.add(org)
                if 'Country:' in shodan_info:
                    country = shodan_info.split('Country:')[1].split('|')[0].strip()
                if 'Tags:' in shodan_info:
                    tags = [tag.strip() for tag in shodan_info.split('Tags:')[1].split('|')[0].split(',')]
                
                shodan_data['host_intelligence'].append({
                    'ip': result.host,
                    'organization': org,
                    'country': country,
                    'last_update': 'Recent',
                    'tags': tags or [],
                    'confidence': 'high'  # Default confidence
                })
            
            if has_shodan:
                shodan_data['hosts_with_data'] += 1
                confidence_scores.append(0.8)  # Default confidence score
        
        shodan_data['unique_organizations'] = len(organizations)
        shodan_data['confidence_score'] = sum(confidence_scores) / len(confidence_scores) * 100 if confidence_scores else 0
        shodan_data['has_shodan_data'] = shodan_data['hosts_with_data'] > 0
        
        return shodan_data
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for vulnerability severity."""
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745',
            'unknown': '#6c757d'
        }
        return colors.get(severity.lower(), '#6c757d')
    
    def _get_confidence_color(self, confidence: str) -> str:
        """Get color for confidence level."""
        colors = {
            'high': '#28a745',
            'medium': '#ffc107',
            'low': '#fd7e14',
            'unknown': '#6c757d'
        }
        return colors.get(confidence.lower(), '#6c757d')
