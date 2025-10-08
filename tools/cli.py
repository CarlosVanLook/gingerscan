"""
Command Line Interface

Provides a rich CLI interface for network scanning:
- Colorized output with rich
- Progress bars and status indicators
- Interactive configuration
- Multiple output formats
"""

import asyncio
import argparse
import sys
from typing import List, Optional
from pathlib import Path
import logging
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.panel import Panel
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    logging.warning("Rich not available. CLI will use basic output.")

from .scanner import PortScanner, ScanConfig, ScanType
from .parser import OutputParser
from .reporter import ReportGenerator, ReportConfig
from .vuln_checks import VulnerabilityChecker, VulnCheckConfig

logger = logging.getLogger(__name__)


class NetworkToolsCLI:
    """Command line interface for network tools."""
    
    def __init__(self):
        self.console = Console() if RICH_AVAILABLE else None
        self.parser = None
        self.scanner = None
        self.results = []
    
    def run(self, args: Optional[List[str]] = None):
        """Run the CLI with given arguments."""
        parser = self._create_parser()
        args = parser.parse_args(args)
        
        # Configure logging
        verbose = getattr(args, 'verbose', False)
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Run the appropriate command
        if args.command == "scan":
            asyncio.run(self._run_scan(args))
        elif args.command == "parse":
            self._run_parse(args)
        elif args.command == "report":
            self._run_report(args)
        elif args.command == "vuln":
            asyncio.run(self._run_vuln_check(args))
        elif args.command == "web":
            self._run_web_dashboard(args)
        else:
            parser.print_help()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser."""
        parser = argparse.ArgumentParser(
            description="Ginger Scan - Comprehensive network scanning and analysis toolkit",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s scan --target 192.168.1.1 --ports 1-1000
  %(prog)s scan --target 192.168.1.0/24 --ports 22,80,443 --banner --discover
  %(prog)s scan --target example.com --ports 1-1000 --comprehensive --output results.json --format json
  %(prog)s scan --target 192.168.1.1 --ports 1-65535 --comprehensive --scan-type tcp_syn
  %(prog)s parse --input results.json --format json --output parsed.csv
  %(prog)s report --input results.json --output report.html --format html
  %(prog)s vuln --input results.json --output vulnerabilities.json
  %(prog)s web --host 0.0.0.0 --port 8000
            """
        )
        
        subparsers = parser.add_subparsers(dest="command", help="Available commands")
        
        # Scan command
        scan_parser = subparsers.add_parser("scan", help="Perform network scan")
        scan_parser.add_argument("--target", "-t", required=True, help="Target host or network")
        scan_parser.add_argument("--ports", "-p", default="1-1000", help="Port range or list (e.g., 1-1000, 22,80,443)")
        scan_parser.add_argument("--scan-type", "-s", choices=["tcp_connect", "tcp_syn", "udp"], 
                               default="tcp_connect", help="Type of scan to perform")
        scan_parser.add_argument("--timeout", default=3.0, type=float, help="Connection timeout")
        scan_parser.add_argument("--rate-limit", default=100, type=int, help="Ports per second")
        scan_parser.add_argument("--threads", default=50, type=int, help="Number of concurrent threads")
        scan_parser.add_argument("--banner", action="store_true", help="Enable banner grabbing")
        scan_parser.add_argument("--discover", action="store_true", help="Enable host discovery")
        scan_parser.add_argument("--os-detection", action="store_true", help="Enable OS detection")
        scan_parser.add_argument("--ip-info", action="store_true", help="Enable IP information gathering (hostname, geolocation, ASN)")
        scan_parser.add_argument("--vuln-check", action="store_true", help="Enable vulnerability checks")
        scan_parser.add_argument("--comprehensive", action="store_true", help="Enable all features (banner, discover, os-detection, ip-info, vuln-check)")
        scan_parser.add_argument("--all", "-a", action="store_true", help="Alias for --comprehensive: enable all features")
        scan_parser.add_argument("--output", "-o", help="Output file")
        scan_parser.add_argument("--format", choices=["json", "csv", "txt", "xml"], 
                               default="txt", help="Output format")
        scan_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
        scan_parser.add_argument("--scan-id", help="Scan ID for dashboard integration (if not provided, one will be generated)")
        
        # Parse command
        parse_parser = subparsers.add_parser("parse", help="Parse scan results")
        parse_parser.add_argument("--input", "-i", required=True, help="Input file")
        parse_parser.add_argument("--format", choices=["json", "csv", "txt", "xml"], 
                                default="json", help="Input format")
        parse_parser.add_argument("--output", "-o", help="Output file")
        parse_parser.add_argument("--output-format", choices=["json", "csv", "txt", "xml"], 
                                default="json", help="Output format")
        
        # Report command
        report_parser = subparsers.add_parser("report", help="Generate reports")
        report_parser.add_argument("--input", "-i", required=True, help="Input file")
        report_parser.add_argument("--format", choices=["json", "csv", "txt", "xml"], 
                                 default="json", help="Input format")
        report_parser.add_argument("--output", "-o", required=True, help="Output file")
        report_parser.add_argument("--report-format", choices=["html", "pdf"], 
                                 default="html", help="Report format")
        report_parser.add_argument("--title", default="Network Scan Report", help="Report title")
        
        # Vulnerability check command
        vuln_parser = subparsers.add_parser("vuln", help="Check vulnerabilities")
        vuln_parser.add_argument("--input", "-i", required=True, help="Input file")
        vuln_parser.add_argument("--format", choices=["json", "csv", "txt", "xml"], 
                               default="json", help="Input format")
        vuln_parser.add_argument("--output", "-o", help="Output file")
        vuln_parser.add_argument("--shodan-key", help="Shodan API key")
        vuln_parser.add_argument("--check-ftp", action="store_true", help="Check FTP vulnerabilities")
        vuln_parser.add_argument("--check-ssl", action="store_true", help="Check SSL vulnerabilities")
        
        # Web dashboard command
        web_parser = subparsers.add_parser("web", help="Start web dashboard")
        web_parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
        web_parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
        
        return parser
    
    async def _run_scan(self, args):
        """Run network scan."""
        import requests
        import random
        import string
        import time
        if self.console:
            self.console.print(Panel.fit("Network Scanner", style="bold blue"))
        
        # Parse ports
        ports = self._parse_ports(args.ports)
        
        # Handle comprehensive argument (support --all alias)
        comprehensive_enabled = bool(getattr(args, "comprehensive", False) or getattr(args, "all", False))
        banner_grab = args.banner or comprehensive_enabled
        host_discovery = args.discover or comprehensive_enabled
        os_detection = args.os_detection or comprehensive_enabled
        ip_info = args.ip_info or comprehensive_enabled
        vuln_check = args.vuln_check or comprehensive_enabled
        
        # Scan ID logic
        scan_id = getattr(args, "scan_id", None)
        if not scan_id:
            # Generate a random scan ID similar to dashboard style
            unique_id = ''.join(random.choices(string.digits, k=6))
            scan_id = f"scan_{args.target.replace('.', '_').replace('/', '_')}_{unique_id}"
        
        # Optionally: Register scan with dashboard (not required for polling, but could be added)
        dashboard_url = "http://localhost:8000"  # Default dashboard URL
        
        config = ScanConfig(
            targets=[args.target],
            ports=ports,
            scan_type=ScanType(args.scan_type),
            timeout=args.timeout,
            rate_limit=args.rate_limit,
            threads=args.threads,
            banner_grab=banner_grab,
            host_discovery=host_discovery,
            os_detection=os_detection,
            ip_info=ip_info,
            verbose=args.verbose
        )
        
        # Run scan with progress bar
        if self.console:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=self.console
            ) as progress:
                task = progress.add_task("Scanning...", total=100)
                
                # Start scan
                scanner = PortScanner(config)
                self.scanner = scanner
                
                # Update progress periodically
                async def update_progress():
                    while not progress.finished:
                        if scanner.results:
                            progress.update(task, completed=min(len(scanner.results), 100))
                        await asyncio.sleep(0.1)
                
                # Poll dashboard for stop request
                async def poll_dashboard_stop():
                    while not progress.finished:
                        try:
                            resp = requests.get(f"{dashboard_url}/api/scan/{scan_id}/status", timeout=2)
                            if resp.status_code == 200:
                                status = resp.json().get("status", "")
                                if status == "stopped":
                                    if self.console:
                                        self.console.print(f"[red]Scan stopped by dashboard![/red]")
                                    scanner.cancel()
                                    break
                        except Exception:
                            pass
                        await asyncio.sleep(2)
                
                # Run scan, progress, and dashboard polling concurrently
                scan_task = asyncio.create_task(scanner.scan())
                progress_task = asyncio.create_task(update_progress())
                poll_task = asyncio.create_task(poll_dashboard_stop())
                
                self.results = await scan_task
                progress_task.cancel()
                poll_task.cancel()
                progress.update(task, completed=100)
        else:
            # Basic output without rich
            print("Starting scan...")
            scanner = PortScanner(config)
            self.scanner = scanner
            # Poll dashboard for stop request in background
            import threading
            stop_flag = {"stopped": False}
            def poll_dashboard_stop_basic():
                while not stop_flag["stopped"]:
                    try:
                        resp = requests.get(f"{dashboard_url}/api/scan/{scan_id}/status", timeout=2)
                        if resp.status_code == 200:
                            status = resp.json().get("status", "")
                            if status == "stopped":
                                print("Scan stopped by dashboard!")
                                scanner.cancel()
                                stop_flag["stopped"] = True
                                break
                    except Exception:
                        pass
                    time.sleep(2)
            poll_thread = threading.Thread(target=poll_dashboard_stop_basic, daemon=True)
            poll_thread.start()
            self.results = await scanner.scan()
            stop_flag["stopped"] = True
        
        # Display results
        self._display_results()
        
        # Vulnerability checks
        if vuln_check:
            await self._run_vulnerability_checks()
        
        # Save results
        if args.output:
            self._save_results(args.output, args.format)
    
    def _parse_ports(self, ports_str: str) -> List:
        """Parse port string into list of ports and ranges."""
        ports = []
        for port_str in ports_str.split(","):
            port_str = port_str.strip()
            if "-" in port_str:
                start, end = map(int, port_str.split("-"))
                ports.append((start, end))
            else:
                ports.append(int(port_str))
        return ports
    
    def _display_results(self):
        """Display scan results."""
        if not self.results:
            if self.console:
                self.console.print("No results found.", style="yellow")
            else:
                print("No results found.")
            return
        
        # Create results table
        if self.console:
            table = Table(title="Scan Results")
            table.add_column("Host", style="cyan")
            table.add_column("Port", style="magenta")
            table.add_column("Protocol", style="green")
            table.add_column("State", style="bold")
            table.add_column("Service", style="blue")
            table.add_column("Banner", style="dim")
            
            for result in self.results:
                state_style = self._get_state_style(result.state)
                table.add_row(
                    result.host,
                    str(result.port),
                    result.protocol,
                    Text(result.state, style=state_style),
                    result.service or "-",
                    result.banner or "-"
                )
            
            self.console.print(table)
        else:
            # Basic table output
            print(f"\nScan Results ({len(self.results)} ports found):")
            print("-" * 80)
            print(f"{'Host':<15} {'Port':<5} {'Protocol':<8} {'State':<12} {'Service':<15} {'Banner'}")
            print("-" * 80)
            
            for result in self.results:
                service = result.service or "-"
                banner = (result.banner or "-")[:30]
                print(f"{result.host:<15} {result.port:<5} {result.protocol:<8} {result.state:<12} {service:<15} {banner}")
    
    def _get_state_style(self, state: str) -> str:
        """Get color style for port state."""
        if state == "open":
            return "green"
        elif state == "closed":
            return "red"
        elif state in ["filtered", "open|filtered"]:
            return "yellow"
        else:
            return "white"
    
    async def _run_vulnerability_checks(self):
        """Run vulnerability checks."""
        if not self.results:
            return
        
        if self.console:
            self.console.print("\n[bold yellow]Running vulnerability checks...[/bold yellow]")
        
        # Convert results to ParsedScanResult objects
        from .parser import ParsedScanResult
        parsed_results = []
        for result in self.results:
            parsed_result = ParsedScanResult(
                host=result.host,
                port=result.port,
                protocol=result.protocol,
                state=result.state,
                service=result.service,
                banner=result.banner,
                version=result.version,
                response_time=result.response_time,
                scan_type=result.scan_type.value if result.scan_type else None,
                timestamp=None
            )
            parsed_results.append(parsed_result)
        
        # Run vulnerability checks
        vuln_checker = VulnerabilityChecker()
        vulnerabilities = await vuln_checker.check_vulnerabilities(parsed_results)
        
        if vulnerabilities:
            self._display_vulnerabilities(vulnerabilities)
        else:
            if self.console:
                self.console.print("No vulnerabilities found.", style="green")
            else:
                print("No vulnerabilities found.")
    
    def _display_vulnerabilities(self, vulnerabilities):
        """Display vulnerability results."""
        if self.console:
            table = Table(title="Vulnerabilities Found")
            table.add_column("Host", style="cyan")
            table.add_column("Port", style="magenta")
            table.add_column("Service", style="green")
            table.add_column("Type", style="bold")
            table.add_column("Severity", style="bold")
            table.add_column("Description", style="dim")
            
            for vuln in vulnerabilities:
                severity_style = self._get_severity_style(vuln.severity)
                table.add_row(
                    vuln.host,
                    str(vuln.port),
                    vuln.service,
                    vuln.vuln_type,
                    Text(vuln.severity.upper(), style=severity_style),
                    vuln.description
                )
            
            self.console.print(table)
        else:
            print(f"\nVulnerabilities Found ({len(vulnerabilities)}):")
            print("-" * 100)
            print(f"{'Host':<15} {'Port':<5} {'Service':<10} {'Type':<25} {'Severity':<10} {'Description'}")
            print("-" * 100)
            
            for vuln in vulnerabilities:
                print(f"{vuln.host:<15} {vuln.port:<5} {vuln.service:<10} {vuln.vuln_type:<25} {vuln.severity:<10} {vuln.description}")
    
    def _get_severity_style(self, severity: str) -> str:
        """Get color style for vulnerability severity."""
        if severity == "critical":
            return "bold red"
        elif severity == "high":
            return "red"
        elif severity == "medium":
            return "yellow"
        else:
            return "green"
    
    def _save_results(self, output_path: str, format: str):
        """Save results to file."""
        try:
            # Create parser and convert results
            parser = OutputParser()
            from .parser import ParsedScanResult
            
            parsed_results = []
            for result in self.results:
                parsed_result = ParsedScanResult(
                    host=result.host,
                    port=result.port,
                    protocol=result.protocol,
                    state=result.state,
                    service=result.service,
                    banner=result.banner,
                    version=result.version,
                    response_time=result.response_time,
                    scan_type=result.scan_type.value if result.scan_type else None,
                    timestamp=None
                )
                parsed_results.append(parsed_result)
            
            parser.results = parsed_results
            
            # Export in requested format
            if format == "json":
                content = parser.export_json()
            elif format == "csv":
                content = parser.export_csv()
            elif format == "xml":
                content = parser.export_nmap_xml()
            else:  # txt
                content = self._format_text_results()
            
            # Save to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            if self.console:
                self.console.print(f"Results saved to {output_path}", style="green")
            else:
                print(f"Results saved to {output_path}")
                
        except Exception as e:
            if self.console:
                self.console.print(f"Error saving results: {e}", style="red")
            else:
                print(f"Error saving results: {e}")
    
    def _format_text_results(self) -> str:
        """Format results as text."""
        output = f"Network Scan Results\n"
        output += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        output += f"Total ports: {len(self.results)}\n"
        output += f"Open ports: {len([r for r in self.results if r.state == 'open'])}\n\n"
        
        output += f"{'Host':<15} {'Port':<5} {'Protocol':<8} {'State':<12} {'Service':<15} {'Banner'}\n"
        output += "-" * 80 + "\n"
        
        for result in self.results:
            service = result.service or "-"
            banner = result.banner or "-"
            output += f"{result.host:<15} {result.port:<5} {result.protocol:<8} {result.state:<12} {service:<15} {banner}\n"
        
        return output
    
    def _run_parse(self, args):
        """Run parsing command."""
        if self.console:
            self.console.print(Panel.fit("Result Parser", style="bold blue"))
        
        try:
            # Load input file
            with open(args.input, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse based on format
            parser = OutputParser()
            if args.format == "json":
                results = parser.parse_json(content)
            elif args.format == "csv":
                results = parser.parse_csv(content)
            elif args.format == "xml":
                results = parser.parse_nmap_xml(content)
            else:  # txt
                results = parser.parse_text(content)
            
            # Display statistics
            stats = parser.get_statistics()
            if self.console:
                table = Table(title="Parse Statistics")
                table.add_column("Metric", style="cyan")
                table.add_column("Value", style="magenta")
                
                for key, value in stats.items():
                    table.add_row(key.replace('_', ' ').title(), str(value))
                
                self.console.print(table)
            else:
                print("Parse Statistics:")
                for key, value in stats.items():
                    print(f"  {key.replace('_', ' ').title()}: {value}")
            
            # Save if output specified
            if args.output:
                if args.output_format == "json":
                    content = parser.export_json()
                elif args.output_format == "csv":
                    content = parser.export_csv()
                elif args.output_format == "xml":
                    content = parser.export_nmap_xml()
                else:  # txt
                    content = self._format_parsed_results(results)
                
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                if self.console:
                    self.console.print(f"Parsed results saved to {args.output}", style="green")
                else:
                    print(f"Parsed results saved to {args.output}")
        
        except Exception as e:
            if self.console:
                self.console.print(f"Error parsing file: {e}", style="red")
            else:
                print(f"Error parsing file: {e}")
    
    def _format_parsed_results(self, results) -> str:
        """Format parsed results as text."""
        output = f"Parsed Results\n"
        output += f"Total results: {len(results)}\n\n"
        
        for result in results:
            output += f"Host: {result.host}, Port: {result.port}, Protocol: {result.protocol}, State: {result.state}\n"
            if result.service:
                output += f"  Service: {result.service}\n"
            if result.banner:
                output += f"  Banner: {result.banner}\n"
            output += "\n"
        
        return output
    
    def _run_report(self, args):
        """Run report generation command."""
        if self.console:
            self.console.print(Panel.fit("Report Generator", style="bold blue"))
        
        try:
            # Load and parse input file
            with open(args.input, 'r', encoding='utf-8') as f:
                content = f.read()
            
            parser = OutputParser()
            if args.format == "json":
                results = parser.parse_json(content)
            elif args.format == "csv":
                results = parser.parse_csv(content)
            elif args.format == "xml":
                results = parser.parse_nmap_xml(content)
            else:  # txt
                results = parser.parse_text(content)
            
            # Generate report
            config = ReportConfig(title=args.title)
            reporter = ReportGenerator(parser, config)
            
            success = reporter.save_report(args.output, args.report_format)
            
            if success:
                if self.console:
                    self.console.print(f"Report generated: {args.output}", style="green")
                else:
                    print(f"Report generated: {args.output}")
            else:
                if self.console:
                    self.console.print("Failed to generate report", style="red")
                else:
                    print("Failed to generate report")
        
        except Exception as e:
            if self.console:
                self.console.print(f"Error generating report: {e}", style="red")
            else:
                print(f"Error generating report: {e}")
    
    async def _run_vuln_check(self, args):
        """Run vulnerability check command."""
        if self.console:
            self.console.print(Panel.fit("Vulnerability Checker", style="bold blue"))
        
        try:
            # Load and parse input file
            with open(args.input, 'r', encoding='utf-8') as f:
                content = f.read()
            
            parser = OutputParser()
            if args.format == "json":
                results = parser.parse_json(content)
            elif args.format == "csv":
                results = parser.parse_csv(content)
            elif args.format == "xml":
                results = parser.parse_nmap_xml(content)
            else:  # txt
                results = parser.parse_text(content)
            
            # Run vulnerability checks
            config = VulnCheckConfig(
                check_anonymous_ftp=args.check_ftp,
                check_ssl_certificates=args.check_ssl,
                shodan_api_key=args.shodan_key
            )
            
            vuln_checker = VulnerabilityChecker(config)
            vulnerabilities = await vuln_checker.check_vulnerabilities(results)
            
            if vulnerabilities:
                self._display_vulnerabilities(vulnerabilities)
            else:
                if self.console:
                    self.console.print("No vulnerabilities found.", style="green")
                else:
                    print("No vulnerabilities found.")
            
            # Save if output specified
            if args.output:
                content = vuln_checker.export_vulnerabilities_json()
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                if self.console:
                    self.console.print(f"Vulnerabilities saved to {args.output}", style="green")
                else:
                    print(f"Vulnerabilities saved to {args.output}")
        
        except Exception as e:
            if self.console:
                self.console.print(f"Error checking vulnerabilities: {e}", style="red")
            else:
                print(f"Error checking vulnerabilities: {e}")
    
    def _run_web_dashboard(self, args):
        """Run web dashboard."""
        try:
            from .web_dashboard import WebDashboard
            dashboard = WebDashboard()
            
            if self.console:
                self.console.print(f"Starting web dashboard on {args.host}:{args.port}", style="green")
                self.console.print(f"Access the dashboard at: http://{args.host}:{args.port}", style="cyan")
            else:
                print(f"Starting web dashboard on {args.host}:{args.port}")
                print(f"Access the dashboard at: http://{args.host}:{args.port}")
            
            dashboard.run(host=args.host, port=args.port)
        
        except ImportError:
            if self.console:
                self.console.print("Web dashboard requires FastAPI. Install with: pip install fastapi uvicorn", style="red")
            else:
                print("Web dashboard requires FastAPI. Install with: pip install fastapi uvicorn")
        except Exception as e:
            if self.console:
                self.console.print(f"Error starting web dashboard: {e}", style="red")
            else:
                print(f"Error starting web dashboard: {e}")


def main():
    """Main entry point for CLI."""
    cli = NetworkToolsCLI()
    cli.run()


if __name__ == "__main__":
    main()
