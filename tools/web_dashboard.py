"""
Web Dashboard Module

Provides a FastAPI-based web interface for:
- Launching scans
- Viewing results
- Managing configurations
- Real-time monitoring
"""

import asyncio
import json
from typing import List, Dict, Optional, Any
from datetime import datetime
import logging
import warnings

try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    from fastapi.requests import Request
    from fastapi.responses import HTMLResponse, JSONResponse, Response
    from pydantic import BaseModel
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    logging.warning("FastAPI not available. Web dashboard will be disabled.")

from .scanner import PortScanner, ScanConfig, ScanType
from .parser import OutputParser
from .reporter import ReportGenerator, ReportConfig
from .vuln_checks import VulnerabilityChecker, VulnCheckConfig

logger = logging.getLogger(__name__)

# Pydantic models for API
class ScanRequest(BaseModel):
    targets: List[str]
    ports: List[str]  # Will be parsed to int ranges
    scan_type: str = "tcp_connect"
    timeout: float = 3.0
    rate_limit: int = 100
    threads: int = 50
    banner_grab: bool = False
    host_discovery: bool = False
    os_detection: bool = False
    ip_info: bool = False
    vuln_check: bool = False

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    results: Optional[List[Dict]] = None
    vulnerabilities: Optional[List[Dict]] = None
    scan_info: Optional[Dict] = None
    scan_ids: Optional[List[str]] = None  # For multiple scan IDs

class ScanStatus(BaseModel):
    scan_id: str
    status: str  # pending, running, completed, failed
    progress: float
    current_target: Optional[str] = None
    results_count: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error: Optional[str] = None

class WebDashboard:
    """FastAPI web dashboard for network scanning."""
    
    def __init__(self):
        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI is required for web dashboard")
        
        self.app = FastAPI(
            title="Ginger Scan Dashboard",
            description="Web interface for network scanning and analysis",
            version="1.0.0"
        )
        
        self.active_scans: Dict[str, ScanStatus] = {}
        self.scan_results: Dict[str, List[Dict]] = {}
        self.connected_clients: List[WebSocket] = []
        self.scan_tasks: Dict[str, asyncio.Task] = {}  # Track running scan tasks
        self.scanners: Dict[str, 'PortScanner'] = {}  # Track scanner instances for cancellation
        self.scan_configs: Dict[str, Dict] = {}  # Store scan configurations for restart
        self.used_scan_ids: set = set()  # Track used 6-digit IDs to ensure uniqueness
        self.scan_batches: Dict[str, List[str]] = {}  # Track scan batches by batch_id
        
        self._setup_routes()
        self._setup_websocket()
    
    def _generate_unique_scan_id(self) -> str:
        """Generate a unique 6-digit scan ID."""
        import random
        while True:
            # Generate a random 6-digit number
            scan_id = f"{random.randint(100000, 999999)}"
            if scan_id not in self.used_scan_ids:
                self.used_scan_ids.add(scan_id)
                return scan_id
    
    def _setup_routes(self):
        """Setup FastAPI routes."""
        
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard(request: Request):
            """Main dashboard page."""
            return self._get_dashboard_html()
        
        @self.app.get("/assets/logo.png")
        async def get_logo():
            """Serve logo image."""
            import os
            from fastapi.responses import FileResponse
            
            # Try multiple possible paths
            possible_paths = [
                os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "logo.png"),
                os.path.join(os.path.dirname(os.path.dirname(__file__)), "logo.png"),
                "assets/logo.png",
                "logo.png"
            ]
            
            for logo_path in possible_paths:
                if os.path.exists(logo_path):
                    return FileResponse(logo_path, media_type="image/png")
            
            from fastapi.responses import JSONResponse
            return JSONResponse({"error": "Logo not found"}, status_code=404)
        
        @self.app.get("/assets/text.png")
        async def get_text():
            """Serve text image."""
            import os
            from fastapi.responses import FileResponse
            
            # Try multiple possible paths
            possible_paths = [
                os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "text.png"),
                os.path.join(os.path.dirname(os.path.dirname(__file__)), "text.png"),
                "assets/text.png",
                "text.png"
            ]
            
            for text_path in possible_paths:
                if os.path.exists(text_path):
                    return FileResponse(text_path, media_type="image/png")
            
            from fastapi.responses import JSONResponse
            return JSONResponse({"error": "Text image not found"}, status_code=404)
        
        @self.app.post("/api/scan", response_model=ScanResponse)
        async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
            """Start a new scan - creates individual scans for each host."""
            # Parse ports
            ports = []
            for port_str in scan_request.ports:
                if "-" in port_str:
                    start, end = map(int, port_str.split("-"))
                    ports.append((start, end))
                else:
                    ports.append(int(port_str))
            
            # Create individual scans for each target
            created_scans = []
            scan_queue = []  # Queue to manage sequential scanning
            batch_id = datetime.now().strftime('%Y%m%d_%H%M%S')  # Create batch ID
            self.scan_batches[batch_id] = []  # Initialize batch tracking
            
            for i, target in enumerate(scan_request.targets):
                # Generate unique 6-digit scan ID
                unique_id = self._generate_unique_scan_id()
                scan_id = f"scan_{target.replace('.', '_').replace('/', '_')}_{unique_id}"
                logger.info(f"Creating scan {i+1}/{len(scan_request.targets)}: {scan_id} for target {target}")
                
                # Add to batch tracking
                self.scan_batches[batch_id].append(scan_id)
                
                # Create scan configuration for single target
                config = ScanConfig(
                    targets=[target],  # Single target only
                    ports=ports,
                    scan_type=ScanType(scan_request.scan_type),
                    timeout=scan_request.timeout,
                    rate_limit=scan_request.rate_limit,
                    threads=scan_request.threads,
                    banner_grab=scan_request.banner_grab,
                    host_discovery=scan_request.host_discovery,
                    os_detection=scan_request.os_detection,
                    ip_info=scan_request.ip_info,
                    verbose=True
                )
                
                # Initialize scan status
                if i == 0:
                    # First scan starts immediately
                    status = "running"
                else:
                    # Other scans start as pending
                    status = "pending"
                
                self.active_scans[scan_id] = ScanStatus(
                    scan_id=scan_id,
                    status=status,
                    progress=0.0,
                    start_time=datetime.now() if status == "running" else None
                )
                logger.info(f"Initialized scan {scan_id} with status '{status}', start_time: {self.active_scans[scan_id].start_time}")
                
                # Store scan configuration for potential restart
                self.scan_configs[scan_id] = {
                    'config': config,
                    'vuln_check': scan_request.vuln_check
                }
                
                # Add to scan queue
                scan_queue.append({
                    'scan_id': scan_id,
                    'config': config,
                    'vuln_check': scan_request.vuln_check
                })
                
                created_scans.append(scan_id)
            
            # Start the first scan immediately
            if scan_queue:
                first_scan = scan_queue[0]
                task = asyncio.create_task(self._run_scan_with_queue(
                    first_scan['scan_id'], 
                    first_scan['config'], 
                    first_scan['vuln_check'],
                    scan_queue[1:]  # Remaining scans
                ))
                self.scan_tasks[first_scan['scan_id']] = task
            
            # Create professional message based on scan count
            if len(created_scans) == 1:
                message = "Scan started successfully."
            else:
                message = f"Started {len(created_scans)} scans. First scan is running, others are pending."
            
            return ScanResponse(
                scan_id=created_scans[0] if created_scans else None,
                status="started",
                message=message,
                scan_ids=created_scans  # Include all scan IDs in the response
            )
        
        @self.app.get("/api/scan/{scan_id}/status", response_model=ScanStatus)
        async def get_scan_status(scan_id: str):
            """Get scan status."""
            if scan_id not in self.active_scans:
                raise HTTPException(status_code=404, detail="Scan not found")
            
            return self.active_scans[scan_id]
        
        @self.app.get("/api/scan/{scan_id}/results")
        async def get_scan_results(scan_id: str):
            """Get scan results."""
            if scan_id not in self.scan_results:
                raise HTTPException(status_code=404, detail="Results not found")
            
            return self.scan_results[scan_id]
        
        @self.app.get("/api/scans")
        async def list_scans():
            """List all scans."""
            return {
                "active_scans": list(self.active_scans.keys()),
                "completed_scans": list(self.scan_results.keys())
            }
        
        @self.app.post("/api/scan/{scan_id}/stop")
        async def stop_scan(scan_id: str):
            """Stop a running scan and move to next pending scan or finish."""
            if scan_id not in self.active_scans:
                raise HTTPException(status_code=404, detail="Scan not found")
            
            scan_status = self.active_scans[scan_id]
            if scan_status.status not in ["pending", "running"]:
                raise HTTPException(status_code=400, detail="Scan is not running")
            
            # Cancel the current scan task and scanner
            if scan_id in self.scan_tasks:
                self.scan_tasks[scan_id].cancel()
                del self.scan_tasks[scan_id]
            
            # Cancel the scanner instance
            if scan_id in self.scanners:
                self.scanners[scan_id].cancel()
                del self.scanners[scan_id]
            
            # Update current scan status to stopped
            scan_status.status = "stopped"
            scan_status.end_time = datetime.now()
            
            # Generate partial report if we have results for the current scan
            if scan_id in self.scan_results and self.scan_results[scan_id].get("results"):
                results = self.scan_results[scan_id]["results"]
                open_ports = [r for r in results if r.get("state") == "open"]
                scan_status.results_count = len(open_ports)
                scan_status.current_target = f"Stopped - {len(open_ports)} open ports found"
            else:
                scan_status.current_target = "Stopped - no results yet"
                scan_status.results_count = 0
                
                # Create empty results structure for stopped scan
                self.scan_results[scan_id] = {
                    "results": [],
                    "vulnerabilities": [],
                    "scan_info": {
                        "targets": [],
                        "ports": [],
                        "scan_type": "unknown",
                        "banner_grab": False,
                        "host_discovery": False,
                        "start_time": scan_status.start_time.isoformat() if scan_status.start_time else datetime.now().isoformat()
                    }
                }
            
            # Find and start the next pending scan in the same batch
            batch_id = None
            current_index = None
            
            # Find which batch this scan belongs to and its position
            for batch, scan_list in self.scan_batches.items():
                if scan_id in scan_list:
                    batch_id = batch
                    current_index = scan_list.index(scan_id)
                    break
            
            # Find the next pending scan in the same batch
            next_scan_id = None
            if batch_id and current_index is not None:
                for i in range(current_index + 1, len(self.scan_batches[batch_id])):
                    candidate_scan_id = self.scan_batches[batch_id][i]
                    if (candidate_scan_id in self.active_scans and 
                        self.active_scans[candidate_scan_id].status == "pending"):
                        next_scan_id = candidate_scan_id
                        break
            
            # Start the next pending scan if found
            if next_scan_id:
                logger.info(f"Starting next pending scan: {next_scan_id}")
                next_scan_status = self.active_scans[next_scan_id]
                next_scan_status.status = "running"
                next_scan_status.start_time = datetime.now()
                next_scan_status.current_target = "Starting scan..."
                
                # Get the stored configuration for this scan and remaining queue
                if next_scan_id in self.scan_configs:
                    config_data = self.scan_configs[next_scan_id]
                    config = config_data['config']
                    vuln_check = config_data['vuln_check']
                    
                    # Get the remaining queue for this batch (only the scans after the next one)
                    remaining_queue = []
                    if batch_id and current_index is not None:
                        remaining_queue = self.scan_batches[batch_id][current_index + 2:]  # Skip current and next scan
                        # Convert to the format expected by _run_scan_with_queue
                        remaining_queue = [
                            {
                                'scan_id': scan_id,
                                'config': self.scan_configs[scan_id]['config'],
                                'vuln_check': self.scan_configs[scan_id]['vuln_check']
                            }
                            for scan_id in remaining_queue
                            if scan_id in self.scan_configs
                        ]
                    
                    # Create a new scan task for the next scan with queue processing
                    # This ensures only one scan runs at a time with proper queue management
                    task = asyncio.create_task(self._run_scan_with_queue(next_scan_id, config, vuln_check, remaining_queue))
                    self.scan_tasks[next_scan_id] = task
                    logger.info(f"Created scan task for {next_scan_id} with {len(remaining_queue)} remaining scans")
                
                await self._broadcast_update(next_scan_id)
                message = f"Scan stopped. Started next pending scan: {next_scan_id}"
            else:
                message = "Scan stopped. No more pending scans in this group."
            
            # Broadcast update for the stopped scan
            await self._broadcast_update(scan_id)
            
            return {"message": message, "scan_id": scan_id}
        
        # Add route to export scan results in different formats
        @self.app.get("/api/scan/{scan_id}/export")
        async def export_results(scan_id: str, format: str = "csv"):
            """Export scan results in CSV, TXT, PDF, or YAML format."""
            if scan_id not in self.scan_results:
                raise HTTPException(status_code=404, detail="Results not found")
            
            # Get scan data
            scan_data = self.scan_results[scan_id]
            results_list = scan_data.get("results", [])
            vulnerabilities = scan_data.get("vulnerabilities", [])
            os_info = scan_data.get("os_info", {})
            ip_info = scan_data.get("ip_info", {})
            scan_info = scan_data.get("scan_info", {})
            
            # Convert results to ParsedScanResult objects
            results = []
            for result_data in results_list:
                from .parser import ParsedScanResult
                result = ParsedScanResult(
                    host=result_data["host"],
                    port=result_data["port"],
                    protocol=result_data["protocol"],
                    state=result_data["state"],
                    service=result_data.get("service"),
                    banner=result_data.get("banner"),
                    version=result_data.get("version"),
                    response_time=result_data.get("response_time"),
                    scan_type=result_data.get("scan_type"),
                    timestamp=datetime.fromisoformat(result_data["timestamp"]) if result_data.get("timestamp") else None
                )
                results.append(result)
            
            if format == "json":
                return await self._export_json(scan_id, results, vulnerabilities, os_info, ip_info, scan_info)
            elif format == "csv":
                return await self._export_csv(scan_id, results, vulnerabilities, os_info, ip_info, scan_info)
            elif format == "txt":
                return await self._export_txt(scan_id, results, vulnerabilities, os_info, ip_info, scan_info)
            elif format == "pdf":
                return await self._export_pdf(scan_id, results, vulnerabilities, os_info, ip_info, scan_info)
            elif format == "yaml":
                return await self._export_yaml(scan_id, results, vulnerabilities, os_info, ip_info, scan_info)
            elif format == "html":
                return await self._export_html(scan_id, results, vulnerabilities, os_info, ip_info, scan_info)
            else:
                raise HTTPException(status_code=400, detail="Unsupported format. Use 'json', 'csv', 'txt', 'pdf', 'yaml', or 'html'")
        
        @self.app.get("/api/scan/{scan_id}/report")
        async def generate_report(scan_id: str, format: str = "html"):
            """Generate report for scan results."""
            if scan_id not in self.scan_results:
                raise HTTPException(status_code=404, detail="Results not found")
            
            # Convert results to ParsedScanResult objects
            results = []
            scan_data = self.scan_results[scan_id]
            results_list = scan_data.get("results", [])
            
            for result_data in results_list:
                from .parser import ParsedScanResult
                result = ParsedScanResult(
                    host=result_data["host"],
                    port=result_data["port"],
                    protocol=result_data["protocol"],
                    state=result_data["state"],
                    service=result_data.get("service"),
                    banner=result_data.get("banner"),
                    version=result_data.get("version"),
                    response_time=result_data.get("response_time"),
                    scan_type=result_data.get("scan_type"),
                    timestamp=datetime.fromisoformat(result_data["timestamp"]) if result_data.get("timestamp") else None
                )
                results.append(result)
            
            # Create parser and reporter
            parser = OutputParser()
            parser.results = results
            
            # Add vulnerability information to parser if available
            vulnerabilities = scan_data.get("vulnerabilities", [])
            if hasattr(parser, 'vulnerabilities'):
                parser.vulnerabilities = vulnerabilities
            else:
                # Add vulnerabilities as a custom attribute
                parser.vulnerabilities = vulnerabilities
            
            reporter = ReportGenerator(parser)
            
            if format == "html":
                # Generate completely custom HTML report with better structure
                html_content = self._generate_custom_html_report(scan_id, results, vulnerabilities)
                return HTMLResponse(content=html_content)
            elif format == "json":
                # Include vulnerabilities in JSON response
                json_data = json.loads(parser.export_json())
                
                # Add Ginger Scan metadata
                json_data['tool_info'] = {
                    'name': 'Ginger Scan',
                    'version': '1.0.0',
                    'description': 'Comprehensive network scanning and vulnerability assessment platform',
                    'generated_by': 'Ginger Scan Web Dashboard'
                }
                
                json_data['vulnerabilities'] = vulnerabilities
                json_data['scan_info'] = scan_data.get("scan_info", {})
                
                # Include IP info and OS info - convert enums to strings
                ip_info = scan_data.get("ip_info", {})
                os_info = scan_data.get("os_info", {})
                
                # Convert any enum values to strings in ip_info and os_info
                def convert_enums_to_strings(obj):
                    if isinstance(obj, dict):
                        return {str(k): convert_enums_to_strings(v) for k, v in obj.items()}
                    elif isinstance(obj, list):
                        return [convert_enums_to_strings(item) for item in obj]
                    elif hasattr(obj, 'value') and hasattr(obj, '__class__') and hasattr(obj.__class__, '__name__'):  # Enum objects
                        return str(obj.value)
                    elif hasattr(obj, '__class__') and 'Enum' in str(obj.__class__.__bases__):  # Additional enum check
                        return str(obj.value)
                    else:
                        return obj
                
                json_data['ip_info'] = convert_enums_to_strings(ip_info)
                json_data['os_info'] = convert_enums_to_strings(os_info)
                
                return JSONResponse(content=json_data)
            else:
                raise HTTPException(status_code=400, detail="Unsupported format")
    
    def _generate_custom_html_report(self, scan_id, results, vulnerabilities):
        """Generate a completely custom, well-structured HTML report."""
        # Separate results by state
        open_ports = [r for r in results if r.state == "open"]
        closed_ports = [r for r in results if r.state in ["closed", "filtered"]]
        
        # Get scan info
        scan_info = self.scan_results.get(scan_id, {}).get("scan_info", {})
        os_info = self.scan_results.get(scan_id, {}).get("os_info", {})
        scan_start = scan_info.get("start_time", "Unknown")
        targets = scan_info.get("targets", [])
        
        # Generate HTML
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ginger Scan - Network Security Assessment Report - {scan_id}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            line-height: 1.5;
            background: #f8f9fa;
            color: #2c3e50;
            padding: 0;
            margin: 0;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 40px auto;
            background: white;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05), 0 1px 2px rgba(0,0,0,0.1);
            border: 1px solid #e5e7eb;
            width: 100%;
            box-sizing: border-box;
            overflow-x: hidden;
        }}
        
        .header {{
            background: #ffffff;
            border-bottom: 2px solid #e5e7eb;
            padding: 40px 60px;
            text-align: left;
        }}
        
        .header h1 {{
            font-size: 28px;
            margin: 0 0 8px 0;
            font-weight: 600;
            color: #1f2937;
            letter-spacing: -0.025em;
        }}
        
        .header .subtitle {{
            font-size: 14px;
            color: #6b7280;
            margin: 4px 0;
            font-weight: 400;
        }}
        
        .summary-section {{
            padding: 40px 60px;
            background: #ffffff;
            border-bottom: 1px solid #e5e7eb;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .summary-card {{
            background: #ffffff;
            padding: 24px;
            border: 1px solid #e5e7eb;
            text-align: center;
        }}
        
        .summary-card h3 {{
            font-size: 32px;
            color: #1f2937;
            margin: 0 0 8px 0;
            font-weight: 700;
            letter-spacing: -0.025em;
        }}
        
        .summary-card p {{
            color: #6b7280;
            font-weight: 500;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin: 0;
        }}
        
        .section {{
            padding: 40px 60px;
            border-bottom: 1px solid #e5e7eb;
            width: 100%;
            box-sizing: border-box;
            overflow-x: hidden;
            max-width: 100%;
            display: block;
            clear: both;
            position: relative;
        }}
        
        .section h2 {{
            font-size: 18px;
            margin: 0 0 24px 0;
            color: #1f2937;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding-bottom: 12px;
            border-bottom: 1px solid #d1d5db;
        }}
        
        .section h2:before {{
            content: '';
            display: inline-block;
            width: 4px;
            height: 16px;
            background: #6b7280;
            margin-right: 12px;
            vertical-align: middle;
        }}
        
        .table-wrapper {{
            width: 100%;
            overflow-x: auto;
            overflow-y: visible;
            margin: 0;
            padding: 0;
            max-width: 100%;
            box-sizing: border-box;
        }}
        
        .ports-table {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            background: white;
            border: 1px solid #e5e7eb;
            font-size: 14px;
            table-layout: fixed;
            max-width: 100%;
        }}
        
        .ports-table th {{
            background: #f9fafb;
            color: #374151;
            padding: 16px 20px;
            text-align: left;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid #e5e7eb;
            border-right: 1px solid #f3f4f6;
        }}
        
        .ports-table th:nth-child(1) {{ width: 18%; }} /* Host */
        .ports-table th:nth-child(2) {{ width: 10%; }} /* Port */
        .ports-table th:nth-child(3) {{ width: 12%; }} /* Protocol */
        .ports-table th:nth-child(4) {{ width: 12%; }} /* Status */
        .ports-table th:nth-child(5) {{ width: 18%; }} /* Service */
        .ports-table th:nth-child(6) {{ width: 15%; }} /* Version */
        .ports-table th:nth-child(7) {{ width: 15%; }} /* Banner */
        
        .ports-table th:last-child {{
            border-right: none;
        }}
        
        .ports-table td {{
            padding: 16px 20px;
            border-bottom: 1px solid #f3f4f6;
            border-right: 1px solid #f3f4f6;
            color: #374151;
            vertical-align: top;
            word-wrap: break-word;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        
        .ports-table td:last-child {{
            border-right: none;
        }}
        
        .ports-table tr:last-child td {{
            border-bottom: none;
        }}
        
        .ports-table tr:nth-child(even) {{
            background: #fafbfc;
        }}
        
        .status-open {{
            color: #065f46;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }}
        
        .status-closed {{
            color: #7f1d1d;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }}
        
        .no-results {{
            text-align: center;
            padding: 60px 40px;
            color: #9ca3af;
            font-style: italic;
            font-size: 14px;
            background: #fafbfc;
            border: 1px solid #e5e7eb;
        }}
        
        .download-buttons {{
            display: flex;
            gap: 16px;
            margin-top: 24px;
        }}
        
        .download-btn {{
            padding: 12px 20px;
            border: 1px solid #d1d5db;
            background: #ffffff;
            color: #374151;
            text-decoration: none;
            font-weight: 500;
            font-size: 14px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.15s ease;
        }}
        
        .download-btn:hover {{
            background: #f9fafb;
            border-color: #9ca3af;
            color: #1f2937;
        }}
        
        .download-btn:active {{
            background: #f3f4f6;
        }}
        
        .vuln-card {{
            background: white;
            border: 1px solid #e5e7eb;
            border-left: 3px solid #9ca3af;
            padding: 24px;
            margin: 16px 0;
        }}
        
        .vuln-card.high {{ border-left-color: #7f1d1d; }}
        .vuln-card.medium {{ border-left-color: #92400e; }}
        .vuln-card.low {{ border-left-color: #a16207; }}
        .vuln-card.info {{ border-left-color: #1e40af; }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 16px;
        }}
        
        .vuln-title {{
            font-size: 16px;
            font-weight: 600;
            color: #1f2937;
            margin: 0;
        }}
        
        .vuln-severity {{
            padding: 4px 8px;
            background: #f3f4f6;
            color: #374151;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border: 1px solid #d1d5db;
        }}
        
        .severity-high {{ background: #fee2e2; color: #7f1d1d; border-color: #fca5a5; }}
        .severity-medium {{ background: #fef3c7; color: #92400e; border-color: #fcd34d; }}
        .severity-low {{ background: #fef9e2; color: #a16207; border-color: #fde047; }}
        .severity-info {{ background: #dbeafe; color: #1e40af; border-color: #93c5fd; }}
        
        .vuln-details {{
            background: #fafbfc;
            padding: 16px;
            border: 1px solid #f3f4f6;
            margin-top: 12px;
        }}
        
        .vuln-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
            font-size: 14px;
            margin-bottom: 12px;
        }}
        
        .vuln-meta strong {{
            color: #6b7280;
            font-weight: 500;
        }}
        
        /* General Information Styles */
        .info-card {{
            background: white;
            border: 1px solid #e5e7eb;
            border-left: 4px solid #10b981;
            padding: 24px;
            margin: 16px 0;
            border-radius: 8px;
            width: 100%;
            box-sizing: border-box;
        }}
        
        .info-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }}
        
        .info-header h3 {{
            margin: 0;
            color: #1f2937;
            font-size: 18px;
            font-weight: 600;
        }}
        
        .info-details {{
            background: #f8f9fa;
            padding: 16px;
            border-radius: 6px;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 12px;
            margin-bottom: 12px;
            width: 100%;
            box-sizing: border-box;
        }}
        
        .info-grid div {{
            font-size: 14px;
            color: #374151;
        }}
        
        .info-grid strong {{
            color: #6b7280;
            font-weight: 600;
        }}
        
        /* OS Information Styles */
        .os-card {{
            background: white;
            border: 1px solid #e5e7eb;
            border-left: 4px solid #3b82f6;
            padding: 24px;
            margin: 16px 0;
            border-radius: 8px;
        }}
        
        .os-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }}
        
        .os-header h3 {{
            margin: 0;
            color: #1f2937;
            font-size: 18px;
            font-weight: 600;
        }}
        
        .os-details {{
            background: #f8f9fa;
            padding: 16px;
            border-radius: 6px;
        }}
        
        .os-info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
            margin-bottom: 12px;
        }}
        
        .os-info-grid div {{
            font-size: 14px;
            color: #374151;
        }}
        
        .os-info-grid strong {{
            color: #6b7280;
            font-weight: 600;
        }}
        
        .os-technical-details {{
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid #e5e7eb;
        }}
        
        .os-technical-details strong {{
            color: #6b7280;
            font-weight: 600;
            font-size: 13px;
        }}
        
        .footer {{
            background: #f9fafb;
            border-top: 1px solid #e5e7eb;
            color: #6b7280;
            text-align: center;
            padding: 24px;
            font-size: 12px;
        }}
        
        /* Pagination Styles - Matching Dashboard Design */
        .paginated-table-container {{
            margin-top: 24px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            overflow: hidden;
            width: 100%;
            max-width: 100%;
            box-sizing: border-box;
            display: block;
            clear: both;
            position: relative;
        }}
        
        .table-wrapper {{
            overflow-x: auto;
            overflow-y: visible;
            width: 100%;
            display: block;
        }}
        
        .table-info {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 20px;
            background: #f8f9fa;
            border-bottom: 1px solid #e5e7eb;
            font-size: 14px;
        }}
        
        .total-items {{
            font-weight: 600;
            color: #374151;
            font-size: 14px;
        }}
        
        .page-info {{
            font-size: 14px;
            color: #6b7280;
            font-weight: 500;
        }}
        
        .pagination {{
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 8px;
            padding: 16px 20px;
            background: #f8f9fa;
            border-top: 1px solid #e5e7eb;
        }}
        
        .pagination-btn {{
            background: #ffffff;
            color: #374151;
            padding: 12px 20px;
            border: 1px solid #d1d5db;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.15s ease;
            border-radius: 6px;
            min-width: 44px;
            text-align: center;
        }}
        
        .pagination-btn:hover:not(:disabled) {{
            background: #f9fafb;
            border-color: #9ca3af;
            color: #1f2937;
        }}
        
        .pagination-btn:disabled {{
            background: #f3f4f6;
            color: #9ca3af;
            cursor: not-allowed;
        }}
        
        .page-numbers {{
            display: flex;
            gap: 6px;
            margin: 0 12px;
        }}
        
        .page-number {{
            background: #ffffff;
            color: #374151;
            padding: 12px 16px;
            border: 1px solid #d1d5db;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.15s ease;
            border-radius: 6px;
            min-width: 44px;
            text-align: center;
        }}
        
        .page-number:hover {{
            background: #f9fafb;
            border-color: #9ca3af;
            color: #1f2937;
        }}
        
        .page-number.active {{
            background: #3b82f6;
            color: white;
            border-color: #3b82f6;
            font-weight: 600;
        }}
        
        .page-number.active:hover {{
            background: #2563eb;
            border-color: #2563eb;
        }}
        
        /* Clearfix for pagination */
        .paginated-table-container::after {{
            content: "";
            display: table;
            clear: both;
        }}
        
        /* Ensure closed ports section properly contains paginated content */
        .closed-ports-section {{
            clear: both;
            overflow: hidden;
        }}
        
        /* Ensure vulnerabilities and export sections stay below paginated content */
        .vuln-section, .download-section {{
            clear: both;
            position: relative;
            z-index: 1;
        }}
        
        /* Responsive pagination */
        @media (max-width: 768px) {{
            .pagination {{
                flex-wrap: wrap;
                gap: 6px;
                padding: 12px 16px;
            }}
            
            .pagination-btn, .page-number {{
                padding: 10px 14px;
                font-size: 13px;
                min-width: 36px;
            }}
            
            .page-numbers {{
                margin: 0 8px;
                gap: 4px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Ginger Scan - Network Security Assessment Report</h1>
            <p class="subtitle">Scan ID: {scan_id}</p>
            <p class="subtitle">Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S UTC')}</p>
        </div>
        
        <div class="summary-section">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>{len(targets)}</h3>
                    <p>Target{'s' if len(targets) != 1 else ''} Scanned</p>
                </div>
                <div class="summary-card">
                    <h3>{len(open_ports)}</h3>
                    <p>Open Ports</p>
                </div>
                <div class="summary-card">
                    <h3>{len(closed_ports)}</h3>
                    <p>Closed/Filtered Ports</p>
                </div>
                <div class="summary-card">
                    <h3>{len(vulnerabilities)}</h3>
                    <p>Vulnerabilities Found</p>
                </div>
            </div>
        </div>
        
        {self._generate_general_info_section(scan_id) if (os_info or self.scan_results.get(scan_id, {}).get("ip_info")) else ''}
        
        <div class="section open-ports-section">
            <h2>Open Ports Analysis</h2>
            {self._generate_ports_table(open_ports, "open", os_info)}
        </div>
        
        <div class="section closed-ports-section">
            <h2>Closed & Filtered Ports</h2>
            {self._generate_paginated_ports_table(closed_ports, "closed", os_info)}
        </div>
        
        {self._generate_vulnerabilities_section(vulnerabilities) if vulnerabilities else ''}
        
        <div class="section download-section">
            <h2>Export Options</h2>
            <div class="download-buttons">
                <a href="/api/scan/{scan_id}/report?format=json" download="{scan_id}_report.json" class="download-btn">
                    📋 JSON Format
                </a>
                <a href="/api/scan/{scan_id}/export?format=csv" download="{scan_id}_results.csv" class="download-btn">
                    📊 CSV Format
                </a>
                <a href="/api/scan/{scan_id}/export?format=txt" download="{scan_id}_results.txt" class="download-btn">
                    📝 TXT Format
                </a>
                <a href="/api/scan/{scan_id}/export?format=pdf" download="{scan_id}_results.pdf" class="download-btn">
                    📄 PDF Format
                </a>
                <a href="/api/scan/{scan_id}/export?format=yaml" download="{scan_id}_results.yaml" class="download-btn">
                    ⚙️ YAML Format
                </a>
                <a href="/api/scan/{scan_id}/export?format=html" download="{scan_id}_results.html" class="download-btn">
                    🌐 HTML Format
                </a>
            </div>
        </div>
        
        <div class="footer">
            <p>Ginger Scan - Network Security Assessment Report • Generated on {datetime.now().strftime('%B %d, %Y')} • Confidential</p>
        </div>
    </div>
</body>
</html>"""
        
        return html
    
    async def _export_json(self, scan_id, results, vulnerabilities, os_info, ip_info, scan_info):
        """Export results to JSON format with all information."""
        from .parser import OutputParser
        
        # Create parser and convert results
        parser = OutputParser()
        parser.results = results
        
        # Get JSON data from parser
        json_data = json.loads(parser.export_json())
        
        # Add Ginger Scan metadata
        json_data['tool_info'] = {
            'name': 'Ginger Scan',
            'version': '1.0.0',
            'description': 'Comprehensive network scanning and vulnerability assessment platform',
            'generated_by': 'Ginger Scan Web Dashboard'
        }
        
        # Add scan information
        json_data['scan_info'] = {
            'scan_id': scan_id,
            'generated': datetime.now().isoformat(),
            'targets': scan_info.get('targets', []),
            'ports': scan_info.get('ports', []),
            'scan_type': scan_info.get('scan_type', 'unknown'),
            'total_hosts': len(set(result.host for result in results)),
            'total_ports_scanned': len(results),
            'open_ports': len([r for r in results if r.state == 'open']),
            'closed_ports': len([r for r in results if r.state in ['closed', 'filtered']]),
            'scan_duration': scan_info.get('duration', 'unknown')
        }
        
        # Convert any enum values to strings in ip_info and os_info
        def convert_enums_to_strings(obj):
            if isinstance(obj, dict):
                return {str(k): convert_enums_to_strings(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_enums_to_strings(item) for item in obj]
            elif hasattr(obj, 'value') and hasattr(obj, '__class__') and hasattr(obj.__class__, '__name__'):  # Enum objects
                return str(obj.value)
            elif hasattr(obj, '__class__') and 'Enum' in str(obj.__class__.__bases__):  # Additional enum check
                return str(obj.value)
            else:
                return obj
        
        # Add host information (IP info)
        json_data['host_information'] = convert_enums_to_strings(ip_info)
        
        # Add OS detection information
        json_data['os_information'] = convert_enums_to_strings(os_info)
        
        # Add vulnerabilities
        json_data['vulnerabilities'] = vulnerabilities
        
        # Add vulnerability summary
        vuln_summary = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            if severity not in vuln_summary:
                vuln_summary[severity] = 0
            vuln_summary[severity] += 1
        
        json_data['vulnerability_summary'] = vuln_summary
        
        json_content = json.dumps(json_data, indent=2, default=str)
        
        return Response(
            content=json_content,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={scan_id}_results.json"}
        )
    
    async def _export_csv(self, scan_id, results, vulnerabilities, os_info, ip_info, scan_info):
        """Export results to CSV format with all information."""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write Ginger Scan header
        writer.writerow(['Ginger Scan - Network Security Assessment Report'])
        writer.writerow(['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')])
        writer.writerow(['Scan ID:', scan_id])
        writer.writerow(['Tool:', 'Ginger Scan v1.0.0'])
        writer.writerow([])  # Empty row
        
        # Write data header
        writer.writerow([
            'Host', 'Hostname', 'Country', 'City', 'Region', 'ISP', 'ASN', 'OS', 'Port', 'Protocol', 'State', 'Service', 'Version', 
            'Banner', 'Response Time', 'Scan Type', 'Timestamp'
        ])
        
        # Write data rows
        for result in results:
            # Get OS information for this host
            host_os = "Unknown"
            if os_info and result.host in os_info:
                os_data = os_info[result.host]
                confidence = os_data.get("confidence", 0)
                family = os_data.get("family", "Unknown")
                if confidence > 0.7:
                    host_os = f"{family} (High)"
                elif confidence > 0.4:
                    host_os = f"{family} (Med)"
                else:
                    host_os = f"{family} (Low)"
            
            # Get IP information for this host
            host_ip_info = ip_info.get(result.host, {}) if ip_info else {}
            
            writer.writerow([
                result.host,
                host_ip_info.get('hostname', ''),
                host_ip_info.get('country_name', ''),
                host_ip_info.get('city', ''),
                host_ip_info.get('region', ''),
                host_ip_info.get('isp', ''),
                host_ip_info.get('asn', ''),
                host_os,
                result.port,
                result.protocol,
                result.state,
                result.service if result.state == 'open' else "N/A (Port Closed)",
                result.version or '',
                result.banner or '',
                result.response_time or '',
                result.scan_type or '',
                result.timestamp.isoformat() if result.timestamp else ''
            ])
        
        # Add vulnerabilities section
        if vulnerabilities:
            writer.writerow([])  # Empty row
            writer.writerow(['VULNERABILITIES'])
            writer.writerow(['Host', 'Port', 'Service', 'Type', 'Severity', 'Description', 'CVE', 'References'])
            
            for vuln in vulnerabilities:
                writer.writerow([
                    vuln.get('host', ''),
                    vuln.get('port', ''),
                    vuln.get('service', ''),
                    vuln.get('vuln_type', ''),
                    vuln.get('severity', ''),
                    vuln.get('description', ''),
                    vuln.get('cve', ''),
                    vuln.get('references', '')
                ])
        
        csv_content = output.getvalue()
        output.close()
        
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={scan_id}_results.csv"}
        )
    
    async def _export_txt(self, scan_id, results, vulnerabilities, os_info, ip_info, scan_info):
        """Export results to TXT format with all information."""
        txt_lines = []
        
        # Header
        txt_lines.append("=" * 80)
        txt_lines.append(f"GINGER SCAN - NETWORK SECURITY ASSESSMENT REPORT")
        txt_lines.append(f"Tool: Ginger Scan v1.0.0")
        txt_lines.append(f"Scan ID: {scan_id}")
        txt_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        txt_lines.append(f"Generated by: Ginger Scan Web Dashboard")
        txt_lines.append("=" * 80)
        txt_lines.append("")
        
        # Scan Information
        txt_lines.append("SCAN INFORMATION")
        txt_lines.append("-" * 40)
        txt_lines.append(f"Targets: {', '.join(scan_info.get('targets', []))}")
        txt_lines.append(f"Ports: {scan_info.get('ports', 'N/A')}")
        txt_lines.append(f"Scan Type: {scan_info.get('scan_type', 'N/A')}")
        txt_lines.append(f"Banner Grab: {scan_info.get('banner_grab', False)}")
        txt_lines.append(f"Host Discovery: {scan_info.get('host_discovery', False)}")
        txt_lines.append(f"OS Detection: {scan_info.get('os_detection', False)}")
        txt_lines.append(f"Start Time: {scan_info.get('start_time', 'N/A')}")
        txt_lines.append("")
        
        # OS Information
        if os_info:
            txt_lines.append("OPERATING SYSTEM DETECTION")
            txt_lines.append("-" * 40)
            for host, info in os_info.items():
                confidence = info.get("confidence", 0)
                family = info.get("family", "Unknown")
                method = info.get("method", "Unknown")
                version = info.get("version", "Unknown")
                
                confidence_level = "High" if confidence > 0.7 else "Medium" if confidence > 0.4 else "Low"
                txt_lines.append(f"Host: {host}")
                txt_lines.append(f"  OS: {family} {version}")
                txt_lines.append(f"  Confidence: {confidence_level} ({confidence:.1%})")
                txt_lines.append(f"  Method: {method}")
                txt_lines.append("")
        
        # IP Information
        if ip_info:
            txt_lines.append("HOST INFORMATION")
            txt_lines.append("-" * 40)
            for host, info in ip_info.items():
                txt_lines.append(f"Host: {host}")
                txt_lines.append(f"  Hostname: {info.get('hostname', 'Unknown')}")
                txt_lines.append(f"  Country: {info.get('country_name', 'Unknown')}")
                txt_lines.append(f"  City: {info.get('city', 'Unknown')}")
                txt_lines.append(f"  Region: {info.get('region', 'Unknown')}")
                txt_lines.append(f"  ISP: {info.get('isp', 'Unknown')}")
                txt_lines.append(f"  ASN: {info.get('asn', 'Unknown')}")
                txt_lines.append("")
        
        # Port Results
        open_ports = [r for r in results if r.state == "open"]
        closed_ports = [r for r in results if r.state in ["closed", "filtered"]]
        
        txt_lines.append("OPEN PORTS")
        txt_lines.append("-" * 40)
        if open_ports:
            for result in open_ports:
                # Get OS information
                host_os = "Unknown"
                if os_info and result.host in os_info:
                    os_data = os_info[result.host]
                    confidence = os_data.get("confidence", 0)
                    family = os_data.get("family", "Unknown")
                    if confidence > 0.7:
                        host_os = f"{family} (High)"
                    elif confidence > 0.4:
                        host_os = f"{family} (Med)"
                    else:
                        host_os = f"{family} (Low)"
                
                txt_lines.append(f"Host: {result.host} | OS: {host_os}")
                txt_lines.append(f"Port: {result.port}/{result.protocol}")
                txt_lines.append(f"Service: {result.service if result.state == 'open' else 'N/A (Port Closed)'}")
                txt_lines.append(f"Version: {result.version or 'Unknown'}")
                if result.banner:
                    txt_lines.append(f"Banner: {result.banner}")
                txt_lines.append("")
        else:
            txt_lines.append("No open ports found.")
            txt_lines.append("")
        
        # Closed/Filtered Ports Summary
        txt_lines.append("CLOSED/FILTERED PORTS SUMMARY")
        txt_lines.append("-" * 40)
        txt_lines.append(f"Total closed/filtered ports: {len(closed_ports)}")
        txt_lines.append("")
        
        # Vulnerabilities
        if vulnerabilities:
            txt_lines.append("VULNERABILITIES FOUND")
            txt_lines.append("-" * 40)
            for i, vuln in enumerate(vulnerabilities, 1):
                txt_lines.append(f"{i}. {vuln.get('vuln_type', 'Unknown Vulnerability')}")
                txt_lines.append(f"   Target: {vuln.get('host', 'Unknown')}:{vuln.get('port', 'Unknown')}")
                txt_lines.append(f"   Service: {vuln.get('service', 'Unknown')}")
                txt_lines.append(f"   Severity: {vuln.get('severity', 'Unknown')}")
                txt_lines.append(f"   Description: {vuln.get('description', 'No description')}")
                if vuln.get('cve'):
                    txt_lines.append(f"   CVE: {vuln.get('cve')}")
                if vuln.get('references'):
                    txt_lines.append(f"   References: {vuln.get('references')}")
                txt_lines.append("")
        else:
            txt_lines.append("VULNERABILITIES FOUND")
            txt_lines.append("-" * 40)
            txt_lines.append("No vulnerabilities found.")
            txt_lines.append("")
        
        # Summary
        txt_lines.append("SUMMARY")
        txt_lines.append("-" * 40)
        txt_lines.append(f"Total hosts scanned: {len(set(r.host for r in results))}")
        txt_lines.append(f"Open ports found: {len(open_ports)}")
        txt_lines.append(f"Closed/filtered ports: {len(closed_ports)}")
        txt_lines.append(f"Vulnerabilities found: {len(vulnerabilities)}")
        txt_lines.append(f"OS detections: {len(os_info)}")
        txt_lines.append("")
        txt_lines.append("=" * 80)
        
        txt_content = "\n".join(txt_lines)
        return Response(
            content=txt_content,
            media_type="text/plain",
            headers={"Content-Disposition": f"attachment; filename={scan_id}_results.txt"}
        )
    
    async def _export_pdf(self, scan_id, results, vulnerabilities, os_info, ip_info, scan_info):
        """Export results to PDF format with all information."""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.lib.units import inch
            import io
            
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
            story = []
            styles = getSampleStyleSheet()
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=16,
                spaceAfter=30,
                alignment=1  # Center alignment
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=12,
                spaceAfter=12,
                textColor=colors.darkblue
            )
            
            # Title
            story.append(Paragraph("Ginger Scan - Network Security Assessment Report", title_style))
            story.append(Paragraph(f"Tool: Ginger Scan v1.0.0", styles['Normal']))
            story.append(Paragraph(f"Scan ID: {scan_id}", styles['Normal']))
            story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles['Normal']))
            story.append(Paragraph(f"Generated by: Ginger Scan Web Dashboard", styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Scan Information
            story.append(Paragraph("Scan Information", heading_style))
            scan_data = [
                ['Targets', ', '.join(scan_info.get('targets', []))],
                ['Ports', str(scan_info.get('ports', 'N/A'))],
                ['Scan Type', scan_info.get('scan_type', 'N/A')],
                ['Banner Grab', str(scan_info.get('banner_grab', False))],
                ['Host Discovery', str(scan_info.get('host_discovery', False))],
                ['OS Detection', str(scan_info.get('os_detection', False))],
                ['Start Time', scan_info.get('start_time', 'N/A')]
            ]
            scan_table = Table(scan_data, colWidths=[2*inch, 4*inch])
            scan_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('BACKGROUND', (0, 0), (0, -1), colors.grey),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ]))
            story.append(scan_table)
            story.append(Spacer(1, 20))
            
            # OS Information
            if os_info:
                story.append(Paragraph("Operating System Detection", heading_style))
                os_data = []
                for host, info in os_info.items():
                    confidence = info.get("confidence", 0)
                    family = info.get("family", "Unknown")
                    method = info.get("method", "Unknown")
                    version = info.get("version", "Unknown")
                    confidence_level = "High" if confidence > 0.7 else "Medium" if confidence > 0.4 else "Low"
                    
                    os_data.append([host, f"{family} {version}", f"{confidence_level} ({confidence:.1%})", method])
                
                os_table = Table(os_data, colWidths=[1.5*inch, 2*inch, 1.5*inch, 1.5*inch])
                os_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(os_table)
                story.append(Spacer(1, 20))
            
            # IP Information
            if ip_info:
                story.append(Paragraph("Host Information", heading_style))
                ip_data = [['Host', 'Hostname', 'Country', 'City', 'Region', 'ISP', 'ASN']]
                for host, info in ip_info.items():
                    ip_data.append([
                        host,
                        info.get('hostname', 'Unknown'),
                        info.get('country_name', 'Unknown'),
                        info.get('city', 'Unknown'),
                        info.get('region', 'Unknown'),
                        info.get('isp', 'Unknown'),
                        info.get('asn', 'Unknown')
                    ])
                
                ip_table = Table(ip_data, colWidths=[1.5*inch, 1.5*inch, 1*inch, 1*inch, 1*inch, 1.5*inch, 1*inch])
                ip_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkgreen),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(ip_table)
                story.append(Spacer(1, 20))
            
            # Open Ports
            open_ports = [r for r in results if r.state == "open"]
            if open_ports:
                story.append(Paragraph("Open Ports", heading_style))
                port_data = [['Host', 'OS', 'Port', 'Protocol', 'Service', 'Version', 'Banner']]
                
                for result in open_ports:
                    # Get OS information
                    host_os = "Unknown"
                    if os_info and result.host in os_info:
                        os_data = os_info[result.host]
                        confidence = os_data.get("confidence", 0)
                        family = os_data.get("family", "Unknown")
                        if confidence > 0.7:
                            host_os = f"{family} (High)"
                        elif confidence > 0.4:
                            host_os = f"{family} (Med)"
                        else:
                            host_os = f"{family} (Low)"
                    
                    banner = result.banner[:50] + "..." if result.banner and len(result.banner) > 50 else result.banner or ""
                    port_data.append([
                        result.host,
                        host_os,
                        str(result.port),
                        result.protocol,
                        result.service if result.state == 'open' else "N/A (Port Closed)",
                        result.version or "",
                        banner
                    ])
                
                port_table = Table(port_data, colWidths=[1*inch, 1.2*inch, 0.5*inch, 0.7*inch, 1*inch, 1*inch, 1.5*inch])
                port_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(port_table)
                story.append(Spacer(1, 20))
            
            # Vulnerabilities
            if vulnerabilities:
                story.append(Paragraph("Vulnerabilities Found", heading_style))
                for i, vuln in enumerate(vulnerabilities, 1):
                    story.append(Paragraph(f"{i}. {vuln.get('vuln_type', 'Unknown Vulnerability')}", styles['Heading3']))
                    story.append(Paragraph(f"Target: {vuln.get('host', 'Unknown')}:{vuln.get('port', 'Unknown')}", styles['Normal']))
                    story.append(Paragraph(f"Service: {vuln.get('service', 'Unknown')}", styles['Normal']))
                    story.append(Paragraph(f"Severity: {vuln.get('severity', 'Unknown')}", styles['Normal']))
                    story.append(Paragraph(f"Description: {vuln.get('description', 'No description')}", styles['Normal']))
                    if vuln.get('cve'):
                        story.append(Paragraph(f"CVE: {vuln.get('cve')}", styles['Normal']))
                    story.append(Spacer(1, 12))
            else:
                story.append(Paragraph("Vulnerabilities Found", heading_style))
                story.append(Paragraph("No vulnerabilities found.", styles['Normal']))
                story.append(Spacer(1, 20))
            
            # Summary
            story.append(Paragraph("Summary", heading_style))
            summary_data = [
                ['Total hosts scanned', str(len(set(r.host for r in results)))],
                ['Open ports found', str(len(open_ports))],
                ['Closed/filtered ports', str(len([r for r in results if r.state in ["closed", "filtered"]]))],
                ['Vulnerabilities found', str(len(vulnerabilities))],
                ['OS detections', str(len(os_info))]
            ]
            summary_table = Table(summary_data, colWidths=[2*inch, 1*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ]))
            story.append(summary_table)
            
            doc.build(story)
            pdf_content = buffer.getvalue()
            buffer.close()
            
            return Response(
                content=pdf_content,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename={scan_id}_results.pdf"}
            )
            
        except ImportError:
            raise HTTPException(status_code=500, detail="PDF generation requires reportlab. Install with: pip install reportlab")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")
    
    async def _export_yaml(self, scan_id, results, vulnerabilities, os_info, ip_info, scan_info):
        """Export results to YAML format with all information."""
        import yaml
        
        # Prepare data structure
        export_data = {
            'tool_info': {
                'name': 'Ginger Scan',
                'version': '1.0.0',
                'description': 'Comprehensive network scanning and vulnerability assessment platform',
                'generated_by': 'Ginger Scan Web Dashboard'
            },
            'scan_info': {
                'scan_id': scan_id,
                'generated': datetime.now().isoformat(),
                'targets': scan_info.get('targets', []),
                'ports': scan_info.get('ports', []),
                'scan_type': scan_info.get('scan_type', ''),
                'banner_grab': scan_info.get('banner_grab', False),
                'host_discovery': scan_info.get('host_discovery', False),
                'os_detection': scan_info.get('os_detection', False),
                'start_time': scan_info.get('start_time', '')
            },
            'summary': {
                'total_hosts': len(set(r.host for r in results)),
                'open_ports': len([r for r in results if r.state == "open"]),
                'closed_ports': len([r for r in results if r.state in ["closed", "filtered"]]),
                'vulnerabilities': len(vulnerabilities),
                'os_detections': len(os_info),
                'ip_info_entries': len(ip_info)
            },
            'os_detection': os_info,
            'host_information': ip_info,
            'results': []
        }
        
        # Add results with OS information
        for result in results:
            # Get OS information for this host
            host_os = "Unknown"
            if os_info and result.host in os_info:
                os_data = os_info[result.host]
                confidence = os_data.get("confidence", 0)
                family = os_data.get("family", "Unknown")
                if confidence > 0.7:
                    host_os = f"{family} (High)"
                elif confidence > 0.4:
                    host_os = f"{family} (Med)"
                else:
                    host_os = f"{family} (Low)"
            
            result_data = {
                'host': result.host,
                'os': host_os,
                'port': result.port,
                'protocol': result.protocol,
                'state': result.state,
                'service': result.service,
                'version': result.version,
                'banner': result.banner,
                'response_time': result.response_time,
                'scan_type': result.scan_type,
                'timestamp': result.timestamp.isoformat() if result.timestamp else None
            }
            export_data['results'].append(result_data)
        
        # Add vulnerabilities
        export_data['vulnerabilities'] = vulnerabilities
        
        yaml_content = yaml.dump(export_data, default_flow_style=False, sort_keys=False, indent=2)
        
        return Response(
            content=yaml_content,
            media_type="application/x-yaml",
            headers={"Content-Disposition": f"attachment; filename={scan_id}_results.yaml"}
        )
    
    async def _export_html(self, scan_id, results, vulnerabilities, os_info, ip_info, scan_info):
        """Export results to HTML format without export section."""
        # Generate the same HTML report but without the export section
        html_content = self._generate_custom_html_report(scan_id, results, vulnerabilities)
        
        # Remove the export section from the HTML
        # Find and remove the export section
        export_section_start = html_content.find('<div class="section download-section">')
        if export_section_start != -1:
            # Find the end of the export section (before the footer)
            footer_start = html_content.find('<div class="footer">')
            if footer_start != -1:
                # Remove everything from export section to footer (exclusive)
                html_content = html_content[:export_section_start] + html_content[footer_start:]
        
        return Response(
            content=html_content,
            media_type="text/html",
            headers={"Content-Disposition": f"attachment; filename={scan_id}_results.html"}
        )
    
    def _generate_general_info_section(self, scan_id):
        """Generate General Information section with IP and OS details."""
        # Get IP info and OS info from scan results
        scan_data = self.scan_results.get(scan_id, {})
        ip_info = scan_data.get("ip_info", {})
        os_info = scan_data.get("os_info", {})
        
        if not ip_info and not os_info:
            return ""
        
        html = '''
        <div class="section general-info-section">
            <h2>General Information</h2>
        '''
        
        # Get all hosts from both IP and OS info
        all_hosts = set(list(ip_info.keys()) + list(os_info.keys()))
        
        for host in all_hosts:
            # IP Information
            ip_data = ip_info.get(host, {})
            os_data = os_info.get(host, {})
            
            html += f'''
            <div class="info-card">
                <div class="info-header">
                    <h3>{host}</h3>
                    <div class="info-status" style="background: #3b82f6; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600;">
                        Host Information
                    </div>
                </div>
                <div class="info-details">
                    <div class="info-grid">
            '''
            
            # Add OS Information first if available
            if os_data:
                html += f'''
                        <div><strong>Operating System:</strong> {os_data.get("family", "Unknown")}</div>
                        <div><strong>OS Version:</strong> {os_data.get("version", "Unknown")}</div>
                        <div><strong>Confidence:</strong> <span style="color: {'#10b981' if os_data.get('confidence', 0) > 0.7 else '#f59e0b' if os_data.get('confidence', 0) > 0.4 else '#ef4444'};">{os_data.get('confidence', 0):.1%}</span></div>
                '''
            
            # Add IP Information
            if ip_data:
                html += f'''
                        <div><strong>Country:</strong> {ip_data.get("country_name") or "Unknown"}</div>
                        <div><strong>City:</strong> {ip_data.get("city") or "Unknown"}</div>
                        <div><strong>Region:</strong> {ip_data.get("region") or "Unknown"}</div>
                        <div><strong>ISP:</strong> {ip_data.get("isp") or "Unknown"}</div>
                        <div><strong>ASN:</strong> {ip_data.get("asn") or "Unknown"}</div>
                        <div><strong>Hostname:</strong> {ip_data.get("hostname") or "Unknown"}</div>

                '''
            
            html += '''
                    </div>
                </div>
            </div>
            '''
        
        html += '</div>'
        return html

    def _generate_os_info_section(self, os_info):
        """Generate OS information section."""
        if not os_info:
            return ""
        
        html = '''
        <div class="section os-info-section">
            <h2>Operating System Detection</h2>
        '''
        
        for host, info in os_info.items():
            confidence_color = "#10b981" if info["confidence"] > 0.7 else "#f59e0b" if info["confidence"] > 0.4 else "#ef4444"
            confidence_text = "High" if info["confidence"] > 0.7 else "Medium" if info["confidence"] > 0.4 else "Low"
            
            html += f'''
            <div class="os-card">
                <div class="os-header">
                    <h3>{host}</h3>
                    <div class="os-confidence" style="background: {confidence_color}; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600;">
                        {confidence_text} Confidence ({info["confidence"]:.1%})
                    </div>
                </div>
                <div class="os-details">
                    <div class="os-info-grid">
                        <div><strong>Operating System:</strong> {info["family"]}</div>
                        <div><strong>Version:</strong> {info.get("version") or "Unknown"}</div>
                        <div><strong>Detection Method:</strong> {info["method"]}</div>
                    </div>
            '''
            
            if info.get("details"):
                html += '''
                    <div class="os-technical-details">
                        <strong>Technical Details:</strong>
                        <pre style="background: #f8f9fa; padding: 12px; border-radius: 6px; font-size: 12px; margin-top: 8px; overflow-x: auto;">'''
                
                # Convert OSFamily enums to strings for JSON serialization
                def convert_os_family(obj):
                    if hasattr(obj, 'value'):  # Check if it's an enum
                        return obj.value
                    elif isinstance(obj, dict):
                        return {str(k): convert_os_family(v) for k, v in obj.items()}
                    elif isinstance(obj, list):
                        return [convert_os_family(item) for item in obj]
                    else:
                        return obj
                
                try:
                    serializable_details = convert_os_family(info["details"])
                    html += json.dumps(serializable_details, indent=2)
                except Exception as e:
                    # Fallback: convert to string representation
                    html += str(info["details"])
                html += '''
                        </pre>
                    </div>
                '''
            
            html += '''
                </div>
            </div>
            '''
        
        html += '</div>'
        return html
    
    def _generate_ports_table(self, ports, table_type, os_info=None):
        """Generate HTML table for ports."""
        if not ports:
            return '<div class="no-results">No ports found in this category</div>'
        
        status_class = "status-open" if table_type == "open" else "status-closed"
        
        html = f'''
        <div class="table-wrapper">
            <table class="ports-table">
                <thead>
                    <tr>
                        <th>Host</th>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Status</th>
                        <th>Service</th>
                        <th>Version</th>
                        <th>Banner</th>
                    </tr>
                </thead>
                <tbody>
        '''
        
        for port in ports:
            # Clean up state terminology
            display_state = "Open" if port.state == "open" else "Closed"
            if port.state == "filtered":
                display_state = "Closed"
            
            banner_display = ""
            if port.banner:
                # Truncate long banners
                banner_display = port.banner[:100] + "..." if len(port.banner) > 100 else port.banner
                banner_display = banner_display.replace('\n', ' ').replace('\r', ' ')
            
            html += f'''
                <tr>
                    <td>{port.host}</td>
                    <td>{port.port}</td>
                    <td>{port.protocol.upper()}</td>
                    <td><span class="{status_class}">{display_state}</span></td>
                    <td>{port.service if port.state == 'open' else '-'}</td>
                    <td>{port.version or '-'}</td>
                    <td>{banner_display or '-'}</td>
                </tr>
            '''
        
        html += '''
                </tbody>
            </table>
        </div>
        '''
        
        return html
    
    def _generate_paginated_ports_table(self, ports, table_type, os_info=None, items_per_page=20):
        """Generate HTML table for ports with pagination."""
        if not ports:
            return '<div class="no-results">No ports found in this category</div>'
        
        status_class = "status-open" if table_type == "open" else "status-closed"
        total_pages = (len(ports) + items_per_page - 1) // items_per_page
        
        # Generate unique IDs for this table
        table_id = f"ports-table-{table_type}"
        pagination_id = f"pagination-{table_type}"
        
        html = f'''
        <div class="paginated-table-container">
            <div class="table-info">
                <span class="total-items">Total: {len(ports)} ports</span>
                <span class="page-info">Page <span id="current-page-{table_type}">1</span> of {total_pages}</span>
            </div>
            
            <div class="table-wrapper">
                <table class="ports-table" id="{table_id}">
                    <thead>
                        <tr>
                            <th>Host</th>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Status</th>
                            <th>Service</th>
                            <th>Version</th>
                            <th>Banner</th>
                        </tr>
                    </thead>
                    <tbody id="table-body-{table_type}">
        '''
        
        # Generate all rows (will be shown/hidden by JavaScript)
        for i, port in enumerate(ports):
            # Clean up state terminology
            display_state = "Open" if port.state == "open" else "Closed"
            if port.state == "filtered":
                display_state = "Closed"
            
            banner_display = ""
            if port.banner:
                # Truncate long banners
                banner_display = port.banner[:100] + "..." if len(port.banner) > 100 else port.banner
                banner_display = banner_display.replace('\n', ' ').replace('\r', ' ')
            
            page_number = (i // items_per_page) + 1
            row_class = f"page-{page_number}" if page_number > 1 else ""
            
            html += f'''
                    <tr class="{row_class}" style="{'display: none;' if page_number > 1 else ''}">
                        <td>{port.host}</td>
                        <td>{port.port}</td>
                        <td>{port.protocol.upper()}</td>
                        <td><span class="{status_class}">{display_state}</span></td>
                        <td>{port.service if port.state == 'open' else '-'}</td>
                        <td>{port.version or '-'}</td>
                        <td>{banner_display or '-'}</td>
                    </tr>
            '''
        
        html += f'''
                    </tbody>
                </table>
            </div>
            
            <div class="pagination" id="{pagination_id}">
                <button class="pagination-btn" onclick="changePage_{table_type}(1)" id="first-{table_type}">« First</button>
                <button class="pagination-btn" onclick="changePage_{table_type}(currentPage_{table_type} - 1)" id="prev-{table_type}">‹ Previous</button>
                <div class="page-numbers" id="page-numbers-{table_type}">
        '''
        
        # Generate page number buttons (limited to 7 pages max)
        # Show first 3 pages, current page, and last 3 pages
        max_visible_pages = 7
        if total_pages <= max_visible_pages:
            # Show all pages if total is small
            for page in range(1, total_pages + 1):
                active_class = "active" if page == 1 else ""
                html += f'<button class="page-number {active_class}" onclick="changePage_{table_type}({page})">{page}</button>'
        else:
            # Show limited pages with ellipsis
            html += '<button class="page-number" onclick="changePage_{table_type}(1)">1</button>'
            if total_pages > 2:
                html += '<span class="page-ellipsis">...</span>'
            # The rest will be handled by JavaScript
        
        html += f'''
                </div>
                <button class="pagination-btn" onclick="changePage_{table_type}(currentPage_{table_type} + 1)" id="next-{table_type}">Next ›</button>
                <button class="pagination-btn" onclick="changePage_{table_type}({total_pages})" id="last-{table_type}">Last »</button>
            </div>
        </div>
        
        <script>
        let currentPage_{table_type} = 1;
        const totalPages_{table_type} = {total_pages};
        const itemsPerPage_{table_type} = {items_per_page};
        
        function changePage_{table_type}(page) {{
            if (page < 1 || page > totalPages_{table_type}) return;
            
            currentPage_{table_type} = page;
            
            // Hide all rows
            const rows = document.querySelectorAll('#table-body-{table_type} tr');
            rows.forEach(row => row.style.display = 'none');
            
            // Show rows for current page
            const startIndex = (page - 1) * itemsPerPage_{table_type};
            const endIndex = startIndex + itemsPerPage_{table_type};
            
            for (let i = startIndex; i < endIndex && i < rows.length; i++) {{
                rows[i].style.display = '';
            }}
            
            // Update page info
            document.getElementById('current-page-{table_type}').textContent = page;
            
            // Update pagination buttons
            updatePagination_{table_type}(page);
            
            // Update prev/next buttons
            document.getElementById('prev-{table_type}').disabled = page === 1;
            document.getElementById('next-{table_type}').disabled = page === totalPages_{table_type};
            document.getElementById('first-{table_type}').disabled = page === 1;
            document.getElementById('last-{table_type}').disabled = page === totalPages_{table_type};
        }}
        
        function updatePagination_{table_type}(currentPage) {{
            const pageNumbersContainer = document.getElementById('page-numbers-{table_type}');
            let html = '';
            
            if (totalPages_{table_type} <= 7) {{
                // Show all pages if total is small
                for (let i = 1; i <= totalPages_{table_type}; i++) {{
                    const activeClass = i === currentPage ? 'active' : '';
                    html += `<button class="page-number ${{activeClass}}" onclick="changePage_{table_type}(${{i}})">${{i}}</button>`;
                }}
            }} else {{
                // Show limited pages with ellipsis
                if (currentPage <= 4) {{
                    // Show first 5 pages
                    for (let i = 1; i <= 5; i++) {{
                        const activeClass = i === currentPage ? 'active' : '';
                        html += `<button class="page-number ${{activeClass}}" onclick="changePage_{table_type}(${{i}})">${{i}}</button>`;
                    }}
                    html += '<span class="page-ellipsis">...</span>';
                    html += `<button class="page-number" onclick="changePage_{table_type}(${{totalPages_{table_type}}})">${{totalPages_{table_type}}}</button>`;
                }} else if (currentPage >= totalPages_{table_type} - 3) {{
                    // Show last 5 pages
                    html += '<button class="page-number" onclick="changePage_{table_type}(1)">1</button>';
                    html += '<span class="page-ellipsis">...</span>';
                    for (let i = totalPages_{table_type} - 4; i <= totalPages_{table_type}; i++) {{
                        const activeClass = i === currentPage ? 'active' : '';
                        html += `<button class="page-number ${{activeClass}}" onclick="changePage_{table_type}(${{i}})">${{i}}</button>`;
                    }}
                }} else {{
                    // Show current page in middle
                    html += '<button class="page-number" onclick="changePage_{table_type}(1)">1</button>';
                    html += '<span class="page-ellipsis">...</span>';
                    for (let i = currentPage - 1; i <= currentPage + 1; i++) {{
                        const activeClass = i === currentPage ? 'active' : '';
                        html += `<button class="page-number ${{activeClass}}" onclick="changePage_{table_type}(${{i}})">${{i}}</button>`;
                    }}
                    html += '<span class="page-ellipsis">...</span>';
                    html += `<button class="page-number" onclick="changePage_{table_type}(${{totalPages_{table_type}}})">${{totalPages_{table_type}}}</button>`;
                }}
            }}
            
            pageNumbersContainer.innerHTML = html;
        }}
        
        // Initialize pagination
        changePage_{table_type}(1);
        </script>
        '''
        
        return html
    
    def _generate_vulnerabilities_section(self, vulnerabilities):
        """Generate vulnerabilities section."""
        if not vulnerabilities:
            return ""
        
        html = '''
        <div class="section vuln-section">
            <h2>Security Vulnerabilities</h2>
        '''
        
        for i, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', 'info').lower()
            severity_class = f"severity-{severity}"
            card_class = f"vuln-card {severity}"
            
            html += f'''
            <div class="{card_class}">
                <div class="vuln-header">
                    <div class="vuln-title">{vuln.get('vuln_type', 'Unknown Vulnerability')}</div>
                    <div class="vuln-severity {severity_class}">{vuln.get('severity', 'INFO')}</div>
                </div>
                <div class="vuln-details">
                    <div class="vuln-meta">
                        <div><strong>Target:</strong> {vuln.get('host', 'Unknown')}:{vuln.get('port', 'Unknown')}</div>
                        <div><strong>Service:</strong> {vuln.get('service', 'Unknown')}</div>
                        <div><strong>Type:</strong> {vuln.get('vuln_type', 'Unknown')}</div>
                    </div>
                    <p style="margin-top: 12px; color: #374151; font-size: 14px; line-height: 1.5;"><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
                </div>
            </div>
            '''
        
        html += '</div>'
        return html

    def _generate_download_buttons_section(self, scan_id):
        """Generate HTML section for download buttons."""
        return f"""
        <div style="margin: 30px 0; padding: 20px; background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); border-radius: 15px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); text-align: center;">
            <h3 style="color: #2c3e50; margin-bottom: 20px; font-size: 1.4em;">
                📄 Download Report
            </h3>
            <div style="display: flex; justify-content: center; gap: 15px; flex-wrap: wrap;">
                <a href="/api/scan/{scan_id}/report?format=json" download="{scan_id}_report.json" 
                   style="background: linear-gradient(45deg, #007bff, #0056b3); color: white; padding: 12px 20px; 
                          text-decoration: none; border-radius: 25px; font-weight: bold; 
                          box-shadow: 0 4px 15px rgba(0,123,255,0.3); transition: all 0.3s ease;
                          display: inline-flex; align-items: center; gap: 8px;">
                    📋 JSON Format
                </a>
                <a href="/api/scan/{scan_id}/export?format=csv" download="{scan_id}_results.csv"
                   style="background: linear-gradient(45deg, #28a745, #1e7e34); color: white; padding: 12px 20px; 
                          text-decoration: none; border-radius: 25px; font-weight: bold; 
                          box-shadow: 0 4px 15px rgba(40,167,69,0.3); transition: all 0.3s ease;
                          display: inline-flex; align-items: center; gap: 8px;">
                    📊 CSV Format
                </a>
                <a href="/api/scan/{scan_id}/export?format=txt" download="{scan_id}_results.txt"
                   style="background: linear-gradient(45deg, #6c757d, #495057); color: white; padding: 12px 20px; 
                          text-decoration: none; border-radius: 25px; font-weight: bold; 
                          box-shadow: 0 4px 15px rgba(108,117,125,0.3); transition: all 0.3s ease;
                          display: inline-flex; align-items: center; gap: 8px;">
                    📝 TXT Format
                </a>
            </div>
            <style>
                a:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(0,0,0,0.15) !important;
                }}
            </style>
        </div>
        """
    
    def _generate_vulnerability_html_section(self, vulnerabilities):
        """Generate HTML section for vulnerabilities."""
        if not vulnerabilities:
            return ""
        
        html = """
        <div style="margin: 40px 0; padding: 25px; background: linear-gradient(135deg, #fff5f5 0%, #fed7d7 100%); 
                    border-radius: 15px; box-shadow: 0 4px 20px rgba(220,53,69,0.1); border-left: 5px solid #dc3545;">
            <div style="text-align: center; margin-bottom: 25px;">
                <h2 style="color: #dc3545; margin: 0; font-size: 1.8em; font-weight: bold;">
                    🔒 Security Vulnerability Assessment
                </h2>
                <p style="color: #721c24; margin: 10px 0 0 0; font-size: 1.1em;">
                    Identified <strong style="color: #dc3545;">{}</strong> potential security issues requiring attention
                </p>
            </div>
        """.format(len(vulnerabilities))
        
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_class = vuln.get('severity', 'info').lower()
            severity_colors = {
                'high': '#dc3545',
                'medium': '#fd7e14', 
                'low': '#ffc107',
                'info': '#17a2b8'
            }
            severity_color = severity_colors.get(severity_class, '#6c757d')
            
            html += f"""
            <div style="background: white; border: 1px solid #e9ecef; border-left: 6px solid {severity_color}; 
                        padding: 20px; margin: 15px 0; border-radius: 10px; 
                        box-shadow: 0 4px 15px rgba(0,0,0,0.1); transition: all 0.3s ease;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 15px;">
                    <h3 style="margin: 0; color: {severity_color}; font-size: 1.3em; font-weight: bold; flex: 1;">
                        🚨 {vuln.get('vuln_type', 'Unknown Vulnerability')}
                    </h3>
                    <span style="background: {severity_color}; color: white; padding: 6px 12px; 
                                border-radius: 20px; font-size: 0.85em; font-weight: bold; 
                                text-transform: uppercase; margin-left: 15px; white-space: nowrap;">
                        {vuln.get('severity', 'INFO')}
                    </span>
                </div>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 15px 0;">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 0.95em;">
                        <div><strong style="color: #495057;">🎯 Target:</strong> <span style="color: #007bff; font-weight: 600;">{vuln.get('host', 'Unknown')}:{vuln.get('port', 'Unknown')}</span></div>
                        <div><strong style="color: #495057;">🔧 Service:</strong> <span style="color: #28a745; font-weight: 600;">{vuln.get('service', 'Unknown')}</span></div>
                        <div style="grid-column: 1 / -1;"><strong style="color: #495057;">📋 Type:</strong> <span style="color: #6f42c1; font-weight: 600;">{vuln.get('vuln_type', 'Unknown')}</span></div>
                    </div>
                </div>
                <div style="margin: 10px 0;">
                    <strong>Description:</strong><br>
                    <p style="margin: 5px 0; color: #495057;">{vuln.get('description', 'No description available')}</p>
                </div>
            """
            
            if vuln.get('cve'):
                html += f"""
                <div style="margin: 10px 0;">
                    <strong>CVE:</strong> <code style="background: #e9ecef; padding: 2px 4px; border-radius: 3px;">{vuln.get('cve')}</code>
                </div>
                """
            
            if vuln.get('references'):
                html += f"""
                <div style="margin: 10px 0;">
                    <strong>References:</strong><br>
                    <p style="margin: 5px 0; color: #495057;">{vuln.get('references')}</p>
                </div>
                """
            
            html += "</div>"
        
        html += "</div>"
        return html
    
    def _setup_websocket(self):
        """Setup WebSocket for real-time updates."""
        
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket endpoint for real-time updates."""
            await websocket.accept()
            self.connected_clients.append(websocket)
            
            try:
                while True:
                    # Keep connection alive
                    await websocket.receive_text()
            except WebSocketDisconnect:
                pass  # WebSocket cleanup handled in finally block
            finally:
                # Safely remove websocket from connected clients
                try:
                    if websocket in self.connected_clients:
                        self.connected_clients.remove(websocket)
                except (ValueError, AttributeError):
                    pass  # Already removed or list modified
    
    async def _run_scan_with_queue(self, scan_id: str, config: ScanConfig, vuln_check: bool = False, remaining_queue: List[Dict] = None):
        """Run a scan and then process the remaining queue sequentially."""
        try:
            logger.info(f"Starting scan {scan_id} with {len(remaining_queue) if remaining_queue else 0} remaining scans in queue")
            
            # Run the current scan
            await self._run_scan(scan_id, config, vuln_check)
            
            # Process remaining scans in queue - only start the next one
            if remaining_queue:
                logger.info(f"Queue has {len(remaining_queue)} remaining scans, starting the next one")
                
                # Only process the first scan in the queue
                next_scan = remaining_queue[0]
                
                # Check if the next scan was stopped by user before starting it
                if next_scan['scan_id'] in self.active_scans and self.active_scans[next_scan['scan_id']].status == "stopped":
                    logger.info(f"Next scan {next_scan['scan_id']} was stopped by user, skipping")
                elif next_scan['scan_id'] not in self.active_scans or self.active_scans[next_scan['scan_id']].status != "pending":
                    logger.info(f"Scan {next_scan['scan_id']} is no longer pending, skipping")
                else:
                    logger.info(f"Starting next scan: {next_scan['scan_id']}")
                    
                    # Update status to running
                    self.active_scans[next_scan['scan_id']].status = "running"
                    self.active_scans[next_scan['scan_id']].start_time = datetime.now()
                    logger.info(f"Updated scan {next_scan['scan_id']} status to running with start_time: {self.active_scans[next_scan['scan_id']].start_time}")
                    await self._broadcast_update(next_scan['scan_id'])
                    
                    # Get the remaining queue for this next scan (excluding the one we're about to start)
                    remaining_for_next = remaining_queue[1:] if len(remaining_queue) > 1 else []
                    
                    # Create a new task for the next scan with its own queue
                    task = asyncio.create_task(self._run_scan_with_queue(
                        next_scan['scan_id'], 
                        next_scan['config'], 
                        next_scan['vuln_check'],
                        remaining_for_next
                    ))
                    self.scan_tasks[next_scan['scan_id']] = task
                    logger.info(f"Created scan task for {next_scan['scan_id']} with {len(remaining_for_next)} remaining scans")
                    
        except Exception as e:
            logger.error(f"Error in scan queue processing: {e}")
            # Mark remaining scans as failed
            if remaining_queue:
                for next_scan in remaining_queue:
                    if next_scan['scan_id'] in self.active_scans:
                        self.active_scans[next_scan['scan_id']].status = "failed"
                        self.active_scans[next_scan['scan_id']].error = str(e)
                        self.active_scans[next_scan['scan_id']].end_time = datetime.now()
                        await self._broadcast_update(next_scan['scan_id'])
    
    async def _run_scan(self, scan_id: str, config: ScanConfig, vuln_check: bool = False):
        """Run a scan in the background."""
        try:
            # Broadcast initial status (already set to running in start_scan)
            await self._broadcast_update(scan_id)
            
            # Create scanner first
            scanner = PortScanner(config)
            
            # Create progress callback
            async def progress_callback(progress: float, status: str, message: str):
                self.active_scans[scan_id].progress = progress
                self.active_scans[scan_id].status = status
                self.active_scans[scan_id].current_target = message
                await self._broadcast_update(scan_id)
                
                # Store partial results if we have them (for stop functionality)
                if hasattr(scanner, 'results') and scanner.results:
                    partial_results = []
                    for result in scanner.results:
                        result_dict = {
                            "host": result.host,
                            "port": result.port,
                            "protocol": result.protocol,
                            "state": result.state,
                            "service": result.service,
                            "banner": result.banner,
                            "version": result.version,
                            "response_time": result.response_time,
                            "scan_type": result.scan_type.value if result.scan_type else None,
                            "timestamp": datetime.now().isoformat()
                        }
                        partial_results.append(result_dict)
                    
                    # Store partial results with OS and IP information
                    # Create storage dictionaries for partial results with robust error handling
                    partial_os_info_dict = {}
                    try:
                        if hasattr(scanner, 'os_info') and scanner.os_info:
                            for host, os_info in scanner.os_info.items():
                                partial_os_info_dict[host] = {
                                    "family": os_info.family.value if hasattr(os_info, 'family') and os_info.family else "Unknown",
                                    "version": os_info.version if hasattr(os_info, 'version') else "Unknown",
                                    "confidence": os_info.confidence if hasattr(os_info, 'confidence') else 0.0,
                                    "method": os_info.method if hasattr(os_info, 'method') else "Unknown",
                                    "details": os_info.details if hasattr(os_info, 'details') else "Unknown"
                                }
                    except Exception as e:
                        logger.error(f"Error processing partial OS info: {e}")
                    
                    partial_ip_info_dict = {}
                    try:
                        if hasattr(scanner, 'ip_info') and scanner.ip_info:
                            for host, ip_info in scanner.ip_info.items():
                                partial_ip_info_dict[host] = {
                                    "ip": ip_info.ip if hasattr(ip_info, 'ip') else host,
                                    "hostname": ip_info.hostname if hasattr(ip_info, 'hostname') else "Unknown",
                                    "domain": ip_info.domain if hasattr(ip_info, 'domain') else "Unknown",
                                    "country_name": ip_info.country_name if hasattr(ip_info, 'country_name') else "Unknown",
                                    "city": ip_info.city if hasattr(ip_info, 'city') else "Unknown",
                                    "organization": ip_info.organization if hasattr(ip_info, 'organization') else "Unknown",
                                    "isp": ip_info.isp if hasattr(ip_info, 'isp') else "Unknown",
                                    "asn": ip_info.asn if hasattr(ip_info, 'asn') else "Unknown",
                                    "asn_name": ip_info.asn_name if hasattr(ip_info, 'asn_name') else "Unknown",
                                    "latitude": ip_info.latitude if hasattr(ip_info, 'latitude') else "Unknown",
                                    "longitude": ip_info.longitude if hasattr(ip_info, 'longitude') else "Unknown",
                                    "timezone": ip_info.timezone if hasattr(ip_info, 'timezone') else "Unknown",
                                    "region": ip_info.region if hasattr(ip_info, 'region') else "Unknown",
                                    "postal_code": ip_info.postal_code if hasattr(ip_info, 'postal_code') else "Unknown"
                                }
                    except Exception as e:
                        logger.error(f"Error processing partial IP info: {e}")
                    
                    self.scan_results[scan_id] = {
                        "results": partial_results,
                        "vulnerabilities": [],
                        "os_info": partial_os_info_dict,
                        "ip_info": partial_ip_info_dict,
                        "scan_info": {
                            "targets": config.targets,
                            "ports": config.ports,
                            "scan_type": config.scan_type.value,
                            "banner_grab": config.banner_grab,
                            "host_discovery": config.host_discovery,
                            "os_detection": config.os_detection,
                            "ip_info": config.ip_info,
                            "start_time": datetime.now().isoformat()
                        }
                    }
                    
                    # Update results count in scan status
                    open_ports = [r for r in partial_results if r.get("state") == "open"]
                    self.active_scans[scan_id].results_count = len(open_ports)
            
            # Set the progress callback
            scanner.progress_callback = progress_callback
            
            # Run scan with progress callbacks (0-80%)
            results = await scanner.scan()
            
            # Debug: Check scanner state after scan
            logger.info(f"After scan - Scanner has ip_info: {hasattr(scanner, 'ip_info')}")
            if hasattr(scanner, 'ip_info'):
                logger.info(f"After scan - Scanner ip_info: {scanner.ip_info}")
            logger.info(f"After scan - Scanner has os_info: {hasattr(scanner, 'os_info')}")
            if hasattr(scanner, 'os_info'):
                logger.info(f"After scan - Scanner os_info: {scanner.os_info}")
            
            # Convert results to dict format
            results_dict = []
            for result in results:
                result_dict = {
                    "host": result.host,
                    "port": result.port,
                    "protocol": result.protocol,
                    "state": result.state,
                    "service": result.service,
                    "banner": result.banner,
                    "version": result.version,
                    "response_time": result.response_time,
                    "scan_type": result.scan_type.value if result.scan_type else None,
                    "timestamp": datetime.now().isoformat()
                }
                results_dict.append(result_dict)
            
            # Store results with scan info
            # Create storage dictionaries with robust error handling
            os_info_dict = {}
            try:
                if hasattr(scanner, 'os_info') and scanner.os_info:
                    for host, os_info in scanner.os_info.items():
                        os_info_dict[host] = {
                            "family": os_info.family.value if hasattr(os_info, 'family') and os_info.family else "Unknown",
                            "version": os_info.version if hasattr(os_info, 'version') else "Unknown",
                            "confidence": os_info.confidence if hasattr(os_info, 'confidence') else 0.0,
                            "method": os_info.method if hasattr(os_info, 'method') else "Unknown",
                            "details": os_info.details if hasattr(os_info, 'details') else "Unknown"
                        }
            except Exception as e:
                logger.error(f"Error processing OS info: {e}")
            
            ip_info_dict = {}
            try:
                if hasattr(scanner, 'ip_info') and scanner.ip_info:
                    for host, ip_info in scanner.ip_info.items():
                        ip_info_dict[host] = {
                            "ip": ip_info.ip if hasattr(ip_info, 'ip') else host,
                            "hostname": ip_info.hostname if hasattr(ip_info, 'hostname') else "Unknown",
                            "domain": ip_info.domain if hasattr(ip_info, 'domain') else "Unknown",
                            "country_name": ip_info.country_name if hasattr(ip_info, 'country_name') else "Unknown",
                            "city": ip_info.city if hasattr(ip_info, 'city') else "Unknown",
                            "organization": ip_info.organization if hasattr(ip_info, 'organization') else "Unknown",
                            "isp": ip_info.isp if hasattr(ip_info, 'isp') else "Unknown",
                            "asn": ip_info.asn if hasattr(ip_info, 'asn') else "Unknown",
                            "asn_name": ip_info.asn_name if hasattr(ip_info, 'asn_name') else "Unknown",
                            "latitude": ip_info.latitude if hasattr(ip_info, 'latitude') else "Unknown",
                            "longitude": ip_info.longitude if hasattr(ip_info, 'longitude') else "Unknown",
                            "timezone": ip_info.timezone if hasattr(ip_info, 'timezone') else "Unknown",
                            "region": ip_info.region if hasattr(ip_info, 'region') else "Unknown",
                            "postal_code": ip_info.postal_code if hasattr(ip_info, 'postal_code') else "Unknown"
                        }
            except Exception as e:
                logger.error(f"Error processing IP info: {e}")
            
            self.scan_results[scan_id] = {
                "results": results_dict,
                "vulnerabilities": [],
                "os_info": os_info_dict,
                "ip_info": ip_info_dict,
                "scan_info": {
                    "targets": config.targets,
                    "ports": config.ports,
                    "scan_type": config.scan_type.value,
                    "banner_grab": config.banner_grab,
                    "host_discovery": config.host_discovery,
                    "os_detection": config.os_detection,
                    "ip_info": config.ip_info,
                    "start_time": datetime.now().isoformat()
                }
            }
            logger.info(f"Stored scan results for {scan_id}: {len(results_dict)} results, targets: {config.targets}")
            
            # Run vulnerability checks if requested (80-95%)
            if vuln_check:
                # Only run vulnerability checks if there are open ports
                open_ports = [r for r in results if r.state == "open"]
                if open_ports:
                    await self._run_vuln_checks(scan_id, results, progress_callback)
                else:
                    logger.info("No open ports found - skipping vulnerability checks")
                    if progress_callback:
                        await progress_callback(100.0, "running", "No open ports found - vulnerability checks skipped")
            
            # Update status - results_count will be updated after vulnerability checks
            self.active_scans[scan_id].status = "completed"
            self.active_scans[scan_id].progress = 100.0
            self.active_scans[scan_id].end_time = datetime.now()
            logger.info(f"Marked scan {scan_id} as completed. Start time: {self.active_scans[scan_id].start_time}, End time: {self.active_scans[scan_id].end_time}")
            
            # Set results count based on vulnerability findings or open ports
            vuln_count = len(self.scan_results.get(scan_id, {}).get("vulnerabilities", []))
            if vuln_count > 0:
                self.active_scans[scan_id].results_count = vuln_count
                self.active_scans[scan_id].current_target = f"Completed - {vuln_count} vulnerabilities found"
            else:
                open_ports = [r for r in results_dict if r.get("state") == "open"]
                self.active_scans[scan_id].results_count = len(open_ports)
                self.active_scans[scan_id].current_target = f"Completed - {len(open_ports)} open ports, no vulnerabilities"
            
            await self._broadcast_update(scan_id)
            
            # Clean up scanner reference
            if scan_id in self.scanners:
                del self.scanners[scan_id]
            
        except asyncio.CancelledError:
            # Scan was cancelled/stopped
            logger.info(f"Scan {scan_id} was cancelled")
            if scan_id in self.active_scans:
                self.active_scans[scan_id].status = "stopped"
                self.active_scans[scan_id].end_time = datetime.now()
                if scan_id in self.scan_results and self.scan_results[scan_id].get("results"):
                    results = self.scan_results[scan_id]["results"]
                    open_ports = [r for r in results if r.get("state") == "open"]
                    self.active_scans[scan_id].results_count = len(open_ports)
                    self.active_scans[scan_id].current_target = f"Stopped - {len(open_ports)} open ports found"
                else:
                    self.active_scans[scan_id].current_target = "Stopped - no results yet"
                    self.active_scans[scan_id].results_count = 0
                await self._broadcast_update(scan_id)
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            self.active_scans[scan_id].status = "failed"
            self.active_scans[scan_id].error = str(e)
            self.active_scans[scan_id].end_time = datetime.now()
            await self._broadcast_update(scan_id)
        finally:
            # Clean up task tracking and scanner reference
            if scan_id in self.scan_tasks:
                del self.scan_tasks[scan_id]
            if scan_id in self.scanners:
                del self.scanners[scan_id]
    
    def _expand_port_ranges(self, ports):
        """Expand port ranges into individual ports."""
        expanded = []
        for port in ports:
            if isinstance(port, tuple):
                expanded.extend(range(port[0], port[1] + 1))
            else:
                expanded.append(port)
        return expanded
    
    async def _run_vuln_checks(self, scan_id: str, results: List, progress_callback=None):
        """Run vulnerability checks on scan results."""
        try:
            # Convert to ParsedScanResult objects
            from .parser import ParsedScanResult
            parsed_results = []
            for result in results:
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
                    timestamp=datetime.now()
                )
                parsed_results.append(parsed_result)
            
            # Run vulnerability checks with progress callback
            vuln_checker = VulnerabilityChecker(progress_callback=progress_callback)
            vulnerabilities = await vuln_checker.check_vulnerabilities(parsed_results)
            
            # Add vulnerabilities to results
            if vulnerabilities:
                vuln_data = []
                for vuln in vulnerabilities:
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
                
                # Store vulnerabilities
                if scan_id in self.scan_results:
                    self.scan_results[scan_id]["vulnerabilities"] = vuln_data
        
        except Exception as e:
            logger.error(f"Vulnerability check failed for scan {scan_id}: {e}")
    
    async def _broadcast_update(self, scan_id: str):
        """Broadcast scan update to connected clients."""
        if scan_id in self.active_scans:
            status = self.active_scans[scan_id]
            # Use model_dump() for Pydantic v2, dict() for v1 (with warning suppression)
            if hasattr(status, 'model_dump'):
                status_dict = status.model_dump()
            else:
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", category=DeprecationWarning, module="pydantic")
                    status_dict = status.dict()
            
            message = {
                "type": "scan_update",
                "scan_id": scan_id,
                "status": status_dict
            }
            
            # Send to all connected clients
            for client in self.connected_clients.copy():
                try:
                    await client.send_text(json.dumps(message, default=str))
                except:
                    if client in self.connected_clients:
                        self.connected_clients.remove(client)
    
    def _get_dashboard_html(self) -> str:
        """Get dashboard HTML."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GingerScan - Network Security Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            line-height: 1.5;
            background: #f8f9fa;
            color: #2c3e50;
            padding: 0;
            margin: 0;
        }
        
        .container {
            max-width: 1200px;
            margin: 40px auto;
            background: white;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05), 0 1px 2px rgba(0,0,0,0.1);
            border: 1px solid #e5e7eb;
        }
        
        .header {
            background: #ffffff;
            border-bottom: 2px solid #e5e7eb;
            padding: 40px 60px;
            text-align: left;
        }
        
        .header h1 {
            font-size: 28px;
            margin: 0 0 8px 0;
            font-weight: 600;
            color: #1f2937;
            letter-spacing: -0.025em;
        }
        
        .header p {
            font-size: 14px;
            color: #6b7280;
            margin: 4px 0;
            font-weight: 400;
        }
        
        .header-content {
            display: flex;
            align-items: center;
            gap: 30px;
        }
        
        
        .logo-container {
            background: transparent;
            padding: 0px;
            border-radius: 0px;
            box-shadow: none;
            border: none;
        }
        
        .logo {
            height: 150px;
            width: auto;
            max-width: 500px;
            object-fit: contain;
        }
        
        .header-text {
            flex: 1;
            display: flex;
            align-items: center;
        }
        
        .text-image {
            height: 120px;
            width: auto;
            max-width: 600px;
            object-fit: contain;
        }
        .scan-form {
            background: #ffffff;
            padding: 40px 60px;
            border-bottom: 1px solid #e5e7eb;
        }
        
        .scan-form h2 {
            font-size: 18px;
            margin: 0 0 24px 0;
            color: #1f2937;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding-bottom: 12px;
            border-bottom: 1px solid #d1d5db;
        }
        
        .scan-form h2:before {
            content: '';
            display: inline-block;
            width: 4px;
            height: 16px;
            background: #6b7280;
            margin-right: 12px;
            vertical-align: middle;
        }
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: #374151;
            font-size: 14px;
        }
        
        .form-group .toggle-label {
            margin-bottom: 0;
        }
        
        .form-group input, .form-group select, .form-group textarea {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid #d1d5db;
            background: #ffffff;
            color: #374151;
            font-size: 14px;
            border-radius: 0;
            box-sizing: border-box;
            transition: border-color 0.15s ease;
        }
        
        .form-group input:focus, .form-group select:focus, .form-group textarea:focus {
            outline: none;
            border-color: #6b7280;
        }
        
        /* Custom Select Options Styling */
        .form-group select option {
            padding: 12px 16px;
            color: #374151;
            background: white;
            font-size: 14px;
            font-weight: 500;
            border: none;
            transition: all 0.2s ease;
        }
        
        .form-group select option:hover {
            background: #f3f4f6;
            color: #1f2937;
        }
        
        .form-group select option:checked {
            background: #3b82f6;
            color: white;
            font-weight: 600;
        }
        
        .form-group select option:focus {
            background: #dbeafe;
            color: #1e40af;
        }
        
        .form-row {
            display: flex;
            gap: 20px;
            align-items: flex-start;
        }
        
        .form-row .form-group {
            flex: 1;
            display: flex;
            flex-direction: column;
        }
        
        .btn {
            background: #ffffff;
            color: #374151;
            padding: 12px 20px;
            border: 1px solid #d1d5db;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.15s ease;
            margin-right: 12px;
        }
        
        .btn:hover {
            background: #f9fafb;
            border-color: #9ca3af;
            color: #1f2937;
        }
        
        .btn:disabled {
            background: #f3f4f6;
            color: #9ca3af;
            cursor: not-allowed;
        }
        
        /* Toggle Switch Styles */
        .toggle-label {
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: pointer;
            font-weight: 500;
            color: #374151;
            font-size: 14px;
            min-height: 32px;
            padding: 4px 0;
            width: 100%;
        }
        
        .toggle-label span {
            flex: 1;
            text-align: left;
        }
        
        .toggle-switch {
            position: relative;
            display: inline-block;
            width: 50px;
            height: 24px;
        }
        
        .toggle-input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        
        .toggle-slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #d1d5db;
            transition: 0.3s;
            border-radius: 24px;
        }
        
        .toggle-slider:before {
            position: absolute;
            content: "";
            height: 18px;
            width: 18px;
            left: 3px;
            bottom: 3px;
            background-color: white;
            transition: 0.3s;
            border-radius: 50%;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        
        .toggle-input:checked + .toggle-slider {
            background-color: #6b7280;
        }
        
        .toggle-input:checked + .toggle-slider:before {
            transform: translateX(24px);
        }
        
        .toggle-input:focus + .toggle-slider {
            box-shadow: 0 0 0 3px rgba(107, 114, 128, 0.1);
        }
        
        /* Ensure consistent spacing for toggle form groups */
        .form-row .form-group .toggle-label {
            height: 32px;
            display: flex;
            align-items: center;
        }
        .scans-list {
            background: #ffffff;
            padding: 40px 60px;
            border-bottom: 1px solid #e5e7eb;
        }
        
        .scans-list h2 {
            font-size: 18px;
            margin: 0 0 24px 0;
            color: #1f2937;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding-bottom: 12px;
            border-bottom: 1px solid #d1d5db;
        }
        
        .scans-list h2:before {
            content: '';
            display: inline-block;
            width: 4px;
            height: 16px;
            background: #6b7280;
            margin-right: 12px;
            vertical-align: middle;
        }
        .scan-item {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            padding: 24px;
            margin: 16px 0;
            transition: all 0.15s ease;
        }
        
        .scan-item:hover {
            border-color: #d1d5db;
        }
        
        .scan-item h3 {
            color: #1f2937;
            margin: 0 0 12px 0;
            font-size: 16px;
            font-weight: normal;
        }
        
        .scan-item .scan-meta {
            color: #6b7280;
            font-size: 14px;
            margin: 6px 0;
        }
        .scan-item .scan-status {
            display: inline-block;
            padding: 4px 8px;
            background: #f3f4f6;
            color: #374151;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border: 1px solid #d1d5db;
        }
        
        .scan-item .status-pending {
            background: #fef3c7;
            color: #92400e;
            border-color: #fcd34d;
        }
        
        .scan-item .status-running {
            background: #dbeafe;
            color: #1e40af;
            border-color: #93c5fd;
        }
        
        .scan-item .status-completed {
            background: #d1fae5;
            color: #065f46;
            border-color: #a7f3d0;
        }
        
        .scan-item .status-stopped {
            background: #fef3c7;
            color: #92400e;
            border-color: #fcd34d;
        }
        
        .scan-item .status-failed {
            background: #fee2e2;
            color: #7f1d1d;
            border-color: #fca5a5;
        }
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #f3f4f6;
            overflow: hidden;
            margin: 12px 0;
        }
        
        .progress-fill {
            height: 100%;
            background: #6b7280;
            transition: width 0.3s ease;
        }
        
        .results-table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            background: white;
            border: 1px solid #e5e7eb;
            font-size: 14px;
            margin-top: 16px;
        }
        
        .results-table th, .results-table td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid #f3f4f6;
            border-right: 1px solid #f3f4f6;
        }
        
        .results-table th {
            background: #f9fafb;
            color: #374151;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .results-table th:last-child, .results-table td:last-child {
            border-right: none;
        }
        
        .results-table tr:last-child td {
            border-bottom: none;
        }
        
        .results-table tr:nth-child(even) {
            background: #fafbfc;
        }
        
        .status-open { 
            color: #065f46; 
            font-weight: 600; 
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }
        
        .status-closed { 
            color: #7f1d1d; 
            font-weight: 600; 
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }
        
        .status-filtered { 
            color: #7f1d1d; 
            font-weight: 600; 
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }
        
        /* Popup Notification Styles */
        .popup-notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
            padding: 16px 20px;
            min-width: 300px;
            max-width: 400px;
            z-index: 1000;
            transform: translateX(100%);
            transition: transform 0.3s ease-in-out;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        
        .popup-notification.show {
            transform: translateX(0);
        }
        
        .popup-notification.success {
            border-left: 4px solid #10b981;
        }
        
        .popup-notification.error {
            border-left: 4px solid #ef4444;
        }
        
        .popup-notification.info {
            border-left: 4px solid #3b82f6;
        }
        
        .popup-notification .popup-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        
        .popup-notification .popup-title {
            font-weight: 600;
            font-size: 14px;
            color: #1f2937;
        }
        
        .popup-notification .popup-close {
            background: none;
            border: none;
            font-size: 18px;
            color: #6b7280;
            cursor: pointer;
            padding: 0;
            width: 20px;
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .popup-notification .popup-close:hover {
            color: #374151;
        }
        
        .popup-notification .popup-message {
            font-size: 13px;
            color: #4b5563;
            line-height: 1.4;
        }
        
        /* Confirmation Modal Styles */
        .confirmation-modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 2000;
            display: flex;
            align-items: center;
            justify-content: center;
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s ease;
        }
        
        .confirmation-modal.show {
            opacity: 1;
            visibility: visible;
        }
        
        .confirmation-content {
            background: white;
            border-radius: 12px;
            padding: 24px;
            max-width: 400px;
            width: 90%;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            transform: scale(0.9);
            transition: transform 0.3s ease;
        }
        
        .confirmation-modal.show .confirmation-content {
            transform: scale(1);
        }
        
        .confirmation-title {
            font-size: 18px;
            font-weight: 600;
            color: #1f2937;
            margin: 0 0 12px 0;
        }
        
        .confirmation-message {
            font-size: 14px;
            color: #4b5563;
            line-height: 1.5;
            margin: 0 0 20px 0;
        }
        
        .confirmation-buttons {
            display: flex;
            gap: 12px;
            justify-content: flex-end;
        }
        
        .confirmation-btn {
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .confirmation-btn.cancel {
            background: #f3f4f6;
            color: #374151;
        }
        
        .confirmation-btn.cancel:hover {
            background: #e5e7eb;
        }
        
        .confirmation-btn.confirm {
            background: #dc2626;
            color: white;
        }
        
        .confirmation-btn.confirm:hover {
            background: #b91c1c;
        }
        
        /* Pagination Styles - Matching Dashboard Design */
        .paginated-table-container {
            margin-top: 24px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            overflow: hidden;
            width: 100%;
            max-width: 100%;
            box-sizing: border-box;
        }
        
        .table-info {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 20px;
            background: #f8f9fa;
            border-bottom: 1px solid #e5e7eb;
            font-size: 14px;
        }
        
        .total-items {
            font-weight: 600;
            color: #374151;
            font-size: 14px;
        }
        
        .page-info {
            font-size: 14px;
            color: #6b7280;
            font-weight: 500;
        }
        
        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 8px;
            padding: 16px 20px;
            background: #f8f9fa;
            border-top: 1px solid #e5e7eb;
            width: 100%;
            box-sizing: border-box;
        }
        
        .pagination-btn {
            background: #ffffff;
            color: #374151;
            padding: 12px 20px;
            border: 1px solid #d1d5db;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.15s ease;
            border-radius: 6px;
            min-width: 44px;
            text-align: center;
        }
        
        .pagination-btn:hover:not(:disabled) {
            background: #f9fafb;
            border-color: #9ca3af;
            color: #1f2937;
        }
        
        .pagination-btn:disabled {
            background: #f3f4f6;
            color: #9ca3af;
            cursor: not-allowed;
        }
        
        .page-numbers {
            display: flex;
            gap: 6px;
            margin: 0 12px;
            flex-wrap: wrap;
            justify-content: center;
            max-width: 100%;
            overflow-x: auto;
        }
        
        .page-number {
            background: #ffffff;
            color: #374151;
            padding: 12px 16px;
            border: 1px solid #d1d5db;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.15s ease;
            border-radius: 6px;
            min-width: 44px;
            text-align: center;
        }
        
        .page-number:hover {
            background: #f9fafb;
            border-color: #9ca3af;
            color: #1f2937;
        }
        
        .page-number.active {
            background: #3b82f6;
            color: white;
            border-color: #3b82f6;
            font-weight: 600;
        }
        
        .page-number.active:hover {
            background: #2563eb;
            border-color: #2563eb;
        }
        
        .page-ellipsis {
            padding: 12px 8px;
            color: #6b7280;
            font-weight: 500;
            font-size: 14px;
        }
        
        /* Responsive pagination */
        @media (max-width: 768px) {
            .pagination {
                flex-wrap: wrap;
                gap: 6px;
                padding: 12px 16px;
            }
            
            .pagination-btn, .page-number {
                padding: 10px 14px;
                font-size: 13px;
                min-width: 36px;
            }
            
            .page-numbers {
                margin: 0 8px;
                gap: 4px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <div class="logo-container">
                    <img src="assets/logo.png" alt="GingerScan Logo" class="logo">
                </div>
                <div class="header-text">
                    <img src="assets/text.png" alt="GingerScan Text" class="text-image">
                </div>  
            </div>
        </div>
        
        <div class="scan-form">
            <h2>Scan Configuration</h2>
            <form id="scanForm">
                <div class="form-group">
                    <label for="targets">Targets (one per line):</label>
                    <textarea id="targets" rows="3" placeholder="192.168.1.1&#10;192.168.1.0/24&#10;example.com"></textarea>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="ports">Ports:</label>
                        <input type="text" id="ports" value="1-1000" placeholder="1-1000, 22, 80, 443">
                    </div>
                    <div class="form-group">
                        <label for="scanType">Scan Type:</label>
                        <select id="scanType">
                            <option value="tcp_connect">TCP Connect</option>
                            <option value="tcp_syn">TCP SYN</option>
                            <option value="udp">UDP</option>
                        </select>
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="timeout">Timeout (seconds):</label>
                        <input type="number" id="timeout" value="3" min="1" max="30">
                    </div>
                    <div class="form-group">
                        <label for="threads">Threads:</label>
                        <input type="number" id="threads" value="50" min="1" max="200">
                    </div>
                </div>
                
                <div class="form-row" style="display: none;">
                    <div class="form-group">
                        <label class="toggle-label">
                            <span>Banner Grabbing</span>
                            <div class="toggle-switch">
                                <input type="checkbox" id="bannerGrab" class="toggle-input" checked>
                                <span class="toggle-slider"></span>
                            </div>
                        </label>
                    </div>
                    <div class="form-group">
                        <label class="toggle-label">
                            <span>Host Discovery</span>
                            <div class="toggle-switch">
                                <input type="checkbox" id="hostDiscovery" class="toggle-input" checked>
                                <span class="toggle-slider"></span>
                            </div>
                        </label>
                    </div>
                    <div class="form-group">
                        <label class="toggle-label">
                            <span>OS Detection</span>
                            <div class="toggle-switch">
                                <input type="checkbox" id="osDetection" class="toggle-input" checked>
                                <span class="toggle-slider"></span>
                            </div>
                        </label>
                    </div>
                    <div class="form-group">
                        <label class="toggle-label">
                            <span>IP Information</span>
                            <div class="toggle-switch">
                                <input type="checkbox" id="ipInfo" class="toggle-input" checked>
                                <span class="toggle-slider"></span>
                            </div>
                        </label>
                    </div>
                    <div class="form-group">
                        <label class="toggle-label">
                            <span>Vulnerability Checks</span>
                            <div class="toggle-switch">
                                <input type="checkbox" id="vulnCheck" class="toggle-input" checked>
                                <span class="toggle-slider"></span>
                            </div>
                        </label>
                    </div>
                </div>
                
                <button type="submit" class="btn" id="startScan">Start Scan</button>
            </form>
        </div>
        
        <div class="scans-list">
            <h2>Scan Management</h2>
            <div id="scansList">
                <p>No active scans</p>
            </div>
        </div>
    </div>
    
    <script>
        let ws = null;
        let activeScans = {};
        
        // Popup notification system
        function showPopup(type, title, message, duration = 5000) {
            const popup = document.createElement('div');
            popup.className = `popup-notification ${type}`;
            popup.innerHTML = `
                <div class="popup-header">
                    <div class="popup-title">${title}</div>
                    <button class="popup-close" onclick="closePopup(this)">&times;</button>
                </div>
                <div class="popup-message">${message}</div>
            `;
            
            document.body.appendChild(popup);
            
            // Show popup with animation
            setTimeout(() => {
                popup.classList.add('show');
            }, 100);
            
            // Auto-close after duration
            setTimeout(() => {
                closePopup(popup.querySelector('.popup-close'));
            }, duration);
        }
        
        function closePopup(closeButton) {
            const popup = closeButton.closest('.popup-notification');
            popup.classList.remove('show');
            setTimeout(() => {
                if (popup.parentNode) {
                    popup.parentNode.removeChild(popup);
                }
            }, 300);
        }
        
        // Confirmation modal system
        function showConfirmation(title, message, onConfirm, onCancel = null) {
            const modal = document.createElement('div');
            modal.className = 'confirmation-modal';
            modal.innerHTML = `
                <div class="confirmation-content">
                    <div class="confirmation-title">${title}</div>
                    <div class="confirmation-message">${message}</div>
                    <div class="confirmation-buttons">
                        <button class="confirmation-btn cancel" onclick="closeConfirmation(this)">Cancel</button>
                        <button class="confirmation-btn confirm" onclick="confirmAction(this)">Confirm</button>
                    </div>
                </div>
            `;
            
            // Store callbacks in the modal element
            modal._onConfirm = onConfirm;
            modal._onCancel = onCancel;
            
            document.body.appendChild(modal);
            
            // Show modal with animation
            setTimeout(() => {
                modal.classList.add('show');
            }, 10);
            
            // Close on background click
            modal.addEventListener('click', function(e) {
                if (e.target === modal) {
                    closeConfirmation(modal.querySelector('.cancel'));
                }
            });
        }
        
        function closeConfirmation(button) {
            const modal = button.closest('.confirmation-modal');
            modal.classList.remove('show');
            setTimeout(() => {
                if (modal.parentNode) {
                    modal.parentNode.removeChild(modal);
                }
            }, 300);
        }
        
        function confirmAction(button) {
            const modal = button.closest('.confirmation-modal');
            if (modal._onConfirm) {
                modal._onConfirm();
            }
            closeConfirmation(button);
        }
        
        // Initialize WebSocket connection
        function initWebSocket() {
            const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${protocol}//${location.host}/ws`);
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                console.log('WebSocket update received:', data);
                if (data.type === 'scan_update') {
                    updateScanStatus(data.scan_id, data.status);
                }
            };
            
            ws.onopen = function() {
                console.log('WebSocket connected');
            };
            
            ws.onclose = function() {
                console.log('WebSocket disconnected, reconnecting...');
                setTimeout(initWebSocket, 1000);
            };
            
            ws.onerror = function(error) {
                console.error('WebSocket error:', error);
            };
        }
        
        // Start WebSocket connection
        initWebSocket();
        
        // Handle scan form submission
        document.getElementById('scanForm').addEventListener('submit', function(e) {
            e.preventDefault();
            console.log('Form submitted!');
            
            const targets = document.getElementById('targets').value.split('\\n').filter(function(t) { return t.trim(); });
            const ports = document.getElementById('ports').value.split(',').map(function(p) { return p.trim(); });
            
            console.log('Targets:', targets);
            console.log('Ports:', ports);
            
            const scanRequest = {
                targets: targets,
                ports: ports,
                scan_type: document.getElementById('scanType').value,
                timeout: parseFloat(document.getElementById('timeout').value),
                threads: parseInt(document.getElementById('threads').value),
                banner_grab: document.getElementById('bannerGrab').checked,
                host_discovery: document.getElementById('hostDiscovery').checked,
                os_detection: document.getElementById('osDetection').checked,
                ip_info: document.getElementById('ipInfo').checked,
                vuln_check: document.getElementById('vulnCheck').checked
            };
            
            console.log('Scan request:', scanRequest);
            console.log('OS Detection toggle value:', document.getElementById('osDetection').checked);
            console.log('OS Detection element:', document.getElementById('osDetection'));
            console.log('All form elements:');
            console.log('- bannerGrab:', document.getElementById('bannerGrab').checked);
            console.log('- hostDiscovery:', document.getElementById('hostDiscovery').checked);
            console.log('- osDetection:', document.getElementById('osDetection').checked);
            console.log('- vulnCheck:', document.getElementById('vulnCheck').checked);
            
            // Debug: Check if the toggle is actually working
            const osToggle = document.getElementById('osDetection');
            console.log('OS Toggle element found:', !!osToggle);
            console.log('OS Toggle checked state:', osToggle ? osToggle.checked : 'N/A');
            console.log('OS Toggle value:', osToggle ? osToggle.value : 'N/A');
            
            fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(scanRequest)
            })
            .then(function(response) {
                console.log('Response status:', response.status);
                return response.json();
            })
            .then(function(result) {
                console.log('Response result:', result);
                
                if (result.status === 'started') {
                    console.log('Scan response message:', result.message);
                    console.log('Created scans:', result.scan_ids);
                    document.getElementById('startScan').disabled = true;
                    showPopup('success', 'Scans Started', result.message);
                    
                    // Load all scans from backend to get correct status
                    loadScans();
                } else {
                    showPopup('error', 'Scan Error', result.message);
                }
            })
            .catch(function(error) {
                console.error('Error:', error);
                showPopup('error', 'Connection Error', 'Error starting scan: ' + error.message);
            });
        });
        
        // Add scan to list
        function addScanToList(scanId) {
            console.log('addScanToList called with:', scanId);
            
            // Determine if this is the first scan (running) or pending
            const isFirstScan = !Object.keys(activeScans).some(id => id.includes(scanId.split('_').slice(-2, -1)[0]));
            
            activeScans[scanId] = {
                scan_id: scanId,
                status: isFirstScan ? 'running' : 'pending',
                progress: 0,
                results_count: 0,
                start_time: isFirstScan ? new Date().toISOString() : null
            };
            console.log('activeScans after adding:', activeScans);
            updateScansList();
        }
        
        // Update scan status
        function updateScanStatus(scanId, status) {
            if (activeScans[scanId]) {
                // Use the start_time from backend if provided, otherwise preserve existing
                const newStartTime = status.start_time || activeScans[scanId].start_time;
                activeScans[scanId] = Object.assign({}, status, {start_time: newStartTime});
                updateScansList();
                
                // Check if all scans are completed, failed, or stopped
                const allScanIds = Object.keys(activeScans);
                const allCompleted = allScanIds.every(scanId => {
                    const scanStatus = activeScans[scanId].status;
                    return scanStatus === 'completed' || scanStatus === 'failed' || scanStatus === 'stopped';
                });
                
                if (allCompleted && allScanIds.length > 0) {
                    document.getElementById('startScan').disabled = false;
                }
            }
        }
        
        // Update scans list display
        function updateScansList() {
            console.log('updateScansList called');
            const scansList = document.getElementById('scansList');
            const scanIds = Object.keys(activeScans);
            console.log('scanIds:', scanIds);
            console.log('activeScans:', activeScans);
            
            if (scanIds.length === 0) {
                scansList.innerHTML = '<p style="text-align: center; color: #6c757d; font-style: italic;">No active scans</p>';
                return;
            }
            
            let html = '';
            // Sort scanIds by priority: RUNNING first, then PENDING, then others
            const sortedScanIds = scanIds.sort((a, b) => {
                const scanA = activeScans[a];
                const scanB = activeScans[b];
                
                // Define priority order
                const priority = {
                    'running': 1,
                    'pending': 2,
                    'completed': 3,
                    'stopped': 3,  // Same priority as completed - sort by time
                    'failed': 4
                };
                
                const priorityA = priority[scanA.status] || 6;
                const priorityB = priority[scanB.status] || 6;
                
                // If different priorities, sort by priority
                if (priorityA !== priorityB) {
                    return priorityA - priorityB;
                }
                
                // If same priority, sort by completion/stop time for finished scans, otherwise by scan ID
                if (priorityA >= 3) { // completed, failed, or stopped
                    // For finished scans, sort by end_time (most recent first)
                    const timeA = new Date(scanA.end_time || 0).getTime();
                    const timeB = new Date(scanB.end_time || 0).getTime();
                    return timeB - timeA; // Most recent first (descending order)
                } else {
                    // For running/pending scans, sort by scan ID (creation order)
                    return a.localeCompare(b);
                }
            });
            
            sortedScanIds.forEach(scanId => {
                const scan = activeScans[scanId];
                const statusClass = `status-${scan.status}`;
                const scanDate = scan.start_time ? new Date(scan.start_time).toLocaleString() : 'Not started';
                
                // Extract target from scan ID for better display
                // Format: scan_217_117_176_208_794628 -> 217.117.176.208
                const parts = scanId.replace('scan_', '').split('_');
                const ipParts = parts.slice(0, -1); // Remove last part (unique ID)
                const targetDisplay = ipParts.join('.');
                
                // Progress bar HTML
                const progressHtml = scan.status === 'running' ? `
                    <div class="progress-bar" style="background: #e9ecef; border-radius: 10px; height: 8px; margin: 10px 0;">
                        <div class="progress-fill" style="background: linear-gradient(90deg, #007acc, #0056b3); height: 100%; border-radius: 10px; width: ${scan.progress || 0}%; transition: width 0.5s ease;"></div>
                    </div>
                ` : '';
                
                // Current target info
                const targetInfo = scan.current_target && scan.status === 'running' ? `
                    <div class="scan-meta" style="font-style: italic; color: #007acc;">
                        Scanning: ${scan.current_target}
                    </div>
                ` : '';
                
                // Status-specific information
                let statusInfo = '';
                if (scan.status === 'running') {
                    statusInfo = `<div class="scan-meta">Progress: ${Math.round(scan.progress || 0)}% | Results: ${scan.results_count || 0}</div>`;
                } else if (scan.status === 'failed') {
                    statusInfo = `<div class="scan-meta" style="color: #dc3545;">❌ Failed: ${scan.error || 'Unknown error'}</div>`;
                } 
                
                html += `
                    <div class="scan-item">
                        <h3><strong>${targetDisplay}</strong><span class="scan-meta"> #${scanId.split('_').pop()}</span></h3>
                        <div class="scan-meta">
                            <span class="scan-status ${statusClass}">${scan.status.toUpperCase()}</span>
                            <span style="margin-left: 10px;">Started: ${scanDate}</span>
                        </div>
                        ${statusInfo}
                        ${targetInfo}
                        ${progressHtml}
                        ${scan.status === 'completed' ? `
                            <div style="margin-top: 10px;">
                                <button onclick="viewResults('${scanId}')" class="btn" style="margin-right: 10px;">View Results</button>
                                <button onclick="generateReport('${scanId}')" class="btn" style="margin-right: 10px;">Generate Report</button>
                                <button onclick="viewVulnerabilities('${scanId}')" class="btn">View Vulnerabilities</button>
                            </div>
                        ` : scan.status === 'running' ? `
                            <div style="margin-top: 10px;">
                                <button onclick="stopScan('${scanId}')" class="btn" style="background: #dc3545; color: white;">Stop Scan</button>
                            </div>
                        ` : scan.status === 'stopped' ? `
                            <div style="margin-top: 10px; display: flex; align-items: center; justify-content: space-between;">
                                <div>
                                    <button onclick="viewResults('${scanId}')" class="btn" style="margin-right: 10px;">View Results</button>
                                    <button onclick="generateReport('${scanId}')" class="btn" style="margin-right: 10px;">Generate Report</button>
                                </div>
                            </div>
                        ` : scan.status === 'failed' ? `
                            <div style="margin-top: 10px;">
                                <span style="color: #dc3545; font-weight: bold;">
                                    ❌ Scan failed: ${scan.error || 'Unknown error'}
                                </span>
                            </div>
                        ` : ''}
                    </div>
                `;
            });
            
            scansList.innerHTML = html;
        }
        
        // View scan results
        async function viewResults(scanId) {
            try {
                const response = await fetch(`/api/scan/${scanId}/results`);
                const data = await response.json();
                
                // Display results in a modal or new page
                displayResults(data);
            } catch (error) {
                showPopup('error', 'Results Error', 'Error loading results: ' + error.message);
            }
        }
        
        // Generate report
        async function generateReport(scanId) {
            try {
                const response = await fetch(`/api/scan/${scanId}/report?format=html`);
                const html = await response.text();
                
                // Open report in new window
                const newWindow = window.open('', '_blank');
                newWindow.document.write(html);
            } catch (error) {
                showPopup('error', 'Report Error', 'Error generating report: ' + error.message);
            }
        }
        
        // Export results
        async function exportResults(scanId, format) {
            try {
                const response = await fetch(`/api/scan/${scanId}/export?format=${format}`);
                
                if (!response.ok) {
                    throw new Error(`Export failed: ${response.statusText}`);
                }
                
                // Get filename from Content-Disposition header or use default
                const contentDisposition = response.headers.get('Content-Disposition');
                let filename = `${scanId}_results.${format}`;
                if (contentDisposition) {
                    const filenameMatch = contentDisposition.match(/filename="?([^"]+)"?/);
                    if (filenameMatch) {
                        filename = filenameMatch[1];
                    }
                }
                
                // Create blob and download
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
                
                showPopup('success', 'Export Successful', `Results exported to ${filename}`);
            } catch (error) {
                showPopup('error', 'Export Error', 'Error exporting results: ' + error.message);
            }
        }
        
        // Stop scan
        async function stopScan(scanId) {
            showConfirmation(
                'Stop Scan',
                'Are you sure you want to stop this scan? Partial results will be preserved.',
                async function() {
                    try {
                        const response = await fetch(`/api/scan/${scanId}/stop`, {
                            method: 'POST'
                        });
                        const data = await response.json();
                        
                        if (response.ok) {
                            showPopup('success', 'Scan Stopped', 'Scan stopped successfully! Partial results have been preserved.');
                            // Update the scan status immediately
                            if (activeScans[scanId]) {
                                activeScans[scanId].status = 'stopped';
                                activeScans[scanId].end_time = new Date().toISOString();
                                updateScansList();
                            }
                            // Enable the start button
                            document.getElementById('startScan').disabled = false;
                        } else {
                            showPopup('error', 'Stop Error', 'Error stopping scan: ' + data.detail);
                        }
                    } catch (error) {
                        showPopup('error', 'Stop Error', 'Error stopping scan: ' + error.message);
                    }
                }
            );
        }
        
        // Display results
        function displayResults(data) {
            const modal = document.createElement('div');
            modal.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0,0,0,0.5);
                z-index: 1000;
                display: flex;
                justify-content: center;
                align-items: center;
            `;
            
            const content = document.createElement('div');
            content.style.cssText = `
                background: white;
                padding: 20px;
                border-radius: 10px;
                max-width: 80%;
                max-height: 80%;
                overflow: auto;
            `;
            
            let html = '<h2>Scan Results</h2>';
            html += '<table class="results-table">';
            html += '<tr><th>Host</th><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Banner</th></tr>';
            
            data.results.forEach(result => {
                if (result.type !== 'vulnerabilities') {
                    const stateClass = `status-${result.state.replace('|', '-')}`;
                    // Convert state display to match report terminology
                    let displayState = result.state;
                    if (result.state === 'filtered') {
                        displayState = 'Closed';
                    } else if (result.state === 'open|filtered') {
                        displayState = 'Open|Closed';
                    }
                    
                    html += `
                        <tr>
                            <td>${result.host}</td>
                            <td>${result.port}</td>
                            <td>${result.protocol}</td>
                            <td class="${stateClass}">${displayState}</td>
                            <td>${result.service || '-'}</td>
                            <td>${result.banner || '-'}</td>
                        </tr>
                    `;
                }
            });
            
            html += '</table>';
            html += '<br><button onclick="this.parentElement.parentElement.remove()" class="btn">Close</button>';
            
            content.innerHTML = html;
            modal.appendChild(content);
            document.body.appendChild(modal);
        }
        
        // Load initial scans
        async function loadScans() {
            try {
                const response = await fetch('/api/scans');
                const data = await response.json();
                
                // Load active scans
                for (const scanId of data.active_scans) {
                    const statusResponse = await fetch(`/api/scan/${scanId}/status`);
                    const status = await statusResponse.json();
                    // Only add start_time if status is running/completed/failed/stopped but missing start_time
                    if (!status.start_time && status.status !== 'pending') {
                        status.start_time = new Date().toISOString();
                    }
                    activeScans[scanId] = status;
                }
                
                updateScansList();
            } catch (error) {
                console.error('Error loading scans:', error);
            }
        }
        
        // Load scans on page load
        loadScans();
        
        // View vulnerabilities
        async function viewVulnerabilities(scanId) {
            try {
                const response = await fetch(`/api/scan/${scanId}/results`);
                const data = await response.json();
                
                if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                    let html = `
                        <style>
                            .vuln-modal {
                                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                                color: #374151;
                            }
                            .vuln-modal h2 {
                                color: #1f2937;
                                font-size: 1.5em;
                                margin-bottom: 20px;
                                padding-bottom: 10px;
                                border-bottom: 2px solid #e5e7eb;
                            }
                            .vuln-card {
                                background: white;
                                border: 1px solid #e5e7eb;
                                border-left: 3px solid #9ca3af;
                                padding: 24px;
                                margin: 16px 0;
                            }
                            .vuln-card.high { border-left-color: #7f1d1d; }
                            .vuln-card.medium { border-left-color: #92400e; }
                            .vuln-card.low { border-left-color: #a16207; }
                            .vuln-card.info { border-left-color: #1e40af; }
                            .vuln-header {
                                display: flex;
                                justify-content: space-between;
                                align-items: flex-start;
                                margin-bottom: 16px;
                            }
                            .vuln-title {
                                font-size: 16px;
                                font-weight: 600;
                                color: #1f2937;
                                margin: 0;
                            }
                            .vuln-severity {
                                padding: 4px 8px;
                                background: #f3f4f6;
                                color: #374151;
                                font-size: 11px;
                                font-weight: 600;
                                text-transform: uppercase;
                                letter-spacing: 0.05em;
                                border: 1px solid #d1d5db;
                            }
                            .vuln-severity.high { background: #fee2e2; color: #7f1d1d; border-color: #fca5a5; }
                            .vuln-severity.medium { background: #fef3c7; color: #92400e; border-color: #fcd34d; }
                            .vuln-severity.low { background: #fef9e2; color: #a16207; border-color: #fde047; }
                            .vuln-severity.info { background: #dbeafe; color: #1e40af; border-color: #93c5fd; }
                            .vuln-details {
                                background: #fafbfc;
                                padding: 16px;
                                border: 1px solid #f3f4f6;
                                margin-top: 12px;
                            }
                            .vuln-meta {
                                display: grid;
                                grid-template-columns: 1fr 1fr;
                                gap: 12px;
                                margin-bottom: 16px;
                                font-size: 0.9em;
                            }
                            .vuln-meta strong {
                                color: #6b7280;
                                font-weight: 600;
                            }
                            .vuln-description {
                                margin-top: 12px;
                                color: #374151;
                                font-size: 0.9em;
                                line-height: 1.5;
                            }
                            .vuln-extra {
                                margin-top: 12px;
                                padding-top: 12px;
                                border-top: 1px solid #e5e7eb;
                                font-size: 0.85em;
                            }
                            .vuln-extra strong {
                                color: #6b7280;
                                font-weight: 600;
                            }
                            .vuln-extra code {
                                background: #f3f4f6;
                                padding: 2px 6px;
                                border-radius: 4px;
                                font-family: 'Monaco', 'Menlo', monospace;
                                font-size: 0.9em;
                            }
                        </style>
                        <div class="vuln-modal">
                            <h2>Security Vulnerabilities Found</h2>
                    `;
                    
                    data.vulnerabilities.forEach(vuln => {
                        const severity = vuln.severity.toLowerCase();
                        const severityClass = `vuln-severity ${severity}`;
                        const cardClass = `vuln-card ${severity}`;
                        
                        html += `
                            <div class="${cardClass}">
                                <div class="vuln-header">
                                    <div class="vuln-title">${vuln.vuln_type || 'Unknown Vulnerability'}</div>
                                    <div class="${severityClass}">${vuln.severity || 'INFO'}</div>
                                </div>
                                <div class="vuln-details">
                                    <div class="vuln-meta">
                                        <div><strong>Target:</strong> ${vuln.host || 'Unknown'}:${vuln.port || 'Unknown'}</div>
                                        <div><strong>Service:</strong> ${vuln.service || 'Unknown'}</div>
                                        <div><strong>Type:</strong> ${vuln.vuln_type || 'Unknown'}</div>
                                    </div>
                                    <div class="vuln-description">
                                        <strong>Description:</strong> ${vuln.description || 'No description available'}
                                    </div>
                                    ${vuln.cve || vuln.references ? `
                                        <div class="vuln-extra">
                                            ${vuln.cve ? `<div><strong>CVE:</strong> <code>${vuln.cve}</code></div>` : ''}
                                            ${vuln.references ? `<div><strong>References:</strong> ${vuln.references}</div>` : ''}
                                        </div>
                                    ` : ''}
                                </div>
                            </div>
                        `;
                    });
                    
                    html += '</div>';
                    
                    // Create modal
                    const modal = document.createElement('div');
                    modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); z-index: 1000; display: flex; align-items: center; justify-content: center; padding: 20px;';
                    
                    const content = document.createElement('div');
                    content.style.cssText = 'background: white; padding: 30px; border-radius: 12px; max-width: 90%; max-height: 90%; overflow-y: auto; box-shadow: 0 20px 60px rgba(0,0,0,0.3); position: relative;';
                    content.innerHTML = html + '<button onclick="this.parentElement.parentElement.remove()" class="btn" style="margin-top: 20px; width: 100%;">Close</button>';
                    
                    modal.appendChild(content);
                    document.body.appendChild(modal);
                } else {
                    showPopup('info', 'No Vulnerabilities', 'No vulnerabilities found for this scan.');
                }
            } catch (error) {
                console.error('Error loading vulnerabilities:', error);
                showPopup('error', 'Vulnerabilities Error', 'Error loading vulnerabilities: ' + error.message);
            }
        }
    </script>
</body>
</html>
        """
    
    def run(self, host: str = "0.0.0.0", port: int = 8000):
        """Run the web dashboard."""
        # Configure uvicorn logging to avoid duplicate messages
        log_config = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "format": "%(levelname)s: %(message)s",
                },
            },
            "handlers": {
                "default": {
                    "formatter": "default",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                },
            },
            "root": {
                "level": "INFO",
                "handlers": ["default"],
            },
            "loggers": {
                "uvicorn": {
                    "level": "INFO",
                    "handlers": ["default"],
                    "propagate": False,
                },
                "uvicorn.error": {
                    "level": "INFO", 
                    "handlers": ["default"],
                    "propagate": False,
                },
                "uvicorn.access": {
                    "level": "INFO",
                    "handlers": ["default"], 
                    "propagate": False,
                },
            },
        }
        
        uvicorn.run(self.app, host=host, port=port, log_config=log_config)


def main():
    """Main function for running the web dashboard."""
    dashboard = WebDashboard()
    dashboard.run()


if __name__ == "__main__":
    main()
