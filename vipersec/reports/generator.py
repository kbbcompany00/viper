"""
Report generation for ViperSec scan results
"""

import json
import asyncio
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime
import logging

from ..core.config import ReportConfig


class ReportGenerator:
    """Generate security reports in various formats"""
    
    def __init__(self, config: ReportConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Ensure template directory exists
        self.template_dir = Path(config.template_dir)
        self.template_dir.mkdir(exist_ok=True)
    
    async def generate(self, results: Dict[str, Any], output_path: str, format: str = "html") -> str:
        """
        Generate report in specified format
        
        Args:
            results: Scan results
            output_path: Output file path
            format: Report format (html, json, markdown, pdf)
            
        Returns:
            Path to generated report
        """
        
        self.logger.info(f"Generating {format} report to {output_path}")
        
        if format.lower() == 'json':
            return await self._generate_json_report(results, output_path)
        elif format.lower() == 'html':
            return await self._generate_html_report(results, output_path)
        elif format.lower() == 'markdown':
            return await self._generate_markdown_report(results, output_path)
        elif format.lower() == 'pdf':
            return await self._generate_pdf_report(results, output_path)
        else:
            raise ValueError(f"Unsupported report format: {format}")
    
    async def _generate_json_report(self, results: Dict[str, Any], output_path: str) -> str:
        """Generate JSON report"""
        
        # Enhance results with metadata
        enhanced_results = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'generator': 'ViperSec 2025',
                'format': 'json',
                'version': '1.0'
            },
            **results
        }
        
        with open(output_path, 'w') as f:
            json.dump(enhanced_results, f, indent=2, default=str)
        
        return output_path
    
    async def _generate_html_report(self, results: Dict[str, Any], output_path: str) -> str:
        """Generate HTML report"""
        
        html_content = self._create_html_report(results)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    async def _generate_markdown_report(self, results: Dict[str, Any], output_path: str) -> str:
        """Generate Markdown report"""
        
        md_content = self._create_markdown_report(results)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        return output_path
    
    async def _generate_pdf_report(self, results: Dict[str, Any], output_path: str) -> str:
        """Generate PDF report"""
        
        # First generate HTML, then convert to PDF
        html_content = self._create_html_report(results)
        
        try:
            # This would require weasyprint or similar library
            # For now, we'll save as HTML with PDF extension
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.warning("PDF generation not fully implemented, saved as HTML")
            
        except Exception as e:
            self.logger.error(f"PDF generation failed: {e}")
            raise
        
        return output_path
    
    def _create_html_report(self, results: Dict[str, Any]) -> str:
        """Create HTML report content"""
        
        vulnerabilities = results.get('vulnerabilities', [])
        statistics = results.get('statistics', {})
        target = results.get('target', 'Unknown')
        start_time = results.get('start_time', 'Unknown')
        duration = results.get('duration', 0)
        
        # Group vulnerabilities by severity
        vuln_by_severity = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': [],
            'INFO': []
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO').upper()
            if severity in vuln_by_severity:
                vuln_by_severity[severity].append(vuln)
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ViperSec 2025 Security Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
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
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #2c3e50;
            margin: 0;
            font-size: 2.5em;
        }}
        .header .subtitle {{
            color: #7f8c8d;
            font-size: 1.2em;
            margin-top: 10px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            color: #2c3e50;
        }}
        .summary-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #3498db;
        }}
        .severity-critical {{ color: #e74c3c; }}
        .severity-high {{ color: #f39c12; }}
        .severity-medium {{ color: #f1c40f; }}
        .severity-low {{ color: #2ecc71; }}
        .severity-info {{ color: #3498db; }}
        
        .vulnerability {{
            border: 1px solid #ddd;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .vulnerability-header {{
            padding: 15px;
            font-weight: bold;
            cursor: pointer;
        }}
        .vulnerability-header.critical {{ background: #e74c3c; color: white; }}
        .vulnerability-header.high {{ background: #f39c12; color: white; }}
        .vulnerability-header.medium {{ background: #f1c40f; color: #2c3e50; }}
        .vulnerability-header.low {{ background: #2ecc71; color: white; }}
        .vulnerability-header.info {{ background: #3498db; color: white; }}
        
        .vulnerability-content {{
            padding: 20px;
            background: #f9f9f9;
        }}
        .evidence {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
            overflow-x: auto;
        }}
        .recommendation {{
            background: #d5f4e6;
            border-left: 4px solid #2ecc71;
            padding: 15px;
            margin: 10px 0;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ ViperSec 2025</h1>
            <div class="subtitle">Security Assessment Report</div>
            <div style="margin-top: 15px;">
                <strong>Target:</strong> {target}<br>
                <strong>Scan Date:</strong> {start_time}<br>
                <strong>Duration:</strong> {duration:.2f} seconds
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total Vulnerabilities</h3>
                <div class="value">{len(vulnerabilities)}</div>
            </div>
            <div class="summary-card">
                <h3>Critical</h3>
                <div class="value severity-critical">{len(vuln_by_severity['CRITICAL'])}</div>
            </div>
            <div class="summary-card">
                <h3>High</h3>
                <div class="value severity-high">{len(vuln_by_severity['HIGH'])}</div>
            </div>
            <div class="summary-card">
                <h3>Medium</h3>
                <div class="value severity-medium">{len(vuln_by_severity['MEDIUM'])}</div>
            </div>
            <div class="summary-card">
                <h3>Low</h3>
                <div class="value severity-low">{len(vuln_by_severity['LOW'])}</div>
            </div>
            <div class="summary-card">
                <h3>Info</h3>
                <div class="value severity-info">{len(vuln_by_severity['INFO'])}</div>
            </div>
        </div>
        
        <h2>Vulnerability Details</h2>
        """
        
        # Add vulnerabilities by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if vuln_by_severity[severity]:
                html += f"<h3>{severity} Severity ({len(vuln_by_severity[severity])})</h3>"
                
                for vuln in vuln_by_severity[severity]:
                    html += self._create_vulnerability_html(vuln, severity.lower())
        
        html += f"""
        <div class="footer">
            <p>Generated by ViperSec 2025 - Next-Generation AI-Driven Cybersecurity Testing Platform</p>
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
    
    <script>
        // Add click handlers for vulnerability headers
        document.querySelectorAll('.vulnerability-header').forEach(header => {{
            header.addEventListener('click', () => {{
                const content = header.nextElementSibling;
                content.style.display = content.style.display === 'none' ? 'block' : 'none';
            }});
        }});
        
        // Initially hide all vulnerability content
        document.querySelectorAll('.vulnerability-content').forEach(content => {{
            content.style.display = 'none';
        }});
    </script>
</body>
</html>
        """
        
        return html
    
    def _create_vulnerability_html(self, vuln: Dict[str, Any], severity: str) -> str:
        """Create HTML for a single vulnerability"""
        
        title = vuln.get('title', 'Unknown Vulnerability')
        description = vuln.get('description', 'No description available')
        evidence = vuln.get('evidence', {})
        recommendation = vuln.get('recommendation', 'No recommendation available')
        cwe_id = vuln.get('cwe_id', '')
        owasp_category = vuln.get('owasp_category', '')
        
        evidence_html = ""
        if evidence:
            evidence_html = f"""
            <h4>Evidence:</h4>
            <div class="evidence">
                {self._format_evidence(evidence)}
            </div>
            """
        
        return f"""
        <div class="vulnerability">
            <div class="vulnerability-header {severity}">
                {title}
                {f' - {cwe_id}' if cwe_id else ''}
                {f' ({owasp_category})' if owasp_category else ''}
            </div>
            <div class="vulnerability-content">
                <h4>Description:</h4>
                <p>{description}</p>
                
                {evidence_html}
                
                <div class="recommendation">
                    <h4>Recommendation:</h4>
                    <p>{recommendation}</p>
                </div>
            </div>
        </div>
        """
    
    def _format_evidence(self, evidence: Dict[str, Any]) -> str:
        """Format evidence for display"""
        
        formatted = []
        
        for key, value in evidence.items():
            if isinstance(value, (dict, list)):
                formatted.append(f"{key}: {json.dumps(value, indent=2)}")
            else:
                formatted.append(f"{key}: {value}")
        
        return "<br>".join(formatted)
    
    def _create_markdown_report(self, results: Dict[str, Any]) -> str:
        """Create Markdown report content"""
        
        vulnerabilities = results.get('vulnerabilities', [])
        statistics = results.get('statistics', {})
        target = results.get('target', 'Unknown')
        start_time = results.get('start_time', 'Unknown')
        duration = results.get('duration', 0)
        
        md = f"""# 🛡️ ViperSec 2025 Security Report

**Target:** {target}  
**Scan Date:** {start_time}  
**Duration:** {duration:.2f} seconds  

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | {statistics.get('critical', 0)} |
| High     | {statistics.get('high', 0)} |
| Medium   | {statistics.get('medium', 0)} |
| Low      | {statistics.get('low', 0)} |
| Info     | {statistics.get('info', 0)} |
| **Total** | **{len(vulnerabilities)}** |

## Vulnerability Details

"""
        
        # Group vulnerabilities by severity
        vuln_by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO').upper()
            if severity not in vuln_by_severity:
                vuln_by_severity[severity] = []
            vuln_by_severity[severity].append(vuln)
        
        # Add vulnerabilities by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity in vuln_by_severity:
                md += f"### {severity} Severity ({len(vuln_by_severity[severity])})\n\n"
                
                for i, vuln in enumerate(vuln_by_severity[severity], 1):
                    md += self._create_vulnerability_markdown(vuln, i)
        
        md += f"""
---

*Report generated by ViperSec 2025 on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        
        return md
    
    def _create_vulnerability_markdown(self, vuln: Dict[str, Any], index: int) -> str:
        """Create Markdown for a single vulnerability"""
        
        title = vuln.get('title', 'Unknown Vulnerability')
        description = vuln.get('description', 'No description available')
        evidence = vuln.get('evidence', {})
        recommendation = vuln.get('recommendation', 'No recommendation available')
        cwe_id = vuln.get('cwe_id', '')
        owasp_category = vuln.get('owasp_category', '')
        
        md = f"""#### {index}. {title}

**Description:** {description}

"""
        
        if cwe_id:
            md += f"**CWE ID:** {cwe_id}  \n"
        
        if owasp_category:
            md += f"**OWASP Category:** {owasp_category}  \n"
        
        if evidence:
            md += "\n**Evidence:**\n```\n"
            for key, value in evidence.items():
                md += f"{key}: {value}\n"
            md += "```\n"
        
        md += f"\n**Recommendation:** {recommendation}\n\n"
        
        return md