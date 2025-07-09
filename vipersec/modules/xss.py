"""
Cross-Site Scripting (XSS) detection module
"""

import re
from typing import Dict, List, Any
from urllib.parse import quote, unquote

from .base import PayloadModule
from ..core.config import Target
from ..core.scanner import SecurityScanner


class XSSModule(PayloadModule):
    """XSS vulnerability detection module"""
    
    def __init__(self):
        # XSS payloads for different contexts
        xss_payloads = [
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            
            # Event handlers
            "javascript:alert('XSS')",
            "onmouseover=alert('XSS')",
            "onfocus=alert('XSS') autofocus",
            
            # Encoded payloads
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            
            # Filter bypass
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<<SCRIPT>alert('XSS');//<</SCRIPT>",
            
            # DOM XSS
            "#<script>alert('XSS')</script>",
            "javascript:alert('XSS')//",
            
            # Polyglot payloads
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>",
            
            # WAF bypass
            "<script>alert(1)</script>",
            "<script>alert(/XSS/)</script>",
            "<script>alert`XSS`</script>",
        ]
        
        super().__init__(
            name="xss",
            description="Cross-Site Scripting vulnerability detection",
            payloads=xss_payloads
        )
        
        # XSS detection patterns
        self.detection_patterns = [
            r"<script[^>]*>.*?alert.*?</script>",
            r"<img[^>]*onerror[^>]*>",
            r"<svg[^>]*onload[^>]*>",
            r"javascript:.*?alert",
            r"on\w+\s*=.*?alert",
        ]
    
    async def scan(self, target: Target, scanner: SecurityScanner) -> Dict[str, Any]:
        """Scan for XSS vulnerabilities"""
        
        self.logger.info(f"Starting XSS scan for {target.url}")
        
        results = {
            'module': self.name,
            'vulnerabilities': [],
            'requests_made': 0,
            'payloads_tested': 0
        }
        
        async with scanner:
            # Analyze target for forms and parameters
            target_analysis = await scanner.analyze_target(target)
            
            # Test forms for XSS
            for form in target_analysis.get('forms', []):
                await self._test_form_xss(target, scanner, form)
            
            # Test URL parameters
            await self._test_url_parameters(target, scanner)
            
            # Test headers for XSS
            await self._test_header_xss(target, scanner)
        
        # Compile results
        results['vulnerabilities'] = self.get_vulnerabilities()
        results['requests_made'] = self.stats['requests_made']
        results['payloads_tested'] = self.stats['payloads_tested']
        
        self.logger.info(f"XSS scan completed. Found {len(results['vulnerabilities'])} vulnerabilities")
        
        return results
    
    async def _test_form_xss(self, target: Target, scanner: SecurityScanner, form: Dict[str, Any]):
        """Test form inputs for XSS"""
        
        for input_field in form.get('inputs', []):
            if input_field.get('type') in ['text', 'search', 'email', 'url']:
                parameter = input_field.get('name')
                if parameter:
                    await self._test_parameter_xss(
                        target, scanner, parameter, form.get('method', 'GET')
                    )
    
    async def _test_url_parameters(self, target: Target, scanner: SecurityScanner):
        """Test URL parameters for XSS"""
        
        # Common parameter names to test
        common_params = ['q', 'search', 'query', 'name', 'message', 'comment', 'text']
        
        for param in common_params:
            await self._test_parameter_xss(target, scanner, param, 'GET')
    
    async def _test_parameter_xss(
        self, 
        target: Target, 
        scanner: SecurityScanner, 
        parameter: str, 
        method: str
    ):
        """Test specific parameter for XSS"""
        
        results = await self.test_payloads(target, scanner, parameter, method)
        
        for result in results:
            if self.analyze_response(result):
                vulnerability = self.create_vulnerability(
                    title=f"Cross-Site Scripting in {parameter}",
                    severity="HIGH",
                    description=f"XSS vulnerability detected in parameter '{parameter}' using payload: {result['payload']}",
                    evidence={
                        'parameter': parameter,
                        'payload': result['payload'],
                        'method': method,
                        'response_snippet': result['content'][:500],
                        'status_code': result['status_code']
                    },
                    recommendation="Implement proper input validation and output encoding",
                    cwe_id="CWE-79",
                    owasp_category="A03:2021 – Injection"
                )
                
                self.add_vulnerability(vulnerability)
    
    async def _test_header_xss(self, target: Target, scanner: SecurityScanner):
        """Test HTTP headers for XSS"""
        
        # Headers that might be reflected
        test_headers = ['User-Agent', 'Referer', 'X-Forwarded-For']
        
        for header in test_headers:
            for payload in self.payloads[:5]:  # Test subset of payloads
                custom_headers = {header: payload}
                
                async with scanner:
                    response = await scanner._make_request(
                        'GET', target.url, target, headers=custom_headers
                    )
                    
                    if response and self._check_xss_in_response(response.text, payload):
                        vulnerability = self.create_vulnerability(
                            title=f"Cross-Site Scripting in {header} header",
                            severity="MEDIUM",
                            description=f"XSS vulnerability detected in {header} header",
                            evidence={
                                'header': header,
                                'payload': payload,
                                'response_snippet': response.text[:500]
                            },
                            recommendation="Sanitize and validate HTTP headers before processing",
                            cwe_id="CWE-79",
                            owasp_category="A03:2021 – Injection"
                        )
                        
                        self.add_vulnerability(vulnerability)
    
    def analyze_response(self, result: Dict[str, Any]) -> bool:
        """Analyze response for XSS indicators"""
        
        payload = result['payload']
        content = result['content']
        
        return self._check_xss_in_response(content, payload)
    
    def _check_xss_in_response(self, content: str, payload: str) -> bool:
        """Check if XSS payload is reflected in response"""
        
        # Direct payload reflection
        if payload in content:
            return True
        
        # URL decoded payload reflection
        decoded_payload = unquote(payload)
        if decoded_payload in content:
            return True
        
        # Pattern-based detection
        for pattern in self.detection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        # Check for script execution context
        if any(keyword in content.lower() for keyword in ['<script', 'javascript:', 'onerror', 'onload']):
            # More sophisticated analysis could be added here
            return True
        
        return False