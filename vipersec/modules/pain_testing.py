"""
Pain testing module for stress testing and business logic attacks
"""

import asyncio
import random
from typing import Dict, List, Any

from .base import BaseModule
from ..core.config import Target
from ..core.scanner import SecurityScanner


class PainTestingModule(BaseModule):
    """Pain testing module for aggressive security testing"""
    
    def __init__(self):
        super().__init__(
            name="pain_testing",
            description="Aggressive stress testing and business logic attacks"
        )
        
        # Malformed payloads for stress testing
        self.stress_payloads = [
            # Large payloads
            "A" * 10000,
            "B" * 50000,
            
            # JSON bombs
            '{"a":' * 1000 + '1' + '}' * 1000,
            
            # XML bombs
            '<?xml version="1.0"?>' + '<root>' * 1000 + 'data' + '</root>' * 1000,
            
            # Null bytes
            "test\x00\x00\x00",
            
            # Unicode attacks
            "test\u0000\u0001\u0002",
            
            # Format string attacks
            "%s%s%s%s%s%s%s%s%s%s",
            "%x%x%x%x%x%x%x%x%x%x",
            
            # Buffer overflow attempts
            "A" * 1024,
            "A" * 2048,
            "A" * 4096,
            
            # Special characters
            "!@#$%^&*()_+-=[]{}|;':\",./<>?",
            
            # Path traversal
            "../" * 100,
            "..\\..\\..\\..\\..\\..\\..\\..\\",
            
            # Command injection attempts
            "; ls -la",
            "| whoami",
            "&& id",
            
            # Script injection
            "<script>while(1){}</script>",
            "javascript:while(1){}",
        ]
    
    async def scan(self, target: Target, scanner: SecurityScanner) -> Dict[str, Any]:
        """Perform pain testing on target"""
        
        self.logger.info(f"Starting pain testing for {target.url}")
        
        results = {
            'module': self.name,
            'vulnerabilities': [],
            'requests_made': 0
        }
        
        async with scanner:
            # Stress test forms
            await self._stress_test_forms(target, scanner)
            
            # Test resource exhaustion
            await self._test_resource_exhaustion(target, scanner)
            
            # Test business logic flaws
            await self._test_business_logic(target, scanner)
            
            # Test file upload abuse
            await self._test_file_upload_abuse(target, scanner)
        
        # Compile results
        results['vulnerabilities'] = self.get_vulnerabilities()
        results['requests_made'] = self.stats['requests_made']
        
        self.logger.info(f"Pain testing completed. Found {len(results['vulnerabilities'])} vulnerabilities")
        
        return results
    
    async def _stress_test_forms(self, target: Target, scanner: SecurityScanner):
        """Stress test forms with malformed data"""
        
        target_analysis = await scanner.analyze_target(target)
        
        for form in target_analysis.get('forms', []):
            await self._stress_test_single_form(target, scanner, form)
    
    async def _stress_test_single_form(self, target: Target, scanner: SecurityScanner, form: Dict[str, Any]):
        """Stress test a single form"""
        
        form_method = form.get('method', 'POST').upper()
        
        # Test each input field with stress payloads
        for input_field in form.get('inputs', []):
            field_name = input_field.get('name')
            field_type = input_field.get('type', 'text')
            
            if field_name and field_type not in ['submit', 'button', 'reset']:
                await self._test_field_with_stress_payloads(
                    target, scanner, field_name, form_method
                )
    
    async def _test_field_with_stress_payloads(
        self, 
        target: Target, 
        scanner: SecurityScanner, 
        field_name: str, 
        method: str
    ):
        """Test field with stress payloads"""
        
        for payload in self.stress_payloads[:10]:  # Test subset to avoid excessive requests
            try:
                if method == 'GET':
                    test_url = f"{target.url}?{field_name}={payload}"
                    response = await scanner._make_request('GET', test_url, target)
                else:
                    form_data = {field_name: payload}
                    response = await scanner._make_request('POST', target.url, target, data=form_data)
                
                self.stats['requests_made'] += 1
                
                if response:
                    # Check for error conditions
                    if self._check_stress_response(response, payload):
                        vulnerability = self.create_vulnerability(
                            title=f"Application Error with Malformed Input in {field_name}",
                            severity="LOW",
                            description=f"Application shows error or unexpected behavior with payload: {payload[:100]}...",
                            evidence={
                                'field_name': field_name,
                                'payload_preview': payload[:100],
                                'payload_length': len(payload),
                                'response_status': response.status_code,
                                'response_length': len(response.text),
                                'error_indicators': self._extract_error_indicators(response.text)
                            },
                            recommendation="Implement proper input validation and error handling",
                            cwe_id="CWE-20",
                            owasp_category="A03:2021 – Injection"
                        )
                        
                        self.add_vulnerability(vulnerability)
                        
            except Exception as e:
                self.logger.debug(f"Stress test payload failed: {e}")
    
    async def _test_resource_exhaustion(self, target: Target, scanner: SecurityScanner):
        """Test for resource exhaustion vulnerabilities"""
        
        # Test concurrent requests
        tasks = []
        for i in range(20):  # Create 20 concurrent requests
            task = asyncio.create_task(
                scanner._make_request('GET', target.url, target)
            )
            tasks.append(task)
        
        start_time = asyncio.get_event_loop().time()
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = asyncio.get_event_loop().time()
        
        self.stats['requests_made'] += len(tasks)
        
        # Analyze responses
        successful_responses = [r for r in responses if not isinstance(r, Exception) and r is not None]
        failed_responses = len(responses) - len(successful_responses)
        
        if failed_responses > len(responses) * 0.3:  # More than 30% failed
            vulnerability = self.create_vulnerability(
                title="Potential Resource Exhaustion",
                severity="MEDIUM",
                description=f"High failure rate ({failed_responses}/{len(responses)}) under concurrent load",
                evidence={
                    'total_requests': len(responses),
                    'successful_responses': len(successful_responses),
                    'failed_responses': failed_responses,
                    'total_time': end_time - start_time,
                    'failure_rate': failed_responses / len(responses)
                },
                recommendation="Implement rate limiting and proper resource management",
                cwe_id="CWE-400",
                owasp_category="A06:2021 – Vulnerable and Outdated Components"
            )
            
            self.add_vulnerability(vulnerability)
    
    async def _test_business_logic(self, target: Target, scanner: SecurityScanner):
        """Test for business logic flaws"""
        
        # Test negative values
        negative_test_params = ['amount', 'quantity', 'price', 'count', 'number']
        
        for param in negative_test_params:
            # Test negative values
            response = await scanner.test_payload(target, '-1', param, 'GET')
            if response:
                self.stats['requests_made'] += 1
                
                if response.status_code == 200 and not self._check_error_in_response(response.text):
                    vulnerability = self.create_vulnerability(
                        title=f"Business Logic Flaw: Negative Values Accepted in {param}",
                        severity="MEDIUM",
                        description=f"Application accepts negative values for parameter '{param}'",
                        evidence={
                            'parameter': param,
                            'test_value': '-1',
                            'response_status': response.status_code,
                            'response_length': len(response.text)
                        },
                        recommendation="Implement proper business logic validation",
                        cwe_id="CWE-840",
                        owasp_category="A04:2021 – Insecure Design"
                    )
                    
                    self.add_vulnerability(vulnerability)
            
            # Test extremely large values
            large_value = '999999999999999999999'
            response = await scanner.test_payload(target, large_value, param, 'GET')
            if response:
                self.stats['requests_made'] += 1
                
                if self._check_overflow_indicators(response.text):
                    vulnerability = self.create_vulnerability(
                        title=f"Potential Integer Overflow in {param}",
                        severity="LOW",
                        description=f"Application may have integer overflow with large values in '{param}'",
                        evidence={
                            'parameter': param,
                            'test_value': large_value,
                            'response_status': response.status_code,
                            'overflow_indicators': self._extract_overflow_indicators(response.text)
                        },
                        recommendation="Implement proper input validation for numeric values",
                        cwe_id="CWE-190",
                        owasp_category="A03:2021 – Injection"
                    )
                    
                    self.add_vulnerability(vulnerability)
    
    async def _test_file_upload_abuse(self, target: Target, scanner: SecurityScanner):
        """Test for file upload abuse"""
        
        target_analysis = await scanner.analyze_target(target)
        
        # Look for file upload forms
        for form in target_analysis.get('forms', []):
            file_inputs = [
                inp for inp in form.get('inputs', [])
                if inp.get('type') == 'file'
            ]
            
            if file_inputs:
                await self._test_file_upload_form(target, scanner, form, file_inputs[0])
    
    async def _test_file_upload_form(
        self, 
        target: Target, 
        scanner: SecurityScanner, 
        form: Dict[str, Any],
        file_input: Dict[str, Any]
    ):
        """Test file upload form for abuse"""
        
        # Test large file upload
        large_file_content = "A" * (10 * 1024 * 1024)  # 10MB
        
        files = {file_input.get('name', 'file'): ('large_file.txt', large_file_content)}
        
        try:
            response = await scanner._make_request(
                form.get('method', 'POST'), 
                target.url, 
                target, 
                files=files
            )
            
            self.stats['requests_made'] += 1
            
            if response and response.status_code == 200:
                vulnerability = self.create_vulnerability(
                    title="Large File Upload Accepted",
                    severity="LOW",
                    description="Application accepts very large file uploads without proper validation",
                    evidence={
                        'file_size': len(large_file_content),
                        'file_input_name': file_input.get('name'),
                        'response_status': response.status_code
                    },
                    recommendation="Implement file size limits and proper validation",
                    cwe_id="CWE-400",
                    owasp_category="A04:2021 – Insecure Design"
                )
                
                self.add_vulnerability(vulnerability)
                
        except Exception as e:
            self.logger.debug(f"File upload test failed: {e}")
    
    def _check_stress_response(self, response, payload: str) -> bool:
        """Check if response indicates stress/error condition"""
        
        # Check for error status codes
        if response.status_code >= 500:
            return True
        
        # Check for error indicators in content
        error_indicators = [
            'error', 'exception', 'stack trace', 'fatal',
            'internal server error', 'database error',
            'timeout', 'memory', 'overflow'
        ]
        
        content_lower = response.text.lower()
        
        for indicator in error_indicators:
            if indicator in content_lower:
                return True
        
        # Check for extremely long response times (would need to be measured)
        # This is simplified - in practice you'd measure actual response time
        
        return False
    
    def _check_error_in_response(self, content: str) -> bool:
        """Check if response contains error indicators"""
        
        error_patterns = [
            'error', 'invalid', 'failed', 'exception',
            'not allowed', 'forbidden', 'denied'
        ]
        
        content_lower = content.lower()
        
        return any(pattern in content_lower for pattern in error_patterns)
    
    def _check_overflow_indicators(self, content: str) -> bool:
        """Check for integer overflow indicators"""
        
        overflow_patterns = [
            'overflow', 'out of range', 'too large',
            'maximum value', 'limit exceeded'
        ]
        
        content_lower = content.lower()
        
        return any(pattern in content_lower for pattern in overflow_patterns)
    
    def _extract_error_indicators(self, content: str) -> List[str]:
        """Extract error indicators from response"""
        
        indicators = []
        error_patterns = [
            'error', 'exception', 'fatal', 'warning',
            'stack trace', 'database error', 'timeout'
        ]
        
        content_lower = content.lower()
        
        for pattern in error_patterns:
            if pattern in content_lower:
                indicators.append(pattern)
        
        return indicators
    
    def _extract_overflow_indicators(self, content: str) -> List[str]:
        """Extract overflow indicators from response"""
        
        indicators = []
        overflow_patterns = [
            'overflow', 'out of range', 'too large',
            'maximum value', 'limit exceeded'
        ]
        
        content_lower = content.lower()
        
        for pattern in overflow_patterns:
            if pattern in content_lower:
                indicators.append(pattern)
        
        return indicators