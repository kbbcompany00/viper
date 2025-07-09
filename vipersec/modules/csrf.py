"""
Cross-Site Request Forgery (CSRF) detection module
"""

import re
from typing import Dict, List, Any
from urllib.parse import urljoin

from .base import BaseModule
from ..core.config import Target
from ..core.scanner import SecurityScanner


class CSRFModule(BaseModule):
    """CSRF vulnerability detection module"""
    
    def __init__(self):
        super().__init__(
            name="csrf",
            description="Cross-Site Request Forgery vulnerability detection"
        )
        
        # CSRF token patterns
        self.csrf_patterns = [
            r'name=["\']?csrf[_-]?token["\']?',
            r'name=["\']?_token["\']?',
            r'name=["\']?authenticity_token["\']?',
            r'name=["\']?csrfmiddlewaretoken["\']?',
            r'name=["\']?__RequestVerificationToken["\']?',
            r'X-CSRF-TOKEN',
            r'X-CSRFToken',
            r'X-XSRF-TOKEN'
        ]
    
    async def scan(self, target: Target, scanner: SecurityScanner) -> Dict[str, Any]:
        """Scan for CSRF vulnerabilities"""
        
        self.logger.info(f"Starting CSRF scan for {target.url}")
        
        results = {
            'module': self.name,
            'vulnerabilities': [],
            'requests_made': 0
        }
        
        async with scanner:
            # Analyze target for forms
            target_analysis = await scanner.analyze_target(target)
            
            # Test each form for CSRF protection
            for form in target_analysis.get('forms', []):
                await self._test_form_csrf(target, scanner, form)
        
        # Compile results
        results['vulnerabilities'] = self.get_vulnerabilities()
        results['requests_made'] = self.stats['requests_made']
        
        self.logger.info(f"CSRF scan completed. Found {len(results['vulnerabilities'])} vulnerabilities")
        
        return results
    
    async def _test_form_csrf(self, target: Target, scanner: SecurityScanner, form: Dict[str, Any]):
        """Test form for CSRF protection"""
        
        form_action = form.get('action', '')
        form_method = form.get('method', 'GET').upper()
        
        # Skip GET forms (typically not vulnerable to CSRF)
        if form_method == 'GET':
            return
        
        # Check if form has CSRF token
        has_csrf_token = self._check_csrf_token_in_form(form)
        
        if not has_csrf_token:
            # Test if form accepts requests without CSRF token
            await self._test_form_without_csrf(target, scanner, form)
        else:
            # Test CSRF token validation
            await self._test_csrf_token_validation(target, scanner, form)
    
    def _check_csrf_token_in_form(self, form: Dict[str, Any]) -> bool:
        """Check if form contains CSRF token"""
        
        for input_field in form.get('inputs', []):
            input_name = input_field.get('name', '').lower()
            
            # Check for common CSRF token field names
            csrf_names = [
                'csrf_token', 'csrftoken', '_token', 'authenticity_token',
                'csrfmiddlewaretoken', '__requestverificationtoken'
            ]
            
            if any(csrf_name in input_name for csrf_name in csrf_names):
                return True
        
        return False
    
    async def _test_form_without_csrf(self, target: Target, scanner: SecurityScanner, form: Dict[str, Any]):
        """Test form submission without CSRF token"""
        
        form_action = form.get('action', '')
        form_method = form.get('method', 'POST').upper()
        
        # Build form URL
        if form_action.startswith('http'):
            form_url = form_action
        else:
            form_url = urljoin(target.url, form_action)
        
        # Prepare form data
        form_data = {}
        for input_field in form.get('inputs', []):
            input_name = input_field.get('name')
            input_type = input_field.get('type', 'text')
            input_value = input_field.get('value', '')
            
            if input_name and input_type not in ['submit', 'button', 'reset']:
                # Use existing value or provide test value
                if input_value:
                    form_data[input_name] = input_value
                else:
                    form_data[input_name] = self._get_test_value_for_input(input_type)
        
        # Submit form without CSRF token
        response = await scanner._make_request(
            form_method, form_url, target, data=form_data
        )
        
        self.stats['requests_made'] += 1
        
        if response and response.status_code in [200, 302, 303]:
            # Form accepted without CSRF token
            vulnerability = self.create_vulnerability(
                title="Missing CSRF Protection",
                severity="MEDIUM",
                description=f"Form at {form_url} accepts requests without CSRF token",
                evidence={
                    'form_url': form_url,
                    'form_method': form_method,
                    'form_data': form_data,
                    'response_status': response.status_code,
                    'csrf_token_present': False
                },
                recommendation="Implement CSRF tokens for all state-changing operations",
                cwe_id="CWE-352",
                owasp_category="A01:2021 – Broken Access Control"
            )
            
            self.add_vulnerability(vulnerability)
    
    async def _test_csrf_token_validation(self, target: Target, scanner: SecurityScanner, form: Dict[str, Any]):
        """Test CSRF token validation"""
        
        form_action = form.get('action', '')
        form_method = form.get('method', 'POST').upper()
        
        # Build form URL
        if form_action.startswith('http'):
            form_url = form_action
        else:
            form_url = urljoin(target.url, form_action)
        
        # Get original form with CSRF token
        original_response = await scanner._make_request('GET', form_url, target)
        if not original_response:
            return
        
        # Extract CSRF token from original form
        csrf_token = self._extract_csrf_token(original_response.text)
        if not csrf_token:
            return
        
        # Prepare form data with invalid CSRF token
        form_data = {}
        for input_field in form.get('inputs', []):
            input_name = input_field.get('name')
            input_type = input_field.get('type', 'text')
            input_value = input_field.get('value', '')
            
            if input_name and input_type not in ['submit', 'button', 'reset']:
                if 'csrf' in input_name.lower() or '_token' in input_name.lower():
                    # Use invalid CSRF token
                    form_data[input_name] = 'invalid_csrf_token_12345'
                elif input_value:
                    form_data[input_name] = input_value
                else:
                    form_data[input_name] = self._get_test_value_for_input(input_type)
        
        # Submit form with invalid CSRF token
        response = await scanner._make_request(
            form_method, form_url, target, data=form_data
        )
        
        self.stats['requests_made'] += 1
        
        if response and response.status_code in [200, 302, 303]:
            # Check if request was accepted despite invalid CSRF token
            if not self._check_csrf_error_in_response(response.text):
                vulnerability = self.create_vulnerability(
                    title="Weak CSRF Token Validation",
                    severity="MEDIUM",
                    description=f"Form at {form_url} accepts invalid CSRF tokens",
                    evidence={
                        'form_url': form_url,
                        'form_method': form_method,
                        'original_csrf_token': csrf_token,
                        'invalid_csrf_token': 'invalid_csrf_token_12345',
                        'response_status': response.status_code
                    },
                    recommendation="Implement proper CSRF token validation",
                    cwe_id="CWE-352",
                    owasp_category="A01:2021 – Broken Access Control"
                )
                
                self.add_vulnerability(vulnerability)
    
    def _extract_csrf_token(self, html_content: str) -> str:
        """Extract CSRF token from HTML content"""
        
        for pattern in self.csrf_patterns:
            match = re.search(pattern + r'[^>]*value=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ""
    
    def _check_csrf_error_in_response(self, content: str) -> bool:
        """Check if response contains CSRF error message"""
        
        csrf_error_patterns = [
            r'csrf.*token.*invalid',
            r'csrf.*token.*missing',
            r'csrf.*token.*expired',
            r'invalid.*csrf',
            r'forbidden.*csrf',
            r'403.*csrf'
        ]
        
        content_lower = content.lower()
        
        for pattern in csrf_error_patterns:
            if re.search(pattern, content_lower):
                return True
        
        return False
    
    def _get_test_value_for_input(self, input_type: str) -> str:
        """Get appropriate test value for input type"""
        
        test_values = {
            'email': 'test@example.com',
            'password': 'testpassword123',
            'number': '123',
            'tel': '1234567890',
            'url': 'https://example.com',
            'date': '2023-01-01',
            'time': '12:00',
            'datetime-local': '2023-01-01T12:00'
        }
        
        return test_values.get(input_type, 'testvalue')