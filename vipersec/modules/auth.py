"""
Authentication testing module
"""

import asyncio
from typing import Dict, List, Any, Optional
import base64

from .base import BaseModule
from ..core.config import Target
from ..core.scanner import SecurityScanner


class AuthModule(BaseModule):
    """Authentication vulnerability detection module"""
    
    def __init__(self):
        super().__init__(
            name="auth",
            description="Authentication mechanism testing"
        )
        
        # Common username/password combinations
        self.common_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('administrator', 'administrator'),
            ('root', 'root'),
            ('root', 'toor'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('user', 'user'),
            ('demo', 'demo')
        ]
        
        # Common authentication endpoints
        self.auth_endpoints = [
            '/login',
            '/signin',
            '/auth',
            '/authenticate',
            '/admin/login',
            '/wp-login.php',
            '/api/login',
            '/api/auth'
        ]
    
    async def scan(self, target: Target, scanner: SecurityScanner) -> Dict[str, Any]:
        """Scan for authentication vulnerabilities"""
        
        self.logger.info(f"Starting authentication scan for {target.url}")
        
        results = {
            'module': self.name,
            'vulnerabilities': [],
            'requests_made': 0
        }
        
        async with scanner:
            # Test for authentication bypass
            await self._test_auth_bypass(target, scanner)
            
            # Test for weak credentials
            await self._test_weak_credentials(target, scanner)
            
            # Test for authentication enumeration
            await self._test_user_enumeration(target, scanner)
            
            # Test for session fixation
            await self._test_session_fixation(target, scanner)
        
        # Compile results
        results['vulnerabilities'] = self.get_vulnerabilities()
        results['requests_made'] = self.stats['requests_made']
        
        self.logger.info(f"Authentication scan completed. Found {len(results['vulnerabilities'])} vulnerabilities")
        
        return results
    
    async def _test_auth_bypass(self, target: Target, scanner: SecurityScanner):
        """Test for authentication bypass vulnerabilities"""
        
        # SQL injection in login forms
        sqli_payloads = [
            "admin' --",
            "admin' #",
            "admin'/*",
            "' or 1=1--",
            "' or 'a'='a",
            "') or ('1'='1'--",
            "admin' or '1'='1'/*"
        ]
        
        # Test login forms
        target_analysis = await scanner.analyze_target(target)
        
        for form in target_analysis.get('forms', []):
            if self._is_login_form(form):
                await self._test_login_form_bypass(target, scanner, form, sqli_payloads)
    
    async def _test_login_form_bypass(
        self, 
        target: Target, 
        scanner: SecurityScanner, 
        form: Dict[str, Any],
        payloads: List[str]
    ):
        """Test login form for bypass vulnerabilities"""
        
        username_field = None
        password_field = None
        
        # Identify username and password fields
        for input_field in form.get('inputs', []):
            input_name = input_field.get('name', '').lower()
            input_type = input_field.get('type', '').lower()
            
            if any(keyword in input_name for keyword in ['user', 'login', 'email']):
                username_field = input_field.get('name')
            elif input_type == 'password' or 'pass' in input_name:
                password_field = input_field.get('name')
        
        if not username_field or not password_field:
            return
        
        # Test SQL injection payloads
        for payload in payloads:
            form_data = {
                username_field: payload,
                password_field: 'password'
            }
            
            # Add other form fields
            for input_field in form.get('inputs', []):
                field_name = input_field.get('name')
                field_type = input_field.get('type', 'text')
                
                if field_name and field_name not in form_data and field_type not in ['submit', 'button']:
                    form_data[field_name] = input_field.get('value', '')
            
            response = await scanner._make_request(
                form.get('method', 'POST'), target.url, target, data=form_data
            )
            
            self.stats['requests_made'] += 1
            
            if response and self._check_successful_login(response):
                vulnerability = self.create_vulnerability(
                    title="Authentication Bypass via SQL Injection",
                    severity="CRITICAL",
                    description=f"Authentication bypass detected using payload: {payload}",
                    evidence={
                        'payload': payload,
                        'username_field': username_field,
                        'password_field': password_field,
                        'response_status': response.status_code,
                        'response_length': len(response.text)
                    },
                    recommendation="Use parameterized queries and proper input validation",
                    cwe_id="CWE-89",
                    owasp_category="A03:2021 – Injection"
                )
                
                self.add_vulnerability(vulnerability)
    
    async def _test_weak_credentials(self, target: Target, scanner: SecurityScanner):
        """Test for weak default credentials"""
        
        # Test common authentication endpoints
        for endpoint in self.auth_endpoints:
            auth_url = target.url.rstrip('/') + endpoint
            
            # Test basic authentication
            await self._test_basic_auth(target, scanner, auth_url)
            
            # Test form-based authentication
            await self._test_form_auth(target, scanner, auth_url)
    
    async def _test_basic_auth(self, target: Target, scanner: SecurityScanner, auth_url: str):
        """Test basic authentication with common credentials"""
        
        for username, password in self.common_credentials[:5]:  # Test subset
            # Create basic auth header
            credentials = f"{username}:{password}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            auth_header = f"Basic {encoded_credentials}"
            
            headers = {'Authorization': auth_header}
            
            response = await scanner._make_request('GET', auth_url, target, headers=headers)
            
            self.stats['requests_made'] += 1
            
            if response and response.status_code == 200:
                vulnerability = self.create_vulnerability(
                    title="Weak Default Credentials (Basic Auth)",
                    severity="HIGH",
                    description=f"Default credentials found: {username}:{password}",
                    evidence={
                        'username': username,
                        'password': password,
                        'auth_url': auth_url,
                        'auth_type': 'basic',
                        'response_status': response.status_code
                    },
                    recommendation="Change default credentials and implement strong password policy",
                    cwe_id="CWE-521",
                    owasp_category="A07:2021 – Identification and Authentication Failures"
                )
                
                self.add_vulnerability(vulnerability)
    
    async def _test_form_auth(self, target: Target, scanner: SecurityScanner, auth_url: str):
        """Test form-based authentication with common credentials"""
        
        # Get login form
        response = await scanner._make_request('GET', auth_url, target)
        if not response:
            return
        
        # Parse form
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        
        login_form = None
        for form in soup.find_all('form'):
            if self._is_login_form_html(form):
                login_form = form
                break
        
        if not login_form:
            return
        
        # Extract form fields
        username_field = None
        password_field = None
        
        for input_tag in login_form.find_all(['input', 'textarea']):
            input_name = input_tag.get('name', '').lower()
            input_type = input_tag.get('type', '').lower()
            
            if any(keyword in input_name for keyword in ['user', 'login', 'email']):
                username_field = input_tag.get('name')
            elif input_type == 'password' or 'pass' in input_name:
                password_field = input_tag.get('name')
        
        if not username_field or not password_field:
            return
        
        # Test common credentials
        for username, password in self.common_credentials[:3]:  # Test subset
            form_data = {
                username_field: username,
                password_field: password
            }
            
            # Add other form fields
            for input_tag in login_form.find_all('input'):
                field_name = input_tag.get('name')
                field_type = input_tag.get('type', 'text')
                field_value = input_tag.get('value', '')
                
                if field_name and field_name not in form_data and field_type not in ['submit', 'button']:
                    form_data[field_name] = field_value
            
            response = await scanner._make_request(
                login_form.get('method', 'POST'), auth_url, target, data=form_data
            )
            
            self.stats['requests_made'] += 1
            
            if response and self._check_successful_login(response):
                vulnerability = self.create_vulnerability(
                    title="Weak Default Credentials (Form Auth)",
                    severity="HIGH",
                    description=f"Default credentials found: {username}:{password}",
                    evidence={
                        'username': username,
                        'password': password,
                        'auth_url': auth_url,
                        'auth_type': 'form',
                        'response_status': response.status_code
                    },
                    recommendation="Change default credentials and implement strong password policy",
                    cwe_id="CWE-521",
                    owasp_category="A07:2021 – Identification and Authentication Failures"
                )
                
                self.add_vulnerability(vulnerability)
    
    async def _test_user_enumeration(self, target: Target, scanner: SecurityScanner):
        """Test for username enumeration vulnerabilities"""
        
        test_usernames = ['admin', 'administrator', 'test', 'user', 'guest', 'nonexistentuser123']
        
        # Test login endpoints
        for endpoint in self.auth_endpoints[:3]:  # Test subset
            auth_url = target.url.rstrip('/') + endpoint
            
            response_times = []
            response_lengths = []
            status_codes = []
            
            for username in test_usernames:
                form_data = {
                    'username': username,
                    'password': 'wrongpassword123'
                }
                
                response = await scanner._make_request('POST', auth_url, target, data=form_data)
                
                self.stats['requests_made'] += 1
                
                if response:
                    response_times.append(response.elapsed.total_seconds())
                    response_lengths.append(len(response.text))
                    status_codes.append(response.status_code)
            
            # Analyze responses for enumeration indicators
            if self._analyze_enumeration_responses(response_times, response_lengths, status_codes):
                vulnerability = self.create_vulnerability(
                    title="Username Enumeration",
                    severity="LOW",
                    description=f"Username enumeration possible at {auth_url}",
                    evidence={
                        'auth_url': auth_url,
                        'test_usernames': test_usernames,
                        'response_times': response_times,
                        'response_lengths': response_lengths,
                        'status_codes': status_codes
                    },
                    recommendation="Implement consistent error messages and response times",
                    cwe_id="CWE-204",
                    owasp_category="A07:2021 – Identification and Authentication Failures"
                )
                
                self.add_vulnerability(vulnerability)
    
    async def _test_session_fixation(self, target: Target, scanner: SecurityScanner):
        """Test for session fixation vulnerabilities"""
        
        # Get initial session
        initial_response = await scanner._make_request('GET', target.url, target)
        if not initial_response:
            return
        
        initial_session = self._extract_session_id(initial_response)
        if not initial_session:
            return
        
        # Attempt login with fixed session
        login_data = {
            'username': 'testuser',
            'password': 'testpass'
        }
        
        # Use the same session ID
        cookies = {initial_session['name']: initial_session['value']}
        
        login_response = await scanner._make_request(
            'POST', target.url, target, data=login_data, cookies=cookies
        )
        
        self.stats['requests_made'] += 2
        
        if login_response:
            post_login_session = self._extract_session_id(login_response)
            
            # Check if session ID remained the same after login
            if (post_login_session and 
                post_login_session['value'] == initial_session['value']):
                
                vulnerability = self.create_vulnerability(
                    title="Session Fixation",
                    severity="MEDIUM",
                    description="Session ID not regenerated after authentication",
                    evidence={
                        'initial_session_id': initial_session['value'],
                        'post_login_session_id': post_login_session['value'],
                        'session_cookie_name': initial_session['name']
                    },
                    recommendation="Regenerate session ID after successful authentication",
                    cwe_id="CWE-384",
                    owasp_category="A07:2021 – Identification and Authentication Failures"
                )
                
                self.add_vulnerability(vulnerability)
    
    def _is_login_form(self, form: Dict[str, Any]) -> bool:
        """Check if form is a login form"""
        
        has_password = False
        has_username = False
        
        for input_field in form.get('inputs', []):
            input_name = input_field.get('name', '').lower()
            input_type = input_field.get('type', '').lower()
            
            if input_type == 'password':
                has_password = True
            elif any(keyword in input_name for keyword in ['user', 'login', 'email']):
                has_username = True
        
        return has_password and has_username
    
    def _is_login_form_html(self, form) -> bool:
        """Check if HTML form is a login form"""
        
        has_password = False
        has_username = False
        
        for input_tag in form.find_all('input'):
            input_name = input_tag.get('name', '').lower()
            input_type = input_tag.get('type', '').lower()
            
            if input_type == 'password':
                has_password = True
            elif any(keyword in input_name for keyword in ['user', 'login', 'email']):
                has_username = True
        
        return has_password and has_username
    
    def _check_successful_login(self, response) -> bool:
        """Check if login was successful"""
        
        # Check for redirect (common after successful login)
        if response.status_code in [302, 303, 307, 308]:
            return True
        
        # Check for success indicators in content
        content_lower = response.text.lower()
        success_indicators = [
            'welcome', 'dashboard', 'logout', 'profile',
            'success', 'authenticated', 'logged in'
        ]
        
        for indicator in success_indicators:
            if indicator in content_lower:
                return True
        
        # Check for absence of error messages
        error_indicators = [
            'invalid', 'incorrect', 'wrong', 'failed',
            'error', 'denied', 'unauthorized'
        ]
        
        has_error = any(error in content_lower for error in error_indicators)
        
        return not has_error and response.status_code == 200
    
    def _extract_session_id(self, response) -> Optional[Dict[str, str]]:
        """Extract session ID from response"""
        
        session_cookie_names = [
            'JSESSIONID', 'PHPSESSID', 'ASPSESSIONID',
            'sessionid', 'session', 'sid'
        ]
        
        for cookie in response.cookies:
            if any(name.lower() in cookie.name.lower() for name in session_cookie_names):
                return {
                    'name': cookie.name,
                    'value': cookie.value
                }
        
        return None
    
    def _analyze_enumeration_responses(
        self, 
        response_times: List[float], 
        response_lengths: List[int], 
        status_codes: List[int]
    ) -> bool:
        """Analyze responses for enumeration indicators"""
        
        if len(response_times) < 2:
            return False
        
        # Check for significant differences in response times
        time_variance = max(response_times) - min(response_times)
        if time_variance > 1.0:  # More than 1 second difference
            return True
        
        # Check for different response lengths
        length_variance = max(response_lengths) - min(response_lengths)
        if length_variance > 100:  # More than 100 characters difference
            return True
        
        # Check for different status codes
        unique_status_codes = set(status_codes)
        if len(unique_status_codes) > 1:
            return True
        
        return False